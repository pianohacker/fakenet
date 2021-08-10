use anyhow::{anyhow, bail, Result as AHResult};
use byteorder::ByteOrder;
use nom::{
    bytes::complete::take,
    combinator::{consumed, eof, map_res},
    multi::many0,
    number::complete::be_u8,
    sequence::terminated,
};
use std::convert::TryFrom;

use crate::protocols::encdec::{BIResult, EncodeTo};
use crate::protocols::ether;
use crate::protocols::ipv4;
use crate::protocols::ipv6;
use crate::{encode, encode_to, proto_enum, proto_enum_with_unknown, try_parse};

// Ref: https://datatracker.ietf.org/doc/html/rfc4443

proto_enum_with_unknown!(Type, u8, {
    DestinationUnreachable = 1,
    TooBig = 2,
    Exceeded = 3,
    Problem = 4,
    EchoRequest = 128,
    EchoReply = 129,
    RouterSolicitation = 133,
    NeighborSolicitation = 135,
    NeighborAdvertisement = 136,
    MldV2Report = 143,
});

// Ref: https://datatracker.ietf.org/doc/html/rfc4861
proto_enum_with_unknown!(NeighborSolicitationOptionType, u8, {
    SourceLinkLayerAddress = 1,
    TargetLinkLayerAddress = 2,
    Nonce = 14,
});

#[derive(Debug, PartialEq)]
pub enum NeighborSolicitationOption {
    SourceLinkLayerAddress(ether::Address),
    TargetLinkLayerAddress(ether::Address),
    Nonce(Vec<u8>),
}

impl EncodeTo for NeighborSolicitationOption {
    fn encoded_len(&self) -> usize {
        match self {
            NeighborSolicitationOption::Nonce(nonce) => 2 + nonce.len(),
            _ => {
                todo!("unsupported option: {:?}", self)
            }
        }
    }
    fn encode_to(&self, buf: &mut [u8]) {
        match self {
            NeighborSolicitationOption::Nonce(nonce) => {
                encode_to!(
                    buf,
                    NeighborSolicitationOptionType::Nonce,
                    ((nonce.len() + 2) as f64 / 8f64).ceil() as u8,
                    nonce
                );
            }
            _ => {
                todo!("unsupported option: {:?}", self)
            }
        }
    }
}

proto_enum!(Mldv2AddressRecordType, u8, {
    CodeIsInclude = 1,
    CodeIsExclude = 2,
    ChangeToIncludeMode = 3,
    ChangeToExcludeMode = 4,
    CllowNewSources = 5,
    ClockOldSources = 6,
});

#[derive(Debug, PartialEq)]
pub struct MldV2AddressRecord {
    pub record_type: Mldv2AddressRecordType,
    pub address: ipv6::Address,
}

impl EncodeTo for MldV2AddressRecord {
    fn encoded_len(&self) -> usize {
        1 + 1 + 2 + 16
    }
    fn encode_to(&self, buf: &mut [u8]) {
        encode_to!(
            buf,
            self.record_type,
            0u8,
            0u16, // Number of Sources
            self.address
        );
    }
}

#[derive(Debug, PartialEq)]
pub enum Packet {
    RouterSolicitation,
    NeighborSolicitation {
        dest: ipv6::Address,
        options: Vec<NeighborSolicitationOption>,
    },
    NeighborAdvertisement {
        src: ipv6::Address,
        options: Vec<NeighborSolicitationOption>,
    },
    MldV2Report(Vec<MldV2AddressRecord>),
}

impl Packet {
    /// Encode this packet.
    ///
    /// The length field in pseudo_header is ignored, and should be set to 0.
    pub fn encode(&self, pseudo_header: PseudoHeader) -> Vec<u8> {
        let mut buffer: Vec<u8> = match self {
            Packet::NeighborSolicitation { dest, options } => encode!(
                Type::NeighborSolicitation,
                0u8,  // Code
                0u16, // Checksum
                0u32, // Reserved
                dest,
                options,
            ),
            Packet::MldV2Report(records) => encode!(
                Type::MldV2Report,
                0u8,  // Reserved
                0u16, // Checksum
                0u16, // Reserved
                records.len() as u16,
                records,
            ),
            _ => {
                todo!("unimplemented icmpv6 option type: {:?}", self)
            }
        };

        let updated_pseudo_header = PseudoHeader {
            length: buffer.len() as u32,
            ..pseudo_header
        };
        let checksum = packet_checksum(&buffer, &updated_pseudo_header);
        byteorder::NetworkEndian::write_u16(&mut buffer[2..4], checksum);
        assert!(packet_checksum(&buffer, &updated_pseudo_header) == 0x0000);

        buffer
    }
}

fn neighbor_solicitation_option<'a>(input: &'a [u8]) -> BIResult<'a, NeighborSolicitationOption> {
    fn inner<'a>(input: &'a [u8]) -> BIResult<'a, NeighborSolicitationOption> {
        let (input, option_type) = map_res(be_u8, NeighborSolicitationOptionType::try_from)(input)?;
        let (input, length) = be_u8(input)?;

        match option_type {
            NeighborSolicitationOptionType::SourceLinkLayerAddress => {
                let (input, address) = ether::address(input)?;

                Ok((
                    input,
                    NeighborSolicitationOption::SourceLinkLayerAddress(address),
                ))
            }
            NeighborSolicitationOptionType::TargetLinkLayerAddress => {
                let (input, address) = ether::address(input)?;

                Ok((
                    input,
                    NeighborSolicitationOption::TargetLinkLayerAddress(address),
                ))
            }
            NeighborSolicitationOptionType::Nonce => {
                let (input, nonce) = take((length as usize * 8) - 2)(input)?;

                Ok((input, NeighborSolicitationOption::Nonce(nonce.to_vec())))
            }
            NeighborSolicitationOptionType::Unknown(t) => {
                todo!("not yet implemented: {}", t)
            }
        }
    }

    let (input, (option_bytes, option)) = consumed(inner)(input)?;

    let input = if option_bytes.len() % 8 == 0 {
        input
    } else {
        let needed_padding = 8 - option_bytes.len() % 8;
        &input[needed_padding..]
    };

    Ok((input, option))
}

fn neighbor_solicitation_packet<'a>(input: &'a [u8]) -> BIResult<'a, Packet> {
    // ignore code, checksum, and reserved
    let input = &input[7..];
    let (input, dest) = ipv6::address(input)?;

    let (input, options) = terminated(many0(neighbor_solicitation_option), eof)(input)?;

    let (input, _) = eof(input)?;

    Ok((input, Packet::NeighborSolicitation { dest, options }))
}

fn neighbor_advertisement_packet<'a>(input: &'a [u8]) -> BIResult<'a, Packet> {
    // ignore code, checksum, and reserved
    let input = &input[7..];

    let (input, src) = ipv6::address(input)?;

    let (input, options) = terminated(many0(neighbor_solicitation_option), eof)(input)?;

    let (input, _) = eof(input)?;

    Ok((input, Packet::NeighborAdvertisement { src, options }))
}

fn mld_v2_address_record<'a>(input: &'a [u8]) -> BIResult<'a, MldV2AddressRecord> {
    let (input, record_type) = map_res(be_u8, Mldv2AddressRecordType::try_from)(input)?;

    // TODO: Aux Data Len, Number of Sources
    let input = &input[3..];

    let (input, address) = ipv6::address(input)?;

    Ok((
        input,
        MldV2AddressRecord {
            record_type,
            address,
        },
    ))
}

fn mld_v2_report_packet<'a>(input: &'a [u8]) -> BIResult<'a, Packet> {
    // ignore code, checksum, and number of records
    let input = &input[7..];

    let (input, records) = terminated(many0(mld_v2_address_record), eof)(input)?;

    let (input, _) = eof(input)?;

    Ok((input, Packet::MldV2Report(records)))
}

pub struct PseudoHeader {
    pub src: ipv6::Address,
    pub dest: ipv6::Address,
    pub length: u32,
}

fn packet_checksum(input: &[u8], pseudo_header: &PseudoHeader) -> u16 {
    // RFC 8200 § 8.1
    let checksummed_buffer = encode!(
        pseudo_header.src,
        pseudo_header.dest,
        pseudo_header.length,
        0u16,
        0u8,
        ipv4::ProtocolNumber::Ipv6Icmp,
        input,
    );

    // RFC 4333 § 2.3
    let mut checksum = 0u32;

    for i in (0..checksummed_buffer.len()).step_by(2) {
        checksum += (checksummed_buffer[i] as u32) << 8 | (checksummed_buffer[i + 1] as u32);
    }

    // Fold in carry repeatedly until nothing is left
    while checksum > 0xffff {
        checksum = (checksum & 0xffff) + (checksum >> 16);
    }

    !(checksum as u16)
}

pub fn packet(input: &[u8], pseudo_header: PseudoHeader) -> AHResult<Packet> {
    let checksum = packet_checksum(input, &pseudo_header);

    if checksum != 0x0000 {
        bail!("icmpv6 checksum invalid: {:x}", checksum);
    }

    try_parse!(
        {
            let (input, packet_type) = map_res(be_u8, Type::try_from)(input)?;

            use Type::*;
            let (input, packet) = match packet_type {
                RouterSolicitation => (input, Packet::RouterSolicitation),
                NeighborSolicitation => neighbor_solicitation_packet(input)?,
                NeighborAdvertisement => neighbor_advertisement_packet(input)?,
                MldV2Report => mld_v2_report_packet(input)?,
                _ => {
                    todo!("not yet implemented: {:?}", packet_type)
                }
            };

            Ok((input, packet))
        },
        "parsing icmpv6 packet failed: {}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hexstring(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    #[test]
    fn router_solicitation_packet_decodes() {
        assert_eq!(
            packet(
                &hexstring("8500707e000000000101560d4f2164f3"),
                PseudoHeader {
                    dest: "ff01::2".parse().unwrap(),
                    src: "::".parse().unwrap(),
                    length: 32
                }
            )
            .unwrap(),
            Packet::RouterSolicitation
        );
    }

    #[test]
    fn neighbor_solicitation_packet_decodes() {
        assert_eq!(
            packet(
                &hexstring("870022160000000000f400440000000000000000000000120101560d4f2164f3"),
                PseudoHeader {
                    dest: "f400:4400::1201".parse().unwrap(),
                    src: "::".parse().unwrap(),
                    length: 64
                }
            )
            .unwrap(),
            Packet::NeighborSolicitation {
                dest: "f4:44::12".parse().unwrap(),
                options: vec![NeighborSolicitationOption::SourceLinkLayerAddress(
                    ether::Address([0x56, 0x0d, 0x4f, 0x21, 0x64, 0xf3]),
                ),],
            },
        );
    }

    #[test]
    fn neighbor_solicitation_packet_with_nonce_decodes() {
        assert_eq!(
            packet(
                &hexstring("870003ca00000000fe80000000000000396df66497e164f30e01d8d14717f0a0"),
                PseudoHeader {
                    dest: "fe80::396d:f664:97e1:64f3".parse().unwrap(),
                    src: "::".parse().unwrap(),
                    length: 32
                }
            )
            .unwrap(),
            Packet::NeighborSolicitation {
                dest: "fe80::396d:f664:97e1:64f3".parse().unwrap(),
                options: vec![NeighborSolicitationOption::Nonce(hexstring("d8d14717f0a0"))],
            },
        );
    }

    #[test]
    fn neighbor_advertisement_packet_decodes() {
        assert_eq!(
            packet(
                &hexstring("8800e1ede0000000fd00736f746f686e000000000000000102011691822a803b"),
                PseudoHeader {
                    dest: "::".parse().unwrap(),
                    src: "fd00:736f:746f:686e::1".parse().unwrap(),
                    length: 64
                }
            )
            .unwrap(),
            Packet::NeighborAdvertisement {
                src: "fd00:736f:746f:686e::1".parse().unwrap(),
                options: vec![NeighborSolicitationOption::TargetLinkLayerAddress(
                    ether::Address([0x16, 0x91, 0x82, 0x2a, 0x80, 0x3b]),
                ),],
            }
        );
    }

    #[test]
    fn multicast_listener_packet_decodes() {
        assert_eq!(
            packet(
                &hexstring("8f002b5a0000000204000000ff05000000000000000000000001000304000000ff020000000000000000000000010002"),
                PseudoHeader {
                    dest: "ff02::16".parse().unwrap(),
                    src: "fe80::a00:27ff:fed4:10bb".parse().unwrap(),
                    length: 48
                }
            )
            .unwrap(),
            Packet::MldV2Report(
                vec![
                    MldV2AddressRecord {
                        record_type: Mldv2AddressRecordType::ChangeToExcludeMode,
                        address: "ff05::1:3".parse().unwrap(),
                    },
                    MldV2AddressRecord {
                        record_type: Mldv2AddressRecordType::ChangeToExcludeMode,
                        address: "ff02::1:2".parse().unwrap(),
                    },
                ],
            ),
        );
    }

    #[test]
    #[should_panic(expected = "checksum")]
    fn multicast_listener_packet_with_invalid_checksum_fails_do_decode() {
        packet(
            &hexstring("8f0011110000000104000000ff0200000000000000000001fff9e0c6"),
            PseudoHeader {
                dest: "::".parse().unwrap(),
                src: "::".parse().unwrap(),
                length: 0,
            },
        )
        .unwrap();
    }

    #[test]
    fn neighbor_solicitation_packet_with_nonce_encodes() {
        assert_eq!(
            Packet::NeighborSolicitation {
                dest: "fe80::396d:f664:97e1:64f3".parse().unwrap(),
                options: vec![NeighborSolicitationOption::Nonce(hexstring("d8d14717f0a0")),],
            }
            .encode(PseudoHeader {
                dest: "fe80::396d:f664:97e1:64f3".parse().unwrap(),
                src: "::".parse().unwrap(),
                length: 0
            }),
            hexstring("870003ca00000000fe80000000000000396df66497e164f30e01d8d14717f0a0"),
        );
    }

    #[test]
    fn multicast_listener_packet_encodes() {
        assert_eq!(
            Packet::MldV2Report(
                vec![
                    MldV2AddressRecord {
                        record_type: Mldv2AddressRecordType::ChangeToExcludeMode,
                        address: "ff05::1:3".parse().unwrap(),
                    },
                    MldV2AddressRecord {
                        record_type: Mldv2AddressRecordType::ChangeToExcludeMode,
                        address: "ff02::1:2".parse().unwrap(),
                    },
                ],
            ).encode(
                PseudoHeader {
                    dest: "ff02::16".parse().unwrap(),
                    src: "fe80::a00:27ff:fed4:10bb".parse().unwrap(),
                    length: 48
                }
            )
            ,
            hexstring("8f002b5a0000000204000000ff05000000000000000000000001000304000000ff020000000000000000000000010002"),
        );
    }
}
