use anyhow::{anyhow, bail, Result as AHResult};
use nom::{
    combinator::{consumed, eof, map_res},
    multi::many0,
    number::complete::be_u8,
    sequence::terminated,
};
use std::convert::TryFrom;

use crate::protocols::ether;
use crate::protocols::ipv4;
use crate::protocols::ipv6;
use crate::protocols::utils::{BIResult, EncodeTo};
use crate::{encode, proto_enum_with_unknown, try_parse};

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
    V2MulticastListenerReport = 143,
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
    Nonce,
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
    V2MulticastListenerReport,
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
                let input = &input[(length as usize * 8) - 2..];

                Ok((input, NeighborSolicitationOption::Nonce))
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

pub struct PseudoHeader {
    pub src: ipv6::Address,
    pub dest: ipv6::Address,
    pub length: u32,
}

fn packet_checksum(input: &[u8], pseudo_header: PseudoHeader) -> u16 {
    let checksummed_buffer = encode!(
        pseudo_header.src,
        pseudo_header.dest,
        pseudo_header.length,
        0u16,
        0u8,
        ipv4::ProtocolNumber::Ipv6Icmp,
        input,
    );

    let mut checksum = 0u16;

    for i in (0..checksummed_buffer.len()).step_by(2) {
        let word = (checksummed_buffer[i] as u16) << 8 | (checksummed_buffer[i + 1] as u16);

        let (new_checksum, overflowed) = checksum.overflowing_add(word);

        checksum = new_checksum + if overflowed { 1 } else { 0 };
    }

    checksum
}

pub fn packet(input: &[u8], pseudo_header: PseudoHeader) -> AHResult<Packet> {
    let checksum = packet_checksum(input, pseudo_header);

    if checksum != 0xffff {
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
                V2MulticastListenerReport => (input, Packet::V2MulticastListenerReport),
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
                &hexstring("870003aa00000000fe80000000000000396df66497e164f30e01d8d14717f0a0"),
                PseudoHeader {
                    dest: "fe80::396d:f664:97e1:64f3".parse().unwrap(),
                    src: "::".parse().unwrap(),
                    length: 64
                }
            )
            .unwrap(),
            Packet::NeighborSolicitation {
                dest: "fe80::396d:f664:97e1:64f3".parse().unwrap(),
                options: vec![NeighborSolicitationOption::Nonce,],
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
                &hexstring("8f008dae0000000104000000ff0200000000000000000001fff9e0c6"),
                PseudoHeader {
                    dest: "ff02::16".parse().unwrap(),
                    src: "::".parse().unwrap(),
                    length: 56
                }
            )
            .unwrap(),
            Packet::V2MulticastListenerReport
        );
    }

    #[test]
    #[should_panic(expected = "checksum")]
    fn multicast_listener_packet_with_invalid_checksum_fails_do_decode() {
        assert_eq!(
            packet(
                &hexstring("8f0011110000000104000000ff0200000000000000000001fff9e0c6"),
                PseudoHeader {
                    dest: "::".parse().unwrap(),
                    src: "::".parse().unwrap(),
                    length: 0
                }
            )
            .unwrap(),
            Packet::V2MulticastListenerReport
        );
    }
}
