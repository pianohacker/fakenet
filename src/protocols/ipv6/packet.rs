use anyhow::{anyhow, Result as AHResult};
use nom::{
    bits, bytes,
    combinator::{eof, map_res},
    multi::many0,
    number::complete::{be_u16, be_u8},
    sequence::{terminated, tuple},
};
use std::convert::TryFrom;

use crate::protocols::encdec::{round_up_to_next, EncodeTo};
use crate::protocols::ipv4;
use crate::protocols::utils::DispatchKeyed;
use crate::{encode, encode_to, proto_enum_with_unknown, try_parse};

use super::address::{address, Address};

const _MULTICAST_ALL_NODES: Address = Address([0xff01, 0, 0, 0, 0, 0, 0, 0x1]);

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub enum NextHeader {
    Unset,
    HopByHopOptions,
    Protocol(ipv4::ProtocolNumber),
}

impl std::convert::TryFrom<u8> for NextHeader {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(NextHeader::HopByHopOptions),
            _ => ipv4::ProtocolNumber::try_from(value).map(|p| NextHeader::Protocol(p)),
        }
    }
}

impl std::fmt::Display for NextHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            NextHeader::Unset => write!(f, "Unset"),
            NextHeader::HopByHopOptions => write!(f, "HopByHop"),
            NextHeader::Protocol(proto) => proto.fmt(f),
        }
    }
}

impl EncodeTo for NextHeader {
    fn encoded_len(&self) -> usize {
        1
    }

    fn encode_to(&self, buf: &mut [u8]) {
        match self {
            NextHeader::HopByHopOptions => 0u8.encode_to(buf),
            NextHeader::Unset => panic!("attempt to encode unset next-header"),
            NextHeader::Protocol(proto) => proto.encode_to(buf),
        };
    }
}

impl Default for NextHeader {
    fn default() -> Self {
        NextHeader::Unset
    }
}

proto_enum_with_unknown!(HopByHopOptionType, u8, {
    Pad1 = 0,
    PadN = 1,
    RouterAlert = 5,
});

proto_enum_with_unknown!(RouterAlertType, u16, {
    Mld = 0,
    Rsvp = 1,
    ActiveNetworks = 2,
});

#[derive(Debug, PartialEq)]
pub enum HopByHopOption {
    RouterAlert(RouterAlertType),
}

impl EncodeTo for HopByHopOption {
    fn encoded_len(&self) -> usize {
        1 + 1
            + match self {
                HopByHopOption::RouterAlert(_) => 2,
            }
    }

    fn encode_to(&self, buf: &mut [u8]) {
        match self {
            HopByHopOption::RouterAlert(t) => {
                encode_to!(buf, HopByHopOptionType::RouterAlert, 2u8, t)
            }
        };
    }
}

fn hop_by_hop_option<'a>(input: &'a [u8]) -> nom::IResult<&'a [u8], Option<HopByHopOption>> {
    let (input, option_type) = map_res(be_u8, HopByHopOptionType::try_from)(input)?;

    if option_type == HopByHopOptionType::PadN {
        let (input, pad_len) = be_u8(input)?;
        let input = &input[(pad_len as usize)..];
        return Ok((input, None));
    } else if option_type == HopByHopOptionType::Pad1 {
        return Ok((input, None));
    }

    let (input, option_len) = be_u8(input)?;
    let (input, option_bytes) = bytes::complete::take(option_len)(input)?;

    let option = match option_type {
        HopByHopOptionType::RouterAlert => {
            let (_, router_alert_type) = map_res(be_u16, RouterAlertType::try_from)(option_bytes)?;

            HopByHopOption::RouterAlert(router_alert_type)
        }
        _ => todo!("unhandled option type: {}", option_type),
    };

    Ok((input, Some(option)))
}

#[derive(Debug, PartialEq)]
pub enum ExtensionHeader {
    HopByHopOptions(Vec<HopByHopOption>),
}

impl EncodeTo for ExtensionHeader {
    fn encoded_len(&self) -> usize {
        1 + round_up_to_next(
            match self {
                ExtensionHeader::HopByHopOptions(options) => options.encoded_len(),
            } + 2,
            8,
        ) - 2
    }

    fn encode_to(&self, buf: &mut [u8]) {
        match self {
            ExtensionHeader::HopByHopOptions(options) => {
                let mut encoded_options = encode!(options);
                let start_len = encoded_options.len();
                let target_len = round_up_to_next(start_len + 2, 8) - 2;

                encoded_options.resize(target_len, 0u8);

                if target_len - start_len > 1 {
                    encode_to!(
                        &mut encoded_options[start_len..],
                        HopByHopOptionType::PadN,
                        (target_len - start_len - 2) as u8
                    );
                }

                encode_to!(buf, (target_len - 6) as u8 / 8, encoded_options);
            }
        }
    }
}

impl ExtensionHeader {
    fn next_header(&self) -> NextHeader {
        match self {
            ExtensionHeader::HopByHopOptions(_) => NextHeader::HopByHopOptions,
        }
    }
}

fn extension_header<'a>(
    input: &'a [u8],
    cur_next_header: NextHeader,
) -> nom::IResult<&'a [u8], Option<(NextHeader, u16, ExtensionHeader)>> {
    match cur_next_header {
        NextHeader::HopByHopOptions => {}
        _ => {
            return Ok((input, None));
        }
    };

    let (input, next_header) = map_res(be_u8, NextHeader::try_from)(input)?;
    let (input, header_len_dwords) = be_u8(input)?;
    let header_len = (1 + header_len_dwords as u16) * 8;
    let (input, header_bytes) = bytes::complete::take(header_len - 2)(input)?;

    let header = match cur_next_header {
        NextHeader::HopByHopOptions => {
            let (_, options) = terminated(many0(hop_by_hop_option), eof)(header_bytes)?;
            ExtensionHeader::HopByHopOptions(options.into_iter().filter_map(|o| o).collect())
        }
        _ => unreachable!(),
    };

    Ok((input, Some((next_header, header_len, header))))
}

#[derive(Debug, Default, PartialEq)]
pub struct Packet {
    pub traffic_class: u8,
    pub flow_label: u32,
    pub next_header: NextHeader,
    pub hop_limit: u8,
    pub src: Address,
    pub dest: Address,
    pub extension_headers: Vec<ExtensionHeader>,
    pub payload: Vec<u8>,
}

impl Packet {
    pub fn builder() -> PacketBuilder {
        PacketBuilder(Self::default())
    }

    fn encode_extension_headers(&self, final_next_header: NextHeader) -> Vec<u8> {
        let mut result = Vec::new();
        if self.extension_headers.len() == 0 {
            return result;
        }

        // Add one byte for each extension header's next header byte
        result.resize(
            self.extension_headers.encoded_len() + self.extension_headers.len(),
            0u8,
        );
        let mut output = &mut result[..];

        for (i, extension_header) in self.extension_headers.iter().enumerate() {
            let next_header = if i == self.extension_headers.len() - 1 {
                final_next_header
            } else {
                self.extension_headers[i + 1].next_header()
            };

            encode_to!(output, next_header, extension_header);
            output = &mut output[1 + extension_header.encoded_len()..];
        }

        result
    }

    pub fn encode(&self) -> Vec<u8> {
        let prelude = (6u32 << 28) | ((self.traffic_class as u32) << 20) | self.flow_label;

        let first_next_header = self
            .extension_headers
            .get(0)
            .map_or(self.next_header, |h| h.next_header());

        let encoded_extension_headers = self.encode_extension_headers(self.next_header);

        encode!(
            prelude,
            (encoded_extension_headers.len() + self.payload.len()) as u16,
            first_next_header,
            self.hop_limit,
            self.src,
            self.dest,
            encoded_extension_headers,
            self.payload,
        )
    }
}

pub fn packet(input: &[u8]) -> AHResult<Packet> {
    try_parse!(
        {
            let (input, (_, traffic_class, flow_label)) =
                bits::bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(tuple((
                    bits::complete::tag(0x6, 4usize),
                    bits::complete::take(8usize),
                    bits::complete::take(20usize),
                )))(input)?;
            let (input, mut payload_length) = be_u16(input)?;
            let (input, mut next_header) = map_res(be_u8, NextHeader::try_from)(input)?;
            let (input, hop_limit) = be_u8(input)?;
            let (input, src) = address(input)?;
            let (mut input, dest) = address(input)?;

            let mut extension_headers = Vec::new();

            dbg!(payload_length);
            while let (new_input, Some((new_next_header, num_header_bytes, header))) =
                extension_header(input, next_header)?
            {
                dbg!(&new_next_header, num_header_bytes, &header);
                payload_length -= num_header_bytes as u16;
                extension_headers.push(header);
                input = new_input;
                next_header = new_next_header;
            }

            let (input, payload) = bytes::complete::take(payload_length)(input)?;

            Ok((
                input,
                Packet {
                    traffic_class,
                    flow_label,
                    next_header,
                    hop_limit,
                    src,
                    dest,
                    extension_headers,
                    payload: payload.to_vec(),
                },
            ))
        },
        "parsing ipv6 packet failed: {}"
    )
}

impl DispatchKeyed for Packet {
    type Key = NextHeader;

    fn dispatch_key(&self) -> Self::Key {
        self.next_header
    }
}

pub struct PacketBuilder(Packet);

impl PacketBuilder {
    pub fn traffic_class(self, traffic_class: u8) -> Self {
        Self(Packet {
            traffic_class,
            ..self.0
        })
    }

    pub fn flow_label(self, flow_label: u32) -> Self {
        Self(Packet {
            flow_label,
            ..self.0
        })
    }

    pub fn protocol(self, proto: ipv4::ProtocolNumber) -> Self {
        Self(Packet {
            next_header: NextHeader::Protocol(proto),
            ..self.0
        })
    }

    pub fn hop_limit(self, hop_limit: u8) -> Self {
        Self(Packet {
            hop_limit,
            ..self.0
        })
    }

    pub fn src(self, src: Address) -> Self {
        Self(Packet { src, ..self.0 })
    }

    pub fn dest(self, dest: Address) -> Self {
        Self(Packet { dest, ..self.0 })
    }

    pub fn extension_header(mut self, extension_header: ExtensionHeader) -> Self {
        self.0.extension_headers.push(extension_header);
        self
    }

    pub fn payload(self, payload: Vec<u8>) -> Self {
        Self(Packet { payload, ..self.0 })
    }

    pub fn build(self) -> Packet {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hexstring(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    fn ipv6a(s: &str) -> Address {
        s.parse().unwrap()
    }

    #[test]
    fn packet_with_unknown_next_header_decodes() {
        assert_eq!(
            packet(&hexstring(
                "6008991a003bff4033ab6549000000004cccc624610ea3eb20014860486000000000000000008888c4020035003be7b562ba0120000100000000000106676f6f676c6503636f6d0000010001000029100000000000000c000a0008eb1aa1842012578a"
            ))
            .unwrap(),
            Packet::builder()
                .flow_label(0x8991a)
                .protocol(ipv4::ProtocolNumber::Unknown(0xff))
                .hop_limit(0x40)
                .src(ipv6a("33ab:6549::4ccc:c624:610e:a3eb"))
                .dest(ipv6a("2001:4860:4860::8888"))
                .payload(hexstring("c4020035003be7b562ba0120000100000000000106676f6f676c6503636f6d0000010001000029100000000000000c000a0008eb1aa1842012578a"))
                .build()
        );
    }

    #[test]
    fn packet_with_hop_by_hop_options_decodes() {
        assert_eq!(
            packet(&hexstring(
                "600000000024000100000000000000000000000000000000ff0200000000000000000000000000163a000502000001008f008dca0000000104000000ff0200000000000000000001fff9e0c6"
            ))
            .unwrap(),
            Packet::builder()
                .protocol(ipv4::ProtocolNumber::Ipv6Icmp)
                .hop_limit(0x01)
                .src(ipv6a("::"))
                .dest(ipv6a("ff02::16"))
                .extension_header(ExtensionHeader::HopByHopOptions(vec![HopByHopOption::RouterAlert(RouterAlertType::Mld)]))
                .payload(hexstring("8f008dca0000000104000000ff0200000000000000000001fff9e0c6").to_vec())
                .build()
        );
    }

    #[test]
    fn basic_packet_encodes() {
        assert_eq!(
            Packet::builder()
                .traffic_class(0x54)
                .flow_label(0x1d4b9)
                .protocol(ipv4::ProtocolNumber::Ipv6Icmp)
                .hop_limit(0xff)
                .src(ipv6a("fe80::209e:feff:fe57:11e5"))
                .dest(ipv6a("ff02::1:ff00:12"))
                .payload(hexstring("87003fc50000000000f400440000000000000000000000120101560d4f2164f3").to_vec())
            .build().encode(),
            hexstring(
                "6541d4b900203afffe80000000000000209efefffe5711e5ff0200000000000000000001ff00001287003fc50000000000f400440000000000000000000000120101560d4f2164f3"
            )
        );
    }

    #[test]
    fn packet_with_hop_by_hop_options_encodes() {
        assert_eq!(
            Packet::builder()
                .protocol(ipv4::ProtocolNumber::Ipv6Icmp)
                .hop_limit(0x01)
                .src(ipv6a("::"))
                .dest(ipv6a("ff02::16"))
                .extension_header(ExtensionHeader::HopByHopOptions(vec![HopByHopOption::RouterAlert(RouterAlertType::Mld)]))
                .payload(hexstring("8f008dca0000000104000000ff0200000000000000000001fff9e0c6").to_vec())
                .build().encode(),
            hexstring(
                "600000000024000100000000000000000000000000000000ff0200000000000000000000000000163a000502000001008f008dca0000000104000000ff0200000000000000000001fff9e0c6"
            )
        );
    }
}
