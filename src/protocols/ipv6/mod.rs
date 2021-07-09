use anyhow::{anyhow, bail, Result as AHResult};
use crossbeam::channel;
use nom::{
    bits, bytes,
    combinator::{eof, map_res, opt},
    multi::{many_m_n, separated_list1},
    number::complete::{be_u16, be_u8},
    sequence::{terminated, tuple},
};
use std::convert::{TryFrom, TryInto};
use std::str::FromStr;
use std::sync::Arc;
use std::thread;

mod icmpv6;

use super::ether;
use super::ipv4;
use super::utils::{BIResult, DispatchKeyed, KeyedDispatcher, RecvSenderMap, SIResult};
use crate::try_parse;

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub enum Ipv6NextHeader {
    Protocol(ipv4::IpProtocolNumber),
    HopByHop,
}

impl std::convert::TryFrom<u8> for Ipv6NextHeader {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Ipv6NextHeader::HopByHop),
            _ => ipv4::IpProtocolNumber::try_from(value).map(|p| Ipv6NextHeader::Protocol(p)),
        }
    }
}

impl std::fmt::Display for Ipv6NextHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            Ipv6NextHeader::HopByHop => write!(f, "HopByHop"),
            Ipv6NextHeader::Protocol(proto) => proto.fmt(f),
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct Ipv6Address(pub [u16; 8]);

fn is_hex_digit(c: char) -> bool {
    c.is_digit(16)
}

fn ipv6_address_part<'a>(input: &'a str) -> SIResult<'a, u16> {
    map_res(bytes::complete::take_while_m_n(1, 4, is_hex_digit), |s| {
        u16::from_str_radix(s, 16)
    })(input)
}

// Ref: RFC 2373
impl FromStr for Ipv6Address {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (maybe_head, placeholder, maybe_tail) = try_parse!(
            {
                terminated(
                    tuple((
                        opt(separated_list1(
                            bytes::complete::tag(":"),
                            ipv6_address_part,
                        )),
                        opt(bytes::complete::tag("::")),
                        opt(separated_list1(
                            bytes::complete::tag(":"),
                            ipv6_address_part,
                        )),
                    )),
                    eof,
                )(&s)
            },
            "parsing ipv6 address failed: {}"
        )?;

        let head = maybe_head.unwrap_or(vec![]);
        let tail = maybe_tail.unwrap_or(vec![]);

        if head.len() + tail.len() > 8 {
            bail!("ipv6 address cannot have more than 8 parts");
        }

        let mut result = Vec::new();
        result.extend(&head);
        if placeholder.is_some() {
            // e.g., ff4d:02::1: 8 - 1 = 7.
            result.resize(8 - tail.len(), 0u16);
        } else if head.len() + tail.len() < 8 {
            bail!("ipv6 address must have 8 parts or a double colon");
        }
        result.extend(tail);

        Ok(Self(result.try_into().unwrap()))
    }
}

pub fn ipv6_address<'a>(input: &'a [u8]) -> BIResult<'a, Ipv6Address> {
    many_m_n(8, 8, be_u16)(input).map(|(i, x)| (i, Ipv6Address(x.try_into().unwrap())))
}

#[derive(Debug, PartialEq)]
pub enum Ipv6ExtensionHeader {
    HopByHop,
}

fn ipv6_extension_header<'a>(
    input: &'a [u8],
    _extension_header: Ipv6NextHeader,
) -> nom::IResult<&'a [u8], (Ipv6NextHeader, u16, Ipv6ExtensionHeader)> {
    let (input, next_header) = map_res(be_u8, Ipv6NextHeader::try_from)(input)?;
    let (input, header_len) = be_u8(input)?;
    let input = &input[header_len as usize + 6..];

    Ok((
        input,
        (
            next_header,
            (header_len + 8) as u16,
            Ipv6ExtensionHeader::HopByHop,
        ),
    ))
}

#[derive(Debug, PartialEq)]
pub struct Ipv6Packet {
    traffic_class: u8,
    flow_label: u32,
    next_header: Ipv6NextHeader,
    hop_limit: u8,
    src: Ipv6Address,
    dest: Ipv6Address,
    extension_headers: Vec<Ipv6ExtensionHeader>,
    payload: Vec<u8>,
}

pub fn ipv6_packet(input: &[u8]) -> AHResult<Ipv6Packet> {
    try_parse!(
        {
            let (input, (_, traffic_class, flow_label)) =
                bits::bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(tuple((
                    bits::complete::tag(0x6, 4usize),
                    bits::complete::take(8usize),
                    bits::complete::take(20usize),
                )))(input)?;
            let (input, mut payload_length) = be_u16(input)?;
            let (input, mut next_header) = map_res(be_u8, Ipv6NextHeader::try_from)(input)?;
            let (input, hop_limit) = be_u8(input)?;
            let (input, src) = ipv6_address(input)?;
            let (mut input, dest) = ipv6_address(input)?;

            let mut extension_headers = Vec::new();

            if next_header == Ipv6NextHeader::HopByHop {
                let (new_input, (new_next_header, num_header_bytes, header)) =
                    ipv6_extension_header(input, next_header)?;
                payload_length -= num_header_bytes as u16;
                extension_headers.push(header);
                input = new_input;
                next_header = new_next_header;
            }

            let (input, payload) = bytes::complete::take(payload_length)(input)?;

            Ok((
                input,
                Ipv6Packet {
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

impl DispatchKeyed for Ipv6Packet {
    type Key = Ipv6NextHeader;

    fn dispatch_key(&self) -> Self::Key {
        self.next_header
    }
}

pub struct Ipv6Server {
    frame_receiver: channel::Receiver<ether::EtherFrame>,
    icmpv6_receiver: channel::Receiver<Ipv6Packet>,
    recv_map: Arc<RecvSenderMap<Ipv6Packet>>,
}

impl Ipv6Server {
    pub fn new(ether_server: &mut impl ether::EthernetServer) -> AHResult<Self> {
        let (frame_sender, frame_receiver) = channel::bounded(1024);
        ether_server.register(ether::EtherType::Ipv6, frame_sender);

        let (icmpv6_sender, icmpv6_receiver) = channel::bounded(1024);

        let mut ipv6_server = Self {
            frame_receiver,
            icmpv6_receiver,
            recv_map: Arc::new(RecvSenderMap::new()),
        };

        ipv6_server.register(
            Ipv6NextHeader::Protocol(ipv4::IpProtocolNumber::Ipv6Icmp),
            icmpv6_sender,
        );

        Ok(ipv6_server)
    }

    pub fn start(&self) {
        self.start_ipv6();
        self.start_icmpv6();
    }

    pub fn start_ipv6(&self) {
        let frame_receiver = self.frame_receiver.clone();
        let recv_map = self.recv_map.clone();

        thread::spawn(move || loop {
            let frame = frame_receiver.recv().unwrap();

            let packet = ipv6_packet(&frame.payload).unwrap();

            recv_map.dispatch(packet).unwrap();
        });
    }

    pub fn start_icmpv6(&self) {
        let icmpv6_receiver = self.icmpv6_receiver.clone();

        thread::spawn(move || loop {
            let ip_packet = icmpv6_receiver.recv().unwrap();

            let packet = icmpv6::icmpv6_packet(&ip_packet.payload).unwrap();
        });
    }
}

impl KeyedDispatcher for Ipv6Server {
    type Item = Ipv6Packet;

    fn recv_map(&self) -> &RecvSenderMap<Ipv6Packet> {
        &self.recv_map
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hexstring(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    #[test]
    fn full_ipv6_address_parses() {
        assert_eq!(
            "FEDC:BA98:7654:3210:FEDC:BA98:7654:3210"
                .parse::<Ipv6Address>()
                .unwrap(),
            Ipv6Address([0xFEDC, 0xBA98, 0x7654, 0x3210, 0xFEDC, 0xBA98, 0x7654, 0x3210])
        );
        assert_eq!(
            "1080:0:0:0:8:800:200C:417A".parse::<Ipv6Address>().unwrap(),
            Ipv6Address([0x1080, 0, 0, 0, 0x8, 0x800, 0x200C, 0x417A])
        );
    }

    #[test]
    fn partial_ipv6_address_parses() {
        assert_eq!(
            "1080::8:800:200C:417A".parse::<Ipv6Address>().unwrap(),
            Ipv6Address([0x1080, 0, 0, 0, 0x8, 0x800, 0x200C, 0x417A])
        );
        assert_eq!(
            "FF01::101".parse::<Ipv6Address>().unwrap(),
            Ipv6Address([0xFF01, 0, 0, 0, 0, 0, 0, 0x101])
        );
        assert_eq!(
            "::1".parse::<Ipv6Address>().unwrap(),
            Ipv6Address([0, 0, 0, 0, 0, 0, 0, 1])
        );
        assert_eq!(
            "::".parse::<Ipv6Address>().unwrap(),
            Ipv6Address([0, 0, 0, 0, 0, 0, 0, 0])
        );
    }

    #[test]
    #[should_panic]
    fn double_placeholder_ipv6_address_does_not_parse() {
        "1080::8::417A".parse::<Ipv6Address>().unwrap();
    }

    #[test]
    #[should_panic(expected = "8 parts")]
    fn too_short_ipv6_address_does_not_parse() {
        "1080:8:417A".parse::<Ipv6Address>().unwrap();
    }

    #[test]
    fn reply_packet_decodes() {
        assert_eq!(
            ipv6_packet(&hexstring(
                "6001d4b900203afffe80000000000000209efefffe5711e5ff0200000000000000000001ff00001287003fc50000000000f400440000000000000000000000120101560d4f2164f3"
            ))
            .unwrap(),
            Ipv6Packet {
                traffic_class: 0,
                flow_label: 0x1d4b9,
                next_header: Ipv6NextHeader::Protocol(ipv4::IpProtocolNumber::Ipv6Icmp),
                hop_limit: 0xff,
                src: "fe80::209e:feff:fe57:11e5".parse().unwrap(),
                dest: "ff02::1:ff00:12".parse().unwrap(),
                extension_headers: vec![],
                payload: hexstring("87003fc50000000000f400440000000000000000000000120101560d4f2164f3").to_vec(),
            }
        );
    }

    #[test]
    fn request_packet_decodes() {
        assert_eq!(
            ipv6_packet(&hexstring(
                "6000000000203afffd00736f746f686e0000000000000001fe80000000000000264163edd76d0807880079e9e0000000fd00736f746f686e000000000000000102011691822a803b"
            ))
            .unwrap(),
            Ipv6Packet {
                traffic_class: 0,
                flow_label: 0,
                next_header: Ipv6NextHeader::Protocol(ipv4::IpProtocolNumber::Ipv6Icmp),
                hop_limit: 0xff,
                src: "fd00:736f:746f:686e::1".parse().unwrap(),
                dest: "fe80::2641:63ed:d76d:807".parse().unwrap(),
                extension_headers: vec![],
                payload: hexstring("880079e9e0000000fd00736f746f686e000000000000000102011691822a803b").to_vec(),
            }
        );
    }

    #[test]
    fn packet_with_unknown_next_header_decodes() {
        assert_eq!(
            ipv6_packet(&hexstring(
                "6008991a003bff4033ab6549000000004cccc624610ea3eb20014860486000000000000000008888c4020035003be7b562ba0120000100000000000106676f6f676c6503636f6d0000010001000029100000000000000c000a0008eb1aa1842012578a"
            ))
            .unwrap(),
            Ipv6Packet {
                traffic_class: 0,
                flow_label: 0x8991a,
                next_header: Ipv6NextHeader::Protocol(ipv4::IpProtocolNumber::Unknown(0xff)),
                hop_limit: 0x40,
                src: "33ab:6549::4ccc:c624:610e:a3eb".parse().unwrap(),
                dest: "2001:4860:4860::8888".parse().unwrap(),
                extension_headers: vec![],
                payload: hexstring("c4020035003be7b562ba0120000100000000000106676f6f676c6503636f6d0000010001000029100000000000000c000a0008eb1aa1842012578a").to_vec(),
            }
        );
    }

    #[test]
    fn packet_with_hop_by_hop_options_decodes() {
        assert_eq!(
            ipv6_packet(&hexstring(
                "600000000024000100000000000000000000000000000000ff0200000000000000000000000000163a000502000001008f008dca0000000104000000ff0200000000000000000001fff9e0c6"
            ))
            .unwrap(),
            Ipv6Packet {
                traffic_class: 0,
                flow_label: 0,
                next_header: Ipv6NextHeader::Protocol(ipv4::IpProtocolNumber::Ipv6Icmp),
                hop_limit: 0x01,
                src: "::".parse().unwrap(),
                dest: "ff02::16".parse().unwrap(),
                extension_headers: vec![
                   Ipv6ExtensionHeader::HopByHop,
                ],
                payload: hexstring("8f008dca0000000104000000ff0200000000000000000001fff9e0c6").to_vec(),
            }
        );
    }
}
