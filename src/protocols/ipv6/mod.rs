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
use super::utils::{BIResult, DispatchKeyed, EncodeTo, KeyedDispatcher, RecvSenderMap, SIResult};
use crate::try_parse;

const MULTICAST_ALL_NODES: Address = Address([0xff01, 0, 0, 0, 0, 0, 0, 0x1]);

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub enum NextHeader {
    Protocol(ipv4::ProtocolNumber),
    HopByHop,
}

impl std::convert::TryFrom<u8> for NextHeader {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(NextHeader::HopByHop),
            _ => ipv4::ProtocolNumber::try_from(value).map(|p| NextHeader::Protocol(p)),
        }
    }
}

impl std::fmt::Display for NextHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            NextHeader::HopByHop => write!(f, "HopByHop"),
            NextHeader::Protocol(proto) => proto.fmt(f),
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct Address(pub [u16; 8]);

fn is_hex_digit(c: char) -> bool {
    c.is_digit(16)
}

fn address_part<'a>(input: &'a str) -> SIResult<'a, u16> {
    map_res(bytes::complete::take_while_m_n(1, 4, is_hex_digit), |s| {
        u16::from_str_radix(s, 16)
    })(input)
}

// Ref: RFC 2373
impl FromStr for Address {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (maybe_head, placeholder, maybe_tail) = try_parse!(
            {
                terminated(
                    tuple((
                        opt(separated_list1(bytes::complete::tag(":"), address_part)),
                        opt(bytes::complete::tag("::")),
                        opt(separated_list1(bytes::complete::tag(":"), address_part)),
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

impl EncodeTo for Address {
    fn encoded_len(&self) -> usize {
        16
    }

    fn encode_to(&self, buf: &mut [u8]) {
        for (i, part) in self.0.iter().enumerate() {
            part.encode_to(&mut buf[i * 2..]);
        }
    }
}

pub fn address<'a>(input: &'a [u8]) -> BIResult<'a, Address> {
    many_m_n(8, 8, be_u16)(input).map(|(i, x)| (i, Address(x.try_into().unwrap())))
}

#[derive(Debug, PartialEq)]
pub enum ExtensionHeader {
    HopByHop,
}

fn extension_header<'a>(
    input: &'a [u8],
    _extension_header: NextHeader,
) -> nom::IResult<&'a [u8], (NextHeader, u16, ExtensionHeader)> {
    let (input, next_header) = map_res(be_u8, NextHeader::try_from)(input)?;
    let (input, header_len) = be_u8(input)?;
    let input = &input[header_len as usize + 6..];

    Ok((
        input,
        (
            next_header,
            (header_len + 8) as u16,
            ExtensionHeader::HopByHop,
        ),
    ))
}

#[derive(Debug, PartialEq)]
pub struct Packet {
    traffic_class: u8,
    flow_label: u32,
    next_header: NextHeader,
    hop_limit: u8,
    src: Address,
    dest: Address,
    extension_headers: Vec<ExtensionHeader>,
    payload: Vec<u8>,
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

            if next_header == NextHeader::HopByHop {
                let (new_input, (new_next_header, num_header_bytes, header)) =
                    extension_header(input, next_header)?;
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

pub struct Server {
    frame_receiver: channel::Receiver<ether::Frame>,
    icmpv6_receiver: channel::Receiver<Packet>,
    recv_map: Arc<RecvSenderMap<Packet>>,
}

impl Server {
    pub fn new(ether_server: &mut impl ether::Server) -> AHResult<Self> {
        let (frame_sender, frame_receiver) = channel::bounded(1024);
        ether_server.register(ether::Type::Ipv6, frame_sender);

        let (icmpv6_sender, icmpv6_receiver) = channel::bounded(1024);

        let mut server = Self {
            frame_receiver,
            icmpv6_receiver,
            recv_map: Arc::new(RecvSenderMap::new()),
        };

        server.register(
            NextHeader::Protocol(ipv4::ProtocolNumber::Ipv6Icmp),
            icmpv6_sender,
        );

        Ok(server)
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

            let packet = packet(&frame.payload).unwrap();

            recv_map.dispatch(packet).unwrap();
        });
    }

    pub fn start_icmpv6(&self) {
        let icmpv6_receiver = self.icmpv6_receiver.clone();

        thread::spawn(move || loop {
            let ip_packet = icmpv6_receiver.recv().unwrap();

            let packet = icmpv6::packet(
                &ip_packet.payload,
                icmpv6::PseudoHeader {
                    src: ip_packet.src,
                    dest: ip_packet.dest,
                    length: ip_packet.payload.len() as u32,
                },
            )
            .unwrap();
        });
    }
}

impl KeyedDispatcher for Server {
    type Item = Packet;

    fn recv_map(&self) -> &RecvSenderMap<Packet> {
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
    fn full_address_parses() {
        assert_eq!(
            "FEDC:BA98:7654:3210:FEDC:BA98:7654:3210"
                .parse::<Address>()
                .unwrap(),
            Address([0xFEDC, 0xBA98, 0x7654, 0x3210, 0xFEDC, 0xBA98, 0x7654, 0x3210])
        );
        assert_eq!(
            "1080:0:0:0:8:800:200C:417A".parse::<Address>().unwrap(),
            Address([0x1080, 0, 0, 0, 0x8, 0x800, 0x200C, 0x417A])
        );
    }

    #[test]
    fn partial_address_parses() {
        assert_eq!(
            "1080::8:800:200C:417A".parse::<Address>().unwrap(),
            Address([0x1080, 0, 0, 0, 0x8, 0x800, 0x200C, 0x417A])
        );
        assert_eq!(
            "FF01::101".parse::<Address>().unwrap(),
            Address([0xFF01, 0, 0, 0, 0, 0, 0, 0x101])
        );
        assert_eq!(
            "::1".parse::<Address>().unwrap(),
            Address([0, 0, 0, 0, 0, 0, 0, 1])
        );
        assert_eq!(
            "::".parse::<Address>().unwrap(),
            Address([0, 0, 0, 0, 0, 0, 0, 0])
        );
    }

    #[test]
    #[should_panic]
    fn double_placeholder_address_does_not_parse() {
        "1080::8::417A".parse::<Address>().unwrap();
    }

    #[test]
    #[should_panic(expected = "8 parts")]
    fn too_short_address_does_not_parse() {
        "1080:8:417A".parse::<Address>().unwrap();
    }

    #[test]
    fn reply_packet_decodes() {
        assert_eq!(
            packet(&hexstring(
                "6001d4b900203afffe80000000000000209efefffe5711e5ff0200000000000000000001ff00001287003fc50000000000f400440000000000000000000000120101560d4f2164f3"
            ))
            .unwrap(),
            Packet {
                traffic_class: 0,
                flow_label: 0x1d4b9,
                next_header: NextHeader::Protocol(ipv4::ProtocolNumber::Ipv6Icmp),
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
            packet(&hexstring(
                "6000000000203afffd00736f746f686e0000000000000001fe80000000000000264163edd76d0807880079e9e0000000fd00736f746f686e000000000000000102011691822a803b"
            ))
            .unwrap(),
            Packet {
                traffic_class: 0,
                flow_label: 0,
                next_header: NextHeader::Protocol(ipv4::ProtocolNumber::Ipv6Icmp),
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
            packet(&hexstring(
                "6008991a003bff4033ab6549000000004cccc624610ea3eb20014860486000000000000000008888c4020035003be7b562ba0120000100000000000106676f6f676c6503636f6d0000010001000029100000000000000c000a0008eb1aa1842012578a"
            ))
            .unwrap(),
            Packet {
                traffic_class: 0,
                flow_label: 0x8991a,
                next_header: NextHeader::Protocol(ipv4::ProtocolNumber::Unknown(0xff)),
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
            packet(&hexstring(
                "600000000024000100000000000000000000000000000000ff0200000000000000000000000000163a000502000001008f008dca0000000104000000ff0200000000000000000001fff9e0c6"
            ))
            .unwrap(),
            Packet {
                traffic_class: 0,
                flow_label: 0,
                next_header: NextHeader::Protocol(ipv4::ProtocolNumber::Ipv6Icmp),
                hop_limit: 0x01,
                src: "::".parse().unwrap(),
                dest: "ff02::16".parse().unwrap(),
                extension_headers: vec![
                   ExtensionHeader::HopByHop,
                ],
                payload: hexstring("8f008dca0000000104000000ff0200000000000000000001fff9e0c6").to_vec(),
            }
        );
    }
}
