use anyhow::{anyhow, Result as AHResult};
use crossbeam::channel;
use nom::{
    bits, bytes,
    combinator::map_res,
    number::complete::{be_u16, be_u8},
    sequence::tuple,
};
use std::convert::TryFrom;
use std::sync::Arc;
use std::thread;

mod address;
mod icmpv6;

use super::encdec::EncodeTo;
use super::ether;
use super::ipv4;
use super::utils::{DispatchKeyed, KeyedDispatcher, RecvSenderMap};
use crate::{encode, try_parse};

use self::address::address;
pub use self::address::Address;

const _MULTICAST_ALL_NODES: Address = Address([0xff01, 0, 0, 0, 0, 0, 0, 0x1]);

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub enum NextHeader {
    Unset,
    HopByHop,
    Protocol(ipv4::ProtocolNumber),
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
            NextHeader::Unset => write!(f, "Unset"),
            NextHeader::HopByHop => write!(f, "HopByHop"),
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
            NextHeader::HopByHop => 0u8.encode_to(buf),
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

#[derive(Debug, PartialEq)]
pub enum ExtensionHeader {
    HopByHop,
}

impl EncodeTo for ExtensionHeader {
    fn encoded_len(&self) -> usize {
        todo!();
    }

    fn encode_to(&self, _buf: &mut [u8]) {
        todo!();
    }
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

#[derive(Debug, Default, PartialEq)]
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

impl Packet {
    fn builder() -> PacketBuilder {
        PacketBuilder(Self::default())
    }

    fn encode(&self) -> Vec<u8> {
        let prelude = (6u32 << 28) | ((self.traffic_class as u32) << 20) | self.flow_label;
        let encoded_extension_headers = encode!(self.extension_headers);

        encode!(
            prelude,
            (encoded_extension_headers.len() + self.payload.len()) as u16,
            self.next_header,
            self.hop_limit,
            self.src,
            self.dest,
            encoded_extension_headers,
            self.payload,
        )
    }
}

struct PacketBuilder(Packet);

impl PacketBuilder {
    fn protocol(self, proto: ipv4::ProtocolNumber) -> Self {
        Self(Packet {
            next_header: NextHeader::Protocol(proto),
            ..self.0
        })
    }

    fn hop_limit(self, hop_limit: u8) -> Self {
        Self(Packet {
            hop_limit,
            ..self.0
        })
    }

    fn src(self, src: Address) -> Self {
        Self(Packet { src, ..self.0 })
    }

    fn dest(self, dest: Address) -> Self {
        Self(Packet { dest, ..self.0 })
    }

    fn payload(self, payload: Vec<u8>) -> Self {
        Self(Packet { payload, ..self.0 })
    }

    fn build(self) -> Packet {
        self.0
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

struct InterfaceAddress {
    address: Address,
    tentative: bool,
}

struct Actor {
    src_ether: ether::Address,
    incoming_receiver: channel::Receiver<ether::Frame>,
    outgoing_sender: channel::Sender<ether::Frame>,
    recv_map: Arc<RecvSenderMap<Packet>>,
    addresses: Vec<InterfaceAddress>,
}

impl Actor {
    fn send_ipv6(&self, packet: Packet) -> AHResult<()> {
        self.outgoing_sender.send(ether::Frame {
            dest: packet.dest.multicast_ether_dest(),
            src: self.src_ether,
            ethertype: ether::Type::Ipv6,
            payload: packet.encode(),
        })?;

        Ok(())
    }

    fn send_icmpv6(&self, src: Address, dest: Address, packet: icmpv6::Packet) -> AHResult<()> {
        self.send_ipv6(
            Packet::builder()
                .protocol(ipv4::ProtocolNumber::Ipv6Icmp)
                .hop_limit(0xff)
                .src(src)
                .dest(dest)
                .payload(packet.encode(icmpv6::PseudoHeader {
                    src,
                    dest,
                    length: 0,
                }))
                .build(),
        )
    }

    fn run(&mut self) {
        let mut rng = rand::thread_rng();
        let link_local_address = Address::random(&mut rng)
            .suffix(64)
            .combine_subnet(&("fe80::".parse().unwrap()));

        thread::sleep(std::time::Duration::from_millis(500));

        self.send_icmpv6(
            "::".parse().unwrap(),
            link_local_address.solicited_nodes_multicast(),
            icmpv6::Packet::NeighborSolicitation {
                dest: link_local_address,
                options: vec![],
            },
        )
        .unwrap();

        loop {
            let frame = self.incoming_receiver.recv().unwrap();

            let packet = packet(&frame.payload).unwrap();

            if packet.next_header != NextHeader::Protocol(ipv4::ProtocolNumber::Ipv6Icmp) {
                self.recv_map.dispatch(packet).unwrap();
                continue;
            }

            let _icmpv6_packet = icmpv6::packet(
                &packet.payload,
                icmpv6::PseudoHeader {
                    src: packet.src,
                    dest: packet.dest,
                    length: packet.payload.len() as u32,
                },
            )
            .unwrap();
        }
    }
}

pub struct Server {
    actor: Option<Actor>,
    recv_map: Arc<RecvSenderMap<Packet>>,
}

impl Server {
    pub fn new(ether_server: &mut impl ether::Server) -> AHResult<Self> {
        let (incoming_sender, incoming_receiver) = channel::bounded(1024);
        ether_server.register(ether::Type::Ipv6, incoming_sender);

        let recv_map = Arc::new(RecvSenderMap::new());

        Ok(Self {
            actor: Some(Actor {
                src_ether: ether_server.if_hwaddr()?,
                incoming_receiver,
                outgoing_sender: ether_server.writer(),
                recv_map: recv_map.clone(),
                addresses: Vec::new(),
            }),
            recv_map,
        })
    }

    pub fn start(&mut self) {
        let mut actor = self.actor.take().unwrap();

        thread::spawn(move || loop {
            actor.run();
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
            Packet {
                traffic_class: 0,
                flow_label: 0x8991a,
                next_header: NextHeader::Protocol(ipv4::ProtocolNumber::Unknown(0xff)),
                hop_limit: 0x40,
                src: ipv6a("33ab:6549::4ccc:c624:610e:a3eb"),
                dest: ipv6a("2001:4860:4860::8888"),
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
                src: ipv6a("::"),
                dest: ipv6a("ff02::16"),
                extension_headers: vec![
                   ExtensionHeader::HopByHop,
                ],
                payload: hexstring("8f008dca0000000104000000ff0200000000000000000001fff9e0c6").to_vec(),
            }
        );
    }

    #[test]
    fn basic_packet_encodes() {
        assert_eq!(
            Packet {
                traffic_class: 0x54,
                flow_label: 0x1d4b9,
                next_header: NextHeader::Protocol(ipv4::ProtocolNumber::Ipv6Icmp),
                hop_limit: 0xff,
                src: ipv6a("fe80::209e:feff:fe57:11e5"),
                dest: ipv6a("ff02::1:ff00:12"),
                extension_headers: vec![],
                payload: hexstring("87003fc50000000000f400440000000000000000000000120101560d4f2164f3").to_vec(),
            }.encode(),
            hexstring(
                "6541d4b900203afffe80000000000000209efefffe5711e5ff0200000000000000000001ff00001287003fc50000000000f400440000000000000000000000120101560d4f2164f3"
            )
        );
    }
}
