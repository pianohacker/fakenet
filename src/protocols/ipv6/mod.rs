use anyhow::Result as AHResult;
use crossbeam::channel;
use std::sync::Arc;
use std::thread;

mod address;
mod icmpv6;
mod packet;

use super::ether;
use super::ipv4;
use super::utils::{KeyedDispatcher, RecvSenderMap};

use self::address::address;
pub use self::address::Address;

pub use self::packet::NextHeader;
pub use self::packet::Packet;

const _MULTICAST_ALL_NODES: Address = Address([0xff01, 0, 0, 0, 0, 0, 0, 0x1]);

struct InterfaceAddress {
    address: Address,
    tentative: bool,
}

struct Actor {
    src_ether: ether::Address,
    incoming_receiver: channel::Receiver<ether::Frame>,
    outgoing_sender: channel::Sender<ether::Frame>,
    recv_map: Arc<RecvSenderMap<packet::Packet>>,
    addresses: Vec<InterfaceAddress>,
}

impl Actor {
    fn send_ipv6(&self, packet: packet::Packet) -> AHResult<()> {
        self.outgoing_sender.send(ether::Frame {
            dest: packet.dest.multicast_ether_dest(),
            src: self.src_ether,
            ethertype: ether::Type::Ipv6,
            payload: packet.encode(),
        })?;

        Ok(())
    }

    fn send_icmpv6(&self, src: Address, dest: Address, packet: icmpv6::Packet) -> AHResult<()> {
        let builder = packet::Packet::builder()
            .protocol(ipv4::ProtocolNumber::Ipv6Icmp)
            .hop_limit(0xff)
            .src(src)
            .dest(dest)
            .payload(packet.encode(icmpv6::PseudoHeader {
                src,
                dest,
                length: 0,
            }));

        let builder = match packet {
            icmpv6::Packet::MldV2Report(_) => {
                builder.extension_header(packet::ExtensionHeader::HopByHopOptions(vec![
                    packet::HopByHopOption::RouterAlert(packet::RouterAlertType::Mld),
                ]))
            }
            _ => builder,
        };

        self.send_ipv6(builder.build())
    }

    fn run(&mut self) {
        let mut rng = rand::thread_rng();
        let link_local_address = Address::random(&mut rng)
            .suffix(64)
            .combine_subnet(&("fe80::".parse().unwrap()));

        thread::sleep(std::time::Duration::from_millis(500));

        self.send_icmpv6(
            "::".parse().unwrap(),
            "ff02::16".parse().unwrap(),
            icmpv6::Packet::MldV2Report(vec![
                icmpv6::MldV2AddressRecord {
                    record_type: icmpv6::Mldv2AddressRecordType::ChangeToExcludeMode,
                    address: "ff02::1".parse().unwrap(),
                },
                icmpv6::MldV2AddressRecord {
                    record_type: icmpv6::Mldv2AddressRecordType::ChangeToExcludeMode,
                    address: link_local_address.solicited_nodes_multicast(),
                },
            ]),
        )
        .unwrap();

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

            let packet = packet::packet(&frame.payload).unwrap();

            if packet.next_header != packet::NextHeader::Protocol(ipv4::ProtocolNumber::Ipv6Icmp) {
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
    recv_map: Arc<RecvSenderMap<packet::Packet>>,
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
    type Item = packet::Packet;

    fn recv_map(&self) -> &RecvSenderMap<packet::Packet> {
        &self.recv_map
    }
}
