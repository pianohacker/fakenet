use anyhow::Result as AHResult;
use crossbeam::channel;
use rand::Rng;
use serde::Serialize;
use std::cell::RefCell;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

mod address;
mod icmpv6;
mod packet;

use super::ether;
use super::ipv4;
use super::utils::{KeyedDispatcher, RecvSenderMap};
use crate::delay_queue::DelayQueue;
use crate::select_queues;
use crate::status;

use self::address::address;
pub use self::address::Address;

pub use self::packet::NextHeader;
pub use self::packet::Packet;

const _MULTICAST_ALL_NODES: Address = Address([0xff01, 0, 0, 0, 0, 0, 0, 0x1]);
const RFC4861_MAX_RTR_SOLICITATION_DELAY: Duration = Duration::from_secs(1);
const RFC4861_RETRANS_TIMER_MS: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, Serialize)]
enum InterfaceAddressState {
    New,
    Tentative,
    Valid,
}

#[derive(Clone, Copy, Debug)]
struct InterfaceAddress {
    address: Address,
    state: InterfaceAddressState,
}

impl InterfaceAddress {
    fn new(address: Address) -> Self {
        Self {
            address,
            state: InterfaceAddressState::New,
        }
    }

    fn address(&self) -> Address {
        self.address
    }

    fn state(&self) -> InterfaceAddressState {
        self.state
    }

    fn set_state(&mut self, state: InterfaceAddressState) {
        self.state = state;

        status::update()
            .child("interface")
            .child("addresses")
            .child(format!("{}", self.address))
            .field("state", self.state)
            .write();
    }
}

struct Actor {
    src_ether: ether::Address,
    incoming_receiver: channel::Receiver<ether::Frame>,
    outgoing_sender: channel::Sender<ether::Frame>,
    recv_map: Arc<RecvSenderMap<packet::Packet>>,
    addresses: Vec<RefCell<InterfaceAddress>>,
    addr_maint_queue: DelayQueue<Address>,
}

impl Actor {
    fn new(
        src_ether: ether::Address,
        incoming_receiver: channel::Receiver<ether::Frame>,
        outgoing_sender: channel::Sender<ether::Frame>,
        recv_map: Arc<RecvSenderMap<packet::Packet>>,
    ) -> Self {
        Self {
            src_ether,
            incoming_receiver,
            outgoing_sender,
            recv_map,
            addresses: Vec::new(),

            addr_maint_queue: DelayQueue::new(),
        }
    }

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

    fn maintain_addr(&mut self, addr: Address) -> AHResult<()> {
        let mut addr_info = self
            .addresses
            .iter()
            .find(|ai| ai.borrow().address() == addr)
            .unwrap()
            .borrow_mut();

        match addr_info.state() {
            InterfaceAddressState::New => {
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
                            address: addr.solicited_nodes_multicast(),
                        },
                    ]),
                )?;

                self.send_icmpv6(
                    "::".parse().unwrap(),
                    addr.solicited_nodes_multicast(),
                    icmpv6::Packet::NeighborSolicitation {
                        dest: addr,
                        options: vec![],
                    },
                )?;

                addr_info.set_state(InterfaceAddressState::Tentative);

                self.addr_maint_queue
                    .push_after(RFC4861_RETRANS_TIMER_MS, addr);
            }
            InterfaceAddressState::Tentative => {
                addr_info.set_state(InterfaceAddressState::Valid);
            }
            _ => {}
        };

        Ok(())
    }

    fn run(&mut self) {
        let mut rng = rand::thread_rng();

        let link_local_address = Address::random(&mut rng)
            .suffix(64)
            .combine_subnet(&("fe80::".parse().unwrap()));

        self.addresses
            .push(RefCell::new(InterfaceAddress::new(link_local_address)));

        self.addr_maint_queue.push_after(
            rng.gen_range(Duration::ZERO..RFC4861_MAX_RTR_SOLICITATION_DELAY),
            link_local_address,
        );

        loop {
            select_queues! {
                recv_queue(self.addr_maint_queue) -> addr => self.maintain_addr(addr.unwrap()).unwrap(),
                recv(self.incoming_receiver) -> frame => {
                    let packet = packet::packet(&frame.unwrap().payload).unwrap();

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
                },
            }
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
            actor: Some(Actor::new(
                ether_server.if_hwaddr()?,
                incoming_receiver,
                ether_server.writer(),
                recv_map.clone(),
            )),
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
