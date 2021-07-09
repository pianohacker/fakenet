use anyhow::{anyhow, Result as AHResult};
use crossbeam::channel;
use nom::{
    combinator::{map_res, verify},
    number::complete::{be_u16, be_u8},
};
use std::collections::HashSet;
use std::convert::TryFrom;
use std::sync::{Arc, RwLock};
use std::thread;

use super::utils::EncodeTo;
use super::{ether, ipv4};
use crate::{encode, proto_enum, try_parse};

proto_enum!(ArpPacketOpcode, u16, {
    Request = 1,
    Reply = 2,
});

#[derive(Debug, PartialEq)]
pub struct ArpPacket {
    pub opcode: ArpPacketOpcode,
    pub src_ether: ether::EtherAddress,
    pub src_ipv4: ipv4::Ipv4Address,
    pub dest_ether: ether::EtherAddress,
    pub dest_ipv4: ipv4::Ipv4Address,
}

impl ArpPacket {
    pub fn encode(&self) -> Vec<u8> {
        encode!(
            1u16,
            ether::EtherType::Ipv4 as u16,
            6u8,
            4u8,
            self.opcode as u16,
            self.src_ether,
            self.src_ipv4,
            self.dest_ether,
            self.dest_ipv4,
        )
    }
}

pub fn arp_packet(input: &[u8]) -> AHResult<ArpPacket> {
    try_parse!(
        {
            let (input, _) = verify(be_u16, |hrd| *hrd == 1)(input)?;
            let (input, _) = verify(be_u16, |pro| *pro == ether::EtherType::Ipv4 as u16)(input)?;
            let (input, _) = verify(be_u8, |hln| *hln == 6)(input)?;
            let (input, _) = verify(be_u8, |pln| *pln == 4)(input)?;
            let (input, opcode) = map_res(be_u16, ArpPacketOpcode::try_from)(input)?;
            let (input, src_ether) = ether::ether_address(input)?;
            let (input, src_ipv4) = ipv4::ipv4_address(input)?;
            let (input, dest_ether) = ether::ether_address(input)?;
            let (input, dest_ipv4) = ipv4::ipv4_address(input)?;

            Ok((
                input,
                ArpPacket {
                    opcode,
                    src_ether,
                    src_ipv4,
                    dest_ether,
                    dest_ipv4,
                },
            ))
        },
        "parsing arp packet failed: {}"
    )
}

pub struct ArpServer {
    receiver: channel::Receiver<ether::EtherFrame>,
    write_sender: channel::Sender<ether::EtherFrame>,
    ether_address: ether::EtherAddress,
    addresses: Arc<RwLock<HashSet<ipv4::Ipv4Address>>>,
}

impl ArpServer {
    pub fn new(interface: &mut impl ether::EthernetServer) -> AHResult<Self> {
        let (sender, receiver) = channel::bounded(1024);
        interface.register(ether::EtherType::Arp, sender);

        Ok(Self {
            receiver,
            write_sender: interface.writer(),
            ether_address: interface.if_hwaddr()?,
            addresses: Arc::new(RwLock::new(HashSet::new())),
        })
    }

    pub fn start(&self) {
        let receiver = self.receiver.clone();
        let write_sender = self.write_sender.clone();
        let src_ether = self.ether_address;
        let addresses = self.addresses.clone();

        thread::spawn(move || loop {
            let frame = receiver.recv().unwrap();

            let packet = arp_packet(&frame.payload).unwrap();

            if addresses.read().unwrap().contains(&packet.dest_ipv4) {
                let frame = ether::EtherFrame {
                    dest: packet.src_ether,
                    src: src_ether,
                    ethertype: ether::EtherType::Arp,
                    payload: ArpPacket {
                        opcode: ArpPacketOpcode::Reply,
                        src_ether,
                        src_ipv4: packet.dest_ipv4,
                        dest_ether: packet.src_ether,
                        dest_ipv4: packet.src_ipv4,
                    }
                    .encode(),
                };

                write_sender.send(frame).unwrap();
            }
        });
    }

    pub fn add(&self, address: ipv4::Ipv4Address) {
        self.addresses.write().unwrap().insert(address);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hexstring(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    #[test]
    fn reply_packet_decodes() {
        assert_eq!(
            arp_packet(&hexstring(
                "0001080006040001000af56dbc840a0001eb0000000000000a000002"
            ))
            .unwrap(),
            ArpPacket {
                opcode: ArpPacketOpcode::Request,
                src_ether: ether::EtherAddress([0, 10, 245, 109, 188, 132]),
                src_ipv4: ipv4::Ipv4Address([10, 0, 1, 235]),
                dest_ether: ether::EtherAddress([0, 0, 0, 0, 0, 0]),
                dest_ipv4: ipv4::Ipv4Address([10, 0, 0, 2]),
            }
        );
    }

    #[test]
    fn request_packet_decodes() {
        assert_eq!(
            arp_packet(&hexstring(
                "0001080006040002b827ebb38fcf0a00012204d9f5f844e80a000168"
            ))
            .unwrap(),
            ArpPacket {
                opcode: ArpPacketOpcode::Reply,
                src_ether: ether::EtherAddress([184, 39, 235, 179, 143, 207]),
                src_ipv4: ipv4::Ipv4Address([10, 0, 1, 34]),
                dest_ether: ether::EtherAddress([4, 217, 245, 248, 68, 232]),
                dest_ipv4: ipv4::Ipv4Address([10, 0, 1, 104]),
            }
        );
    }
}
