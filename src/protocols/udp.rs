use anyhow::Result as AHResult;
use crossbeam::channel;
use std::thread;

use super::utils::KeyedDispatcher;
use super::{ipv4, ipv6};

pub struct UdpServer {
    ipv6_receiver: channel::Receiver<ipv6::Ipv6Packet>,
}

impl UdpServer {
    pub fn new(ipv6_server: &mut ipv6::Ipv6Server) -> AHResult<Self> {
        let (ipv6_sender, ipv6_receiver) = channel::bounded(1024);

        ipv6_server.register(
            ipv6::Ipv6NextHeader::Protocol(ipv4::IpProtocolNumber::Udp),
            ipv6_sender,
        );

        Ok(Self { ipv6_receiver })
    }

    pub fn start(&self) {
        let ipv6_receiver = self.ipv6_receiver.clone();

        thread::spawn(move || loop {
            let _packet = ipv6_receiver.recv().unwrap();
        });
    }
}
