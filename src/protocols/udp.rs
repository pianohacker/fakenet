use anyhow::Result as AHResult;
use crossbeam::channel;
use std::thread;

use super::utils::KeyedDispatcher;
use super::{ipv4, ipv6};

pub struct Server {
    ipv6_receiver: channel::Receiver<ipv6::Packet>,
}

impl Server {
    pub fn new(ipv6_server: &mut ipv6::Server) -> AHResult<Self> {
        let (ipv6_sender, ipv6_receiver) = channel::bounded(1024);

        ipv6_server.register(
            ipv6::NextHeader::Protocol(ipv4::ProtocolNumber::Udp),
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
