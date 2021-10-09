use anyhow::Result as AHResult;
use serde::Deserialize;
use std::env;
use std::fs::File;
use std::io::Read;
use std::thread;

mod delay_queue;
mod protocols;
mod status;
mod tap_device;

#[derive(Deserialize)]
struct Network {
    node: Node,
}

#[derive(Deserialize)]
struct Node {
    ether_address: String,
    ipv4_address: Option<String>,
}

fn main() -> AHResult<()> {
    let mut network_config = String::new();
    File::open(
        env::args()
            .nth(1)
            .expect("expected a network config file as an argument"),
    )?
    .read_to_string(&mut network_config)?;
    let network: Network = toml::from_str(&network_config)?;

    let mut eth = protocols::ether::TapInterface::open(network.node.ether_address.parse()?)?;
    status::update()
        .child("interface")
        .field("name", eth.if_name()?)
        .write();

    if let Some(ipv4_address) = network.node.ipv4_address {
        let arp_server = protocols::arp::Server::new(&mut eth)?;
        arp_server.add(ipv4_address.parse()?);
        arp_server.start();
    }

    let mut ipv6_server = protocols::ipv6::Server::new(&mut eth)?;
    ipv6_server.start();

    let udp_server = protocols::udp::Server::new(&mut ipv6_server)?;
    udp_server.start();

    eth.start()?;

    loop {
        thread::park();
    }
}
