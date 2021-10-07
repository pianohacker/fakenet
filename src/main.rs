use anyhow::Result as AHResult;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::thread;

mod delay_queue;
mod protocols;
mod reactor;
mod tap_device;

#[derive(Deserialize)]
struct Network {
    node: Node,
}

#[derive(Deserialize)]
struct Node {
    address: String,
}

#[derive(Serialize)]
enum StatusMessage {
    InterfaceName { name: String },
}

fn report(msg: StatusMessage) {
    let stdout_handle = std::io::stdout();
    let mut stdout = stdout_handle.lock();

    serde_json::to_writer(&mut stdout, &msg).unwrap();
    write!(stdout, "\n").unwrap();
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

    let mut eth = protocols::ether::TapInterface::open(network.node.address.parse()?)?;
    report(StatusMessage::InterfaceName {
        name: eth.if_name()?,
    });

    let arp_server = protocols::arp::Server::new(&mut eth)?;
    arp_server.add("10.1.0.1".parse()?);
    arp_server.start();

    let mut ipv6_server = protocols::ipv6::Server::new(&mut eth)?;
    ipv6_server.start();

    let udp_server = protocols::udp::Server::new(&mut ipv6_server)?;
    udp_server.start();

    eth.start()?;

    loop {
        thread::park();
    }
}
