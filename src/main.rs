use anyhow::Result as AHResult;
use std::thread;

mod protocols;
mod tap_device;

fn main() -> AHResult<()> {
    let mut eth = protocols::ether::TapInterface::open()?;
    println!("Interface: {}", eth.if_name()?);

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
