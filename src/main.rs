use anyhow::{anyhow, Result as AHResult};
use crossbeam::channel;
use std::collections::{HashMap, HashSet};
use std::os::unix::io as unix_io;
use std::sync::{Arc, RwLock};
use std::thread;

mod protocols;
mod tap_device;

// fn handle_arp_frame(frame: protocols::EtherFrame) -> AHResult<()> {
//     let (_, packet) = protocols::arp_packet(&frame.payload)
//         .map_err(|e| anyhow!("parsing arp packet failed: {}", e.to_string()))?;

//     Ok(())
// }

// fn handle_ether_data(data: &[u8]) -> AHResult<()> {
//     let (_, frame) = protocols::ether_frame(&data)
//         .map_err(|e| anyhow!("parsing ethernet frame failed: {}", e.to_string()))?;

//     match frame.ethertype {
//         0x0806 => {
//             handle_arp_frame(frame)?;
//         }
//         0x86dd => {
//             println!("INFO: IPv6 frame: {}", frame);
//         }
//         _ => {
//             println!("WARN: Unhandled frame: {}", frame);
//         }
//     }

//     Ok(())
// }

trait DispatchKeyed: Send + Sync
where
    Self::Key: std::fmt::Display + Eq + std::hash::Hash + Sync + Send,
{
    type Key;

    fn dispatch_key(&self) -> Self::Key;
}

impl DispatchKeyed for protocols::EtherFrame {
    type Key = protocols::EtherType;

    fn dispatch_key(&self) -> Self::Key {
        self.ethertype
    }
}

struct RecvSenderMap<T: DispatchKeyed>(
    RwLock<HashMap<<T as DispatchKeyed>::Key, channel::Sender<T>>>,
);

impl<T: DispatchKeyed + Send + Sync> RecvSenderMap<T> {
    fn new() -> Self {
        Self(RwLock::new(HashMap::new()))
    }

    fn dispatch(&self, item: T) -> AHResult<()> {
        let key = item.dispatch_key();
        if let Some(ref sender) = &self.0.write().unwrap().get(&key) {
            sender
                .send(item)
                .map_err(|_| anyhow!("failed to send to {}", key))?;
        } else {
            println!("WARN: unhandled {}", key);
        };

        Ok(())
    }

    pub fn register(&self, key: <T as DispatchKeyed>::Key, sender: channel::Sender<T>) {
        self.0.write().unwrap().insert(key, sender.clone());
    }
}

trait KeyedDispatcher
where
    Self::Item: DispatchKeyed,
{
    type Item;

    fn recv_map(&self) -> &RecvSenderMap<Self::Item>;

    fn register(
        &mut self,
        key: <Self::Item as DispatchKeyed>::Key,
        sender: channel::Sender<Self::Item>,
    ) {
        self.recv_map().register(key, sender);
    }
}

struct TapEthernetInterface {
    tap_dev: Arc<RwLock<tap_device::TapDevice>>,
    recv_map: Arc<RecvSenderMap<protocols::EtherFrame>>,
    write_sender: channel::Sender<protocols::EtherFrame>,
    write_receiver: channel::Receiver<protocols::EtherFrame>,
    write_alert_read_fd: unix_io::RawFd,
    write_alert_write_fd: unix_io::RawFd,
}

impl TapEthernetInterface {
    pub fn open() -> AHResult<Self> {
        let tap_dev = tap_device::TapDevice::open()?;

        let (write_sender, write_receiver) = channel::bounded(1024);

        let (write_alert_read_fd, write_alert_write_fd) = nix::unistd::pipe()?;

        Ok(Self {
            tap_dev: Arc::new(RwLock::new(tap_dev)),
            recv_map: Arc::new(RecvSenderMap::new()),
            write_sender,
            write_receiver,
            write_alert_read_fd,
            write_alert_write_fd,
        })
    }

    pub fn start(&self) -> AHResult<()> {
        let tap_dev = Arc::clone(&self.tap_dev);
        let recv_map = Arc::clone(&self.recv_map);
        let write_alert_read_fd = self.write_alert_read_fd;
        let write_receiver = self.write_receiver.clone();

        self.tap_dev.write().unwrap().up()?;

        thread::spawn(move || {
            let mut buffer = Vec::new();
            buffer.resize(tap_device::TapDevice::FRAME_SIZE, 0u8);

            let tap_dev_fd = tap_dev.read().unwrap().rawfd();
            let mut fd_set = nix::sys::select::FdSet::new();
            fd_set.insert(write_alert_read_fd);
            fd_set.insert(tap_dev_fd);

            let mut write_alert_read =
                unsafe { <std::fs::File as unix_io::FromRawFd>::from_raw_fd(write_alert_read_fd) };

            loop {
                let mut fd_set = fd_set.clone();
                nix::sys::select::select(None, Some(&mut fd_set), None, None, None).unwrap();

                if fd_set.contains(tap_dev_fd) {
                    let num_read = tap_dev.write().unwrap().read(&mut buffer).unwrap();
                    let frame = protocols::ether_frame(&buffer[..num_read])
                        .map_err(|e| anyhow!("parsing ethernet frame failed: {}", e.to_string()))
                        .unwrap();

                    recv_map.dispatch(frame).unwrap();
                }

                if fd_set.contains(write_alert_read_fd) {
                    // Read only one character, in case we have multiple frames backed up.
                    <std::fs::File as std::io::Read>::read(&mut write_alert_read, &mut buffer[..1])
                        .unwrap();

                    let frame = write_receiver.recv().unwrap();

                    tap_dev.write().unwrap().write(&frame.encode()).unwrap();
                }
            }
        });

        Ok(())
    }

    pub fn if_hwaddr(&self) -> AHResult<protocols::EtherAddress> {
        self.tap_dev.read().unwrap().if_hwaddr()
    }

    pub fn if_name(&self) -> AHResult<String> {
        self.tap_dev.read().unwrap().if_name()
    }

    fn writer(&self) -> crossbeam::channel::Sender<protocols::EtherFrame> {
        let mut write_alert_write = unsafe {
            <std::fs::File as unix_io::FromRawFd>::from_raw_fd(self.write_alert_write_fd)
        };
        let sender = self.write_sender.clone();

        let (alerter_sender, alerter_receiver) = crossbeam::channel::bounded(1024);

        thread::spawn(move || loop {
            let frame = alerter_receiver.recv().unwrap();
            sender.send(frame).unwrap();
            <std::fs::File as std::io::Write>::write(&mut write_alert_write, &[1u8]).unwrap();
        });

        alerter_sender
    }
}

impl KeyedDispatcher for TapEthernetInterface {
    type Item = protocols::EtherFrame;

    fn recv_map(&self) -> &RecvSenderMap<protocols::EtherFrame> {
        &self.recv_map
    }
}

struct ArpServer {
    receiver: channel::Receiver<protocols::EtherFrame>,
    write_sender: channel::Sender<protocols::EtherFrame>,
    ether_address: protocols::EtherAddress,
    addresses: Arc<RwLock<HashSet<protocols::Ipv4Address>>>,
}

impl ArpServer {
    fn new(interface: &mut TapEthernetInterface) -> AHResult<Self> {
        let (sender, receiver) = channel::bounded(1024);
        interface.register(protocols::EtherType::Arp, sender);

        Ok(Self {
            receiver,
            write_sender: interface.writer(),
            ether_address: interface.if_hwaddr()?,
            addresses: Arc::new(RwLock::new(HashSet::new())),
        })
    }

    fn start(&self) {
        let receiver = self.receiver.clone();
        let write_sender = self.write_sender.clone();
        let src_ether = self.ether_address;
        let addresses = self.addresses.clone();

        thread::spawn(move || loop {
            let frame = receiver.recv().unwrap();

            let packet = protocols::arp_packet(&frame.payload).unwrap();

            if addresses.read().unwrap().contains(&packet.dest_ipv4) {
                let frame = protocols::EtherFrame {
                    dest: packet.src_ether,
                    src: src_ether,
                    ethertype: protocols::EtherType::Arp,
                    payload: protocols::ArpPacket {
                        opcode: protocols::ArpPacketOpcode::Reply,
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

    fn add(&self, address: protocols::Ipv4Address) {
        self.addresses.write().unwrap().insert(address);
    }
}

fn main() -> AHResult<()> {
    let mut eth = TapEthernetInterface::open()?;
    println!("Interface: {}", eth.if_name()?);

    let arp_server = ArpServer::new(&mut eth)?;
    arp_server.add("10.1.0.1".parse()?);
    arp_server.start();

    eth.start()?;

    loop {
        thread::park();
    }
}
