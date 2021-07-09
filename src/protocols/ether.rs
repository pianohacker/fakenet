use anyhow::{anyhow, Result as AHResult};
use crossbeam::channel;
use nom::{bytes::complete::take, combinator::map_res, number::complete::be_u16};
use std::convert::{TryFrom, TryInto};
use std::fmt::{Display, Formatter};
use std::os::unix::io as unix_io;
use std::sync::{Arc, RwLock};
use std::thread;

use super::utils::{hexdump, BIResult, DispatchKeyed, EncodeTo, KeyedDispatcher, RecvSenderMap};
use crate::tap_device;
use crate::{encode, proto_enum, try_parse};

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct EtherAddress(pub [u8; 6]);

impl Display for EtherAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        for (i, part) in self.0.iter().enumerate() {
            write!(f, "{:02x}", part)?;
            if i != 5 {
                write!(f, ":")?;
            }
        }

        Ok(())
    }
}

pub fn ether_address<'a>(input: &'a [u8]) -> BIResult<'a, EtherAddress> {
    take(6 as usize)(input).map(|(i, x)| (i, EtherAddress(x.try_into().unwrap())))
}

impl EncodeTo for EtherAddress {
    fn encoded_len(&self) -> usize {
        6
    }

    fn encode_to(&self, buf: &mut [u8]) {
        buf[..6].copy_from_slice(&self.0);
    }
}

proto_enum!(EtherType, u16, {
    Arp = 0x0806,
    Ipv4 = 0x0800,
    Ipv6 = 0x86DD,
});

#[derive(Debug, PartialEq)]
pub struct EtherFrame {
    pub dest: EtherAddress,
    pub src: EtherAddress,
    pub ethertype: EtherType,
    pub payload: Vec<u8>,
}

impl Display for EtherFrame {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "From: {}, To: {}, Ethertype: {}\n{}",
            self.src,
            self.dest,
            self.ethertype,
            hexdump(&self.payload)?
        )?;

        Ok(())
    }
}

impl EtherFrame {
    pub fn encode(&self) -> Vec<u8> {
        let mut result = encode!(self.dest, self.src, self.ethertype as u16);

        result.extend_from_slice(&self.payload);

        if result.len() < 60 {
            result.resize(60, 0u8);
        }

        result
    }
}

pub fn ether_frame<'a>(input: &'a [u8]) -> AHResult<EtherFrame> {
    try_parse!(
        {
            let (input, dest) = ether_address(input)?;
            let (input, src) = ether_address(input)?;
            let (input, ethertype) = map_res(be_u16, EtherType::try_from)(input)?;

            Ok((
                input,
                EtherFrame {
                    dest,
                    src,
                    ethertype,
                    payload: input.to_vec(),
                },
            ))
        },
        "parsing ethernet frame failed: {}"
    )
}

impl DispatchKeyed for EtherFrame {
    type Key = EtherType;

    fn dispatch_key(&self) -> Self::Key {
        self.ethertype
    }
}

pub struct TapEthernetInterface {
    tap_dev: Arc<RwLock<tap_device::TapDevice>>,
    recv_map: Arc<RecvSenderMap<EtherFrame>>,
    write_sender: channel::Sender<EtherFrame>,
    write_receiver: channel::Receiver<EtherFrame>,
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
                    let frame = ether_frame(&buffer[..num_read])
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

    pub fn if_name(&self) -> AHResult<String> {
        self.tap_dev.read().unwrap().if_name()
    }
}

impl KeyedDispatcher for TapEthernetInterface {
    type Item = EtherFrame;

    fn recv_map(&self) -> &RecvSenderMap<EtherFrame> {
        &self.recv_map
    }
}

pub trait EthernetServer: KeyedDispatcher<Item = EtherFrame> {
    fn if_hwaddr(&self) -> AHResult<EtherAddress>;
    fn writer(&self) -> crossbeam::channel::Sender<EtherFrame>;
}

impl EthernetServer for TapEthernetInterface {
    fn if_hwaddr(&self) -> AHResult<EtherAddress> {
        Ok(EtherAddress(self.tap_dev.read().unwrap().if_hwaddr()?))
    }

    fn writer(&self) -> crossbeam::channel::Sender<EtherFrame> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_decodes() {
        assert_eq!(
            ether_frame(b"123456abcdef\x08\x00payload").unwrap(),
            EtherFrame {
                dest: EtherAddress(*b"123456"),
                src: EtherAddress(*b"abcdef"),
                ethertype: EtherType::Ipv4,
                payload: b"payload".to_vec(),
            }
        );
    }
}
