//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//                    Version 2, December 2004
//
// Copyleft (ↄ) meh. <meh@schizofreni.co> | http://meh.schizofreni.co
//
// Everyone is permitted to copy and distribute verbatim or modified
// copies of this license document, and changing it is allowed as long
// as the name is changed.
//
//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
//
//  0. You just DO WHAT THE FUCK YOU WANT TO.

//! Bindings to internal Linux stuff.
#![allow(dead_code)]

mod tun_sys {
    use libc::sockaddr;
    use libc::{c_char, c_int, c_short, c_uchar, c_uint, c_ulong, c_ushort, c_void};
    use nix::{ioctl_read_bad, ioctl_write_ptr, ioctl_write_ptr_bad};
    use std::mem;

    pub const ARPHRD_ETHER: libc::sa_family_t = 1;

    const IFNAMSIZ: usize = 16;

    pub const IFF_UP: c_short = 0x1;
    const IFF_RUNNING: c_short = 0x40;

    const IFF_TUN: c_short = 0x0001;
    pub const IFF_TAP: c_short = 0x0002;
    pub const IFF_NO_PI: c_short = 0x1000;
    const IFF_MULTI_QUEUE: c_short = 0x0100;

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct IfMap {
        pub mem_start: c_ulong,
        pub mem_end: c_ulong,
        pub base_addr: c_ushort,
        pub irq: c_uchar,
        pub dma: c_uchar,
        pub port: c_uchar,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub union IfSu {
        pub raw_hdlc_proto: *mut c_void,
        pub cisco: *mut c_void,
        pub fr: *mut c_void,
        pub fr_pvc: *mut c_void,
        pub fr_pvc_info: *mut c_void,
        pub sync: *mut c_void,
        pub te1: *mut c_void,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct IfSettings {
        pub type_: c_uint,
        pub size: c_uint,
        pub ifsu: IfSu,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub union IfRn {
        pub name: [c_char; IFNAMSIZ],
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub union IfRu {
        pub addr: sockaddr,
        pub dstaddr: sockaddr,
        pub broadaddr: sockaddr,
        pub netmask: sockaddr,
        pub hwaddr: sockaddr,

        pub flags: c_short,
        pub ivalue: c_int,
        pub mtu: c_int,
        pub map: IfMap,
        pub slave: [c_char; IFNAMSIZ],
        pub newname: [c_char; IFNAMSIZ],
        pub data: *mut c_void,
        pub settings: IfSettings,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct IfReq {
        pub ifrn: IfRn,
        pub ifru: IfRu,
    }

    ioctl_read_bad!(siocgifflags, 0x8913, IfReq);
    ioctl_write_ptr_bad!(siocsifflags, 0x8914, IfReq);
    ioctl_read_bad!(siocgifaddr, 0x8915, IfReq);
    ioctl_write_ptr_bad!(siocsifaddr, 0x8916, IfReq);
    ioctl_read_bad!(siocgifdstaddr, 0x8917, IfReq);
    ioctl_write_ptr_bad!(siocsifdstaddr, 0x8918, IfReq);
    ioctl_read_bad!(siocgifbrdaddr, 0x8919, IfReq);
    ioctl_write_ptr_bad!(siocsifbrdaddr, 0x891a, IfReq);
    ioctl_read_bad!(siocgifnetmask, 0x891b, IfReq);
    ioctl_write_ptr_bad!(siocsifnetmask, 0x891c, IfReq);
    ioctl_read_bad!(siocgifmtu, 0x8921, IfReq);
    ioctl_write_ptr_bad!(siocsifmtu, 0x8922, IfReq);
    ioctl_write_ptr_bad!(siocsifname, 0x8923, IfReq);
    ioctl_write_ptr_bad!(siocgifhwaddr, 0x8927, IfReq);

    ioctl_write_ptr_bad!(
        tunsetiff,
        nix::request_code_write!(b'T', 202, mem::size_of::<c_int>()),
        IfReq
    );
    ioctl_write_ptr!(tunsetpersist, b'T', 203, IfReq);
    ioctl_write_ptr!(tunsetowner, b'T', 204, IfReq);
    ioctl_write_ptr!(tunsetgroup, b'T', 206, IfReq);
}

use anyhow::{bail, Result as AHResult};
use libc::c_char;
use std::ffi::CStr;
use std::fs::{File, OpenOptions};
use std::io;
use std::io::{Read, Write};
use std::mem;
use std::os::unix::io::{AsRawFd, RawFd};

pub struct TapDevice {
    ctl_sock_fd: RawFd,
    file: File,
    if_name_chars: Vec<c_char>,
    buffer: Vec<u8>,
}

impl TapDevice {
    pub const FRAME_SIZE: usize = 1514;

    pub fn open() -> AHResult<Self> {
        let dev_tap = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")?;
        let dev_tap_fd = dev_tap.as_raw_fd();

        let mut if_name_chars;
        unsafe {
            let mut ifr: tun_sys::IfReq = mem::zeroed();
            ifr.ifru.flags = tun_sys::IFF_TAP | tun_sys::IFF_NO_PI;
            tun_sys::tunsetiff(dev_tap_fd, &ifr)?;
            if_name_chars = Vec::from(ifr.ifrn.name);
            if_name_chars.truncate(libc::strlen(if_name_chars.as_ptr()) + 1);
        }

        let ctl_sock_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };

        if ctl_sock_fd == -1 {
            bail!(io::Error::last_os_error());
        }

        let tap = Self {
            file: dev_tap,
            if_name_chars,
            ctl_sock_fd,
            buffer: Vec::new(),
        };

        unsafe {
            let mut mtu_ifr = tap.new_ifreq()?;

            mtu_ifr.ifru.mtu = Self::FRAME_SIZE as i32 - 6 - 6 - 2;
            tun_sys::siocsifmtu(ctl_sock_fd, &mut mtu_ifr)?;
        }

        Ok(tap)
    }

    unsafe fn new_ifreq(&self) -> AHResult<tun_sys::IfReq> {
        let mut ifr: tun_sys::IfReq = mem::zeroed();

        ifr.ifrn.name[..self.if_name_chars.len()].copy_from_slice(&self.if_name_chars);

        Ok(ifr)
    }

    pub fn up(&mut self) -> AHResult<()> {
        unsafe {
            let mut flags_ifr = self.new_ifreq()?;

            tun_sys::siocgifflags(self.ctl_sock_fd, &mut flags_ifr)?;
            flags_ifr.ifru.flags |= tun_sys::IFF_UP;
            tun_sys::siocsifflags(self.ctl_sock_fd, &flags_ifr)?;
        }

        Ok(())
    }

    pub fn if_name(&self) -> AHResult<String> {
        let if_name_bytes: Vec<u8> = self.if_name_chars.iter().map(|x| *x as u8).collect();
        Ok(CStr::from_bytes_with_nul(&if_name_bytes)?
            .to_str()?
            .to_string())
    }

    pub fn if_hwaddr(&self) -> AHResult<[u8; 6]> {
        unsafe {
            let mut flags_ifr = self.new_ifreq()?;

            tun_sys::siocgifhwaddr(self.ctl_sock_fd, &mut flags_ifr)?;

            if flags_ifr.ifru.addr.sa_family != tun_sys::ARPHRD_ETHER {
                bail!(
                    "unknown hardware address type {}",
                    flags_ifr.ifru.addr.sa_family
                );
            }

            Ok({
                let d = flags_ifr.ifru.addr.sa_data;

                [
                    d[0] as u8, d[1] as u8, d[2] as u8, d[3] as u8, d[4] as u8, d[5] as u8,
                ]
            })
        }
    }

    pub fn read(&mut self, buf: &mut [u8]) -> AHResult<usize> {
        Ok(self.file.read(buf)?)
    }

    pub fn write(&mut self, buf: &[u8]) -> AHResult<()> {
        Ok(self.file.write_all(buf)?)
    }

    pub fn rawfd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}
