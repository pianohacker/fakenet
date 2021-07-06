use anyhow::{anyhow, bail, Result as AHResult};
use byteorder::{ByteOrder, NetworkEndian};
use nom::{
    branch::alt,
    bytes::complete::{tag, take},
    character::complete::{digit0, one_of},
    combinator::{eof, map_res, recognize, verify},
    multi::separated_list1,
    number::complete::{be_u16, be_u8},
    sequence::{pair, terminated},
    IResult,
};
use std::convert::{TryFrom, TryInto};
use std::fmt::{Display, Formatter, Write};
use std::str::FromStr;

type BIResult<'a, O> = IResult<&'a [u8], O>;
type SIResult<'a, O> = IResult<&'a str, O>;

macro_rules! proto_enum_inner {
    ($name:ident, $type:ty, { $variant_name:ident = $variant_disc:expr, $( $variants:tt )* } ( $($enum_accum:tt)* ) ( $($try_from_accum:tt)* )) => {
        proto_enum_inner!($name, $type, { $($variants)* } ( $variant_name = $variant_disc, $($enum_accum)? ) ( $variant_disc => Ok($name::$variant_name), $($try_from_accum)? ) );
    };

    ($name:ident, $type:ty, {} ( $($enum_accum:tt)+ ) ( $($try_from_accum:tt)+ )) => {
        #[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
        pub enum $name { $($enum_accum)+ }

        impl std::convert::TryFrom<$type> for $name {
            type Error = anyhow::Error;

            fn try_from(value: $type) -> Result<Self, Self::Error> {
                match value {
                    $($try_from_accum)+
                    _ => { bail!("unknown {}: {}", stringify!($ident), value) }
                }
            }
        }
    };
}

macro_rules! proto_enum {
    ($name:ident, $type:ty, { $($variants:tt)+ } $(,)?) => {
        proto_enum_inner!($name, $type, { $($variants)+ } () ());
    };
}

fn hexdump(data: &[u8]) -> Result<String, std::fmt::Error> {
    let mut result = String::new();

    let offsetlen = (data.len() as f64).log(16.).ceil() as usize;

    for (chunk_num, chunk) in data.chunks(16).enumerate() {
        {
            let mut i = 0;

            write!(&mut result, "{:1$x}: ", chunk_num * 16, offsetlen)?;

            while i < 16 && i < chunk.len() {
                write!(&mut result, "{:02x} ", chunk[i])?;

                i = i + 1;
            }

            write!(&mut result, "{}", "   ".repeat(16 - i))?;
        }

        {
            let mut i = 0;

            while i < 16 && i < chunk.len() {
                if (chunk[i] as char).is_ascii_graphic() || (chunk[i] as char) == ' ' {
                    write!(&mut result, "{}", chunk[i] as char)?;
                } else {
                    write!(&mut result, ".")?;
                }

                i = i + 1;
            }
        }

        write!(&mut result, "\n")?;
    }

    Ok(result)
}

trait EncodeTo {
    fn encoded_len(&self) -> usize;
    fn encode_to(&self, buf: &mut [u8]);
}

impl EncodeTo for u8 {
    fn encoded_len(&self) -> usize {
        1
    }

    fn encode_to(&self, buf: &mut [u8]) {
        buf[0] = *self;
    }
}

impl EncodeTo for u16 {
    fn encoded_len(&self) -> usize {
        2
    }

    fn encode_to(&self, buf: &mut [u8]) {
        NetworkEndian::write_u16(buf, *self);
    }
}

macro_rules! encode {
    ( $($val:expr $(,)?)+ ) => {
        {
            let mut result = Vec::new();
            result.resize(
                $($val.encoded_len() + )+ 0,
                0u8,
            );

            let mut buf = &mut result[..];
            $(
                $val.encode_to(&mut buf);
                buf = &mut buf[$val.encoded_len()..];
            )+
            let _ = buf;

            result
        }
    }
}

macro_rules! try_parse {
    ($block:tt, $error_template:expr) => {
        {
            let result = || -> nom::IResult<_, _> $block ();

            match result {
                Ok((_, output)) => Ok(output),
                Err(e) => Err(anyhow!($error_template, e.to_string())),
            }
        }
    };
}

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

fn ether_address<'a>(input: &'a [u8]) -> BIResult<'a, EtherAddress> {
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

impl Display for EtherType {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{:04x}", *self as u16)
    }
}

#[derive(Debug)]
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

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct Ipv4Address([u8; 4]);

impl Display for Ipv4Address {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        for (i, part) in self.0.iter().enumerate() {
            write!(f, "{:02x}", part)?;
            if i != 3 {
                write!(f, ":")?;
            }
        }

        Ok(())
    }
}

fn ipv4_address_part<'a>(input: &'a str) -> SIResult<'a, u8> {
    map_res(
        alt((tag("0"), recognize(pair(one_of("123456789"), digit0)))),
        u8::from_str,
    )(input)
}

impl FromStr for Ipv4Address {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts = try_parse!(
            { terminated(separated_list1(tag("."), ipv4_address_part), eof)(&s) },
            "parsing ipv4 address failed: {}"
        )?;

        if parts.len() != 4 {
            bail!("ipv4 address must have 4 parts");
        }

        Ok(Self(parts.try_into().unwrap()))
    }
}

impl EncodeTo for Ipv4Address {
    fn encoded_len(&self) -> usize {
        4
    }

    fn encode_to(&self, buf: &mut [u8]) {
        buf[..4].copy_from_slice(&self.0);
    }
}

fn ipv4_address<'a>(input: &'a [u8]) -> BIResult<'a, Ipv4Address> {
    take(4 as usize)(input).map(|(i, x)| (i, Ipv4Address(x.try_into().unwrap())))
}

proto_enum!(ArpPacketOpcode, u16, {
    Request = 1,
    Reply = 2,
});

#[derive(Debug)]
pub struct ArpPacket {
    pub opcode: ArpPacketOpcode,
    pub src_ether: EtherAddress,
    pub src_ipv4: Ipv4Address,
    pub dest_ether: EtherAddress,
    pub dest_ipv4: Ipv4Address,
}

impl ArpPacket {
    pub fn encode(&self) -> Vec<u8> {
        encode!(
            1u16,
            EtherType::Ipv4 as u16,
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
            let (input, _) = verify(be_u16, |pro| *pro == EtherType::Ipv4 as u16)(input)?;
            let (input, _) = verify(be_u8, |hln| *hln == 6)(input)?;
            let (input, _) = verify(be_u8, |pln| *pln == 4)(input)?;
            let (input, opcode) = map_res(be_u16, ArpPacketOpcode::try_from)(input)?;
            let (input, src_ether) = ether_address(input)?;
            let (input, src_ipv4) = ipv4_address(input)?;
            let (input, dest_ether) = ether_address(input)?;
            let (input, dest_ipv4) = ipv4_address(input)?;

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
