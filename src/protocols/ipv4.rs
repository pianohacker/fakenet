use anyhow::{anyhow, bail};
use nom::{
    branch::alt,
    bytes::complete::{tag, take},
    character::complete::{digit0, one_of},
    combinator::{eof, map_res, recognize},
    multi::separated_list1,
    sequence::{pair, terminated},
};
use std::convert::TryInto;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

use super::encdec::{BIResult, EncodeTo, SIResult};
use crate::{proto_enum_with_unknown, try_parse};

// Ref: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
proto_enum_with_unknown!(ProtocolNumber, u8, {
    Udp = 17,
    Ipv6Icmp = 58,
});

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct Address(pub [u8; 4]);

impl Display for Address {
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

fn address_part<'a>(input: &'a str) -> SIResult<'a, u8> {
    map_res(
        alt((tag("0"), recognize(pair(one_of("123456789"), digit0)))),
        u8::from_str,
    )(input)
}

impl FromStr for Address {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts = try_parse!(
            { terminated(separated_list1(tag("."), address_part), eof)(&s) },
            "parsing ipv4 address failed: {}"
        )?;

        if parts.len() != 4 {
            bail!("ipv4 address must have 4 parts");
        }

        Ok(Self(parts.try_into().unwrap()))
    }
}

impl EncodeTo for Address {
    fn encoded_len(&self) -> usize {
        4
    }

    fn encode_to(&self, buf: &mut [u8]) {
        buf[..4].copy_from_slice(&self.0);
    }
}

pub fn address<'a>(input: &'a [u8]) -> BIResult<'a, Address> {
    take(4 as usize)(input).map(|(i, x)| (i, Address(x.try_into().unwrap())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonzero_address_decodes() {
        assert_eq!("1.2.3.4".parse::<Address>().unwrap(), Address([1, 2, 3, 4]));
    }

    #[test]
    fn address_with_zeroes_decodes() {
        assert_eq!(
            "10.0.3.0".parse::<Address>().unwrap(),
            Address([10, 0, 3, 0])
        );
    }
}
