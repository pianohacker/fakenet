use anyhow::{anyhow, bail};
use nom::{
    bytes,
    combinator::{eof, map_res, opt},
    multi::{many_m_n, separated_list1},
    number::complete::be_u16,
    sequence::{terminated, tuple},
};
use std::convert::TryInto;
use std::str::FromStr;

use crate::protocols::encdec::{BIResult, EncodeTo, SIResult};
use crate::protocols::ether;

use crate::try_parse;

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Hash)]
pub struct Address(pub [u16; 8]);

fn is_hex_digit(c: char) -> bool {
    c.is_digit(16)
}

fn address_part<'a>(input: &'a str) -> SIResult<'a, u16> {
    map_res(bytes::complete::take_while_m_n(1, 4, is_hex_digit), |s| {
        u16::from_str_radix(s, 16)
    })(input)
}

// Ref: RFC 2373
impl FromStr for Address {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (maybe_head, placeholder, maybe_tail) = try_parse!(
            {
                terminated(
                    tuple((
                        opt(separated_list1(bytes::complete::tag(":"), address_part)),
                        opt(bytes::complete::tag("::")),
                        opt(separated_list1(bytes::complete::tag(":"), address_part)),
                    )),
                    eof,
                )(&s)
            },
            "parsing ipv6 address failed: {}"
        )?;

        let head = maybe_head.unwrap_or(vec![]);
        let tail = maybe_tail.unwrap_or(vec![]);

        if head.len() + tail.len() > 8 {
            bail!("ipv6 address cannot have more than 8 parts");
        }

        let mut result = Vec::new();
        result.extend(&head);
        if placeholder.is_some() {
            // e.g., ff4d:02::1: 8 - 1 = 7.
            result.resize(8 - tail.len(), 0u16);
        } else if head.len() + tail.len() < 8 {
            bail!("ipv6 address must have 8 parts or a double colon");
        }
        result.extend(tail);

        Ok(Self(result.try_into().unwrap()))
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let mut longest_zeroes_start = 8;
        let mut longest_zeroes_len = 0;
        let mut i = 0;

        while i < 8 {
            let start = i;
            let mut len = 0;

            while i < 8 && self.0[i] == 0 {
                len += 1;
                i += 1;
            }

            if len > longest_zeroes_len {
                longest_zeroes_start = start;
                longest_zeroes_len = len;
            }

            if start == i {
                i += 1;
            }
        }

        let mut i = 0;
        while i < 8 {
            if i == longest_zeroes_start {
                write!(f, ":")?;

                while i < longest_zeroes_start + longest_zeroes_len {
                    if i == 0 || i == 7 {
                        write!(f, ":")?;
                    }

                    i += 1;
                }
            } else {
                write!(f, "{:x}", self.0[i])?;

                if i != 7 {
                    write!(f, ":")?;
                }

                i += 1;
            }
        }

        Ok(())
    }
}

impl EncodeTo for Address {
    fn encoded_len(&self) -> usize {
        16
    }

    fn encode_to(&self, buf: &mut [u8]) {
        for (i, part) in self.0.iter().enumerate() {
            part.encode_to(&mut buf[i * 2..]);
        }
    }
}

impl std::convert::From<Address> for u128 {
    fn from(addr: Address) -> u128 {
        let mut result: u128 = 0;

        for part in addr.0.iter() {
            result = (result << 16) | (*part as u128);
        }

        result
    }
}

impl std::convert::From<u128> for Address {
    fn from(addr: u128) -> Address {
        let mut addr = addr;
        let mut result: Address = Address::default();

        for i in (0..8).rev() {
            result.0[i] = (addr & 0xffff) as u16;
            addr >>= 16;
        }

        result
    }
}

impl Address {
    pub fn combine_subnet(&self, subnet: &Address) -> Address {
        let subnet_bits: u128 = (*subnet).into();
        let interface_bits: u128 = (*self).into();

        assert!(
            (128 - subnet_bits.trailing_zeros()) <= interface_bits.leading_zeros(),
            "subnet and interface ID overlap",
        );

        (subnet_bits | interface_bits).into()
    }

    pub fn prefix(&self, len: usize) -> Self {
        if len == 0 {
            return 0u128.into();
        }
        let mask: u128 = (!0u128) << (128 - len);

        (u128::from(*self) & mask).into()
    }

    pub fn suffix(&self, len: usize) -> Self {
        if len == 0 {
            return 0u128.into();
        }
        let mask: u128 = (!0u128) >> (128 - len);

        (u128::from(*self) & mask).into()
    }

    pub fn random(rng: &mut impl rand::Rng) -> Self {
        let full: u128 = rng.gen();

        Address::from(full)
    }

    pub fn solicited_nodes_multicast(&self) -> Self {
        self.suffix(24)
            .combine_subnet(&("ff02::1:ff00:0".parse().unwrap()))
    }

    pub fn multicast_ether_dest(&self) -> ether::Address {
        let lowest = u128::from(*self) & 0xffffffff;

        ether::Address([
            0x33,
            0x33,
            ((lowest >> 24) & 0xff) as u8,
            ((lowest >> 16) & 0xff) as u8,
            ((lowest >> 8) & 0xff) as u8,
            ((lowest) & 0xff) as u8,
        ])
    }
}

pub fn address<'a>(input: &'a [u8]) -> BIResult<'a, Address> {
    many_m_n(8, 8, be_u16)(input).map(|(i, x)| (i, Address(x.try_into().unwrap())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::From;
    use std::fmt::Write;

    fn ipv6a(s: &str) -> Address {
        s.parse().unwrap()
    }

    #[test]
    fn full_address_parses() {
        assert_eq!(
            ipv6a("fedc:ba98:7654:3210:fedc:ba98:7654:3210"),
            Address([0xFEDC, 0xBA98, 0x7654, 0x3210, 0xFEDC, 0xBA98, 0x7654, 0x3210])
        );
        assert_eq!(
            ipv6a("1080:0:0:0:8:800:200c:417a"),
            Address([0x1080, 0, 0, 0, 0x8, 0x800, 0x200C, 0x417A])
        );
    }

    #[test]
    fn partial_address_parses() {
        assert_eq!(
            ipv6a("1080::8:800:200c:417a"),
            Address([0x1080, 0, 0, 0, 0x8, 0x800, 0x200C, 0x417A])
        );
        assert_eq!(
            ipv6a("ff01::101"),
            Address([0xFF01, 0, 0, 0, 0, 0, 0, 0x101])
        );
        assert_eq!(ipv6a("::1"), Address([0, 0, 0, 0, 0, 0, 0, 1]));
        assert_eq!(ipv6a("::"), Address([0, 0, 0, 0, 0, 0, 0, 0]));
    }

    #[test]
    #[should_panic]
    fn double_placeholder_address_does_not_parse() {
        ipv6a("1080::8::417a");
    }

    #[test]
    #[should_panic(expected = "8 parts")]
    fn too_short_address_does_not_parse() {
        ipv6a("1080:8:417a");
    }

    #[test]
    fn into_u128_preserves_order() {
        assert_eq!(
            u128::from(ipv6a("1080::8:800:200c:417a")),
            0x108000000000000000080800200C417Au128
        );
        assert_eq!(
            u128::from(ipv6a("ff01::101")),
            0xFF010000000000000000000000000101u128
        );
        assert_eq!(
            u128::from(ipv6a("::1")),
            00000000000000000000000000000001u128,
        );
        assert_eq!(
            u128::from(ipv6a("::")),
            00000000000000000000000000000000u128,
        );
        assert_eq!(
            u128::from(ipv6a("fedc:ba98:7654:3210:fedc:ba98:7654:3210")),
            0xFEDCBA9876543210FEDCBA9876543210u128
        );
    }

    #[test]
    fn from_u128_preserves_order() {
        assert_eq!(
            Address::from(0x108000000000000000080800200C417Au128),
            ipv6a("1080::8:800:200c:417a")
        );
        assert_eq!(
            Address::from(0xFF010000000000000000000000000101u128),
            ipv6a("ff01::101")
        );
        assert_eq!(
            Address::from(0x00000000000000000000000000000001u128),
            ipv6a("::1"),
        );
        assert_eq!(
            Address::from(0x00000000000000000000000000000000u128),
            ipv6a("::"),
        );
        assert_eq!(
            Address::from(0xFEDCBA9876543210FEDCBA9876543210u128),
            ipv6a("fedc:ba98:7654:3210:fedc:ba98:7654:3210")
        );
    }

    #[test]
    fn combine_subnet_interface_works_on_trivial_input() {
        assert_eq!(
            ipv6a("::1").combine_subnet(&ipv6a("f840::")),
            ipv6a("f840::1"),
        );
        assert_eq!(
            ipv6a("::54:3210:fedc:ba98:7654:3210").combine_subnet(&ipv6a("fedc:ba98:7600::")),
            ipv6a("fedc:ba98:7654:3210:fedc:ba98:7654:3210"),
        );
    }

    #[test]
    #[should_panic]
    fn combine_subnet_interface_panics_on_overlapping_subnet_and_interface() {
        ipv6a("::bbbb:aaaa:9999:8888:7777").combine_subnet(&ipv6a("ffff:eeee:dddd:cccc:bbbb::"));
    }

    #[test]
    fn suffix_gets_exactly_the_desired_bits() {
        assert_eq!(
            ipv6a("fedc:ba98:7654:3210:fedc:ba98:7654:3210").suffix(128),
            ipv6a("fedc:ba98:7654:3210:fedc:ba98:7654:3210")
        );
        assert_eq!(
            ipv6a("fedc:ba98:7654:3210:fedc:ba98:7654:3210").suffix(88),
            ipv6a("::54:3210:fedc:ba98:7654:3210")
        );
        assert_eq!(
            ipv6a("fedc:ba98:7654:3210:fedc:ba98:7654:3210").suffix(30),
            ipv6a("::3654:3210"),
        );
        assert_eq!(
            ipv6a("fedc:ba98:7654:3210:fedc:ba98:7654:3210").suffix(0),
            ipv6a("::")
        );
    }

    #[test]
    fn prefix_gets_exactly_the_desired_bits() {
        assert_eq!(
            ipv6a("fedc:ba98:7654:3210:fedc:ba98:7654:3210").prefix(128),
            ipv6a("fedc:ba98:7654:3210:fedc:ba98:7654:3210")
        );
        assert_eq!(
            ipv6a("fedc:ba98:7654:3210:fedc:ba98:7654:3210").prefix(88),
            ipv6a("fedc:ba98:7654:3210:fedc:ba00::")
        );
        assert_eq!(
            ipv6a("fedc:ba98:7654:3210:fedc:ba98:7654:3210").prefix(30),
            ipv6a("fedc:ba98::")
        );
        assert_eq!(
            ipv6a("fedc:ba98:7654:3210:fedc:ba98:7654:3210").prefix(0),
            ipv6a("::")
        );
    }

    #[test]
    fn solicited_nodes_multicast_preserves_lowest_bits() {
        assert_eq!(
            ipv6a("1080::8:800:200c:417a").solicited_nodes_multicast(),
            ipv6a("ff02::1:ff0c:417a"),
        );
        assert_eq!(
            ipv6a("2601::101").solicited_nodes_multicast(),
            ipv6a("ff02::1:ff00:101"),
        );
        assert_eq!(
            ipv6a("fedc:ba98:7654:3210:fedc:ba98:7654:3210").solicited_nodes_multicast(),
            ipv6a("ff02::1:ff54:3210"),
        );
    }

    #[test]
    fn multicast_ether_dest_preserves_lowest_bits() {
        assert_eq!(
            ipv6a("ff02::1:ff0c:417a").multicast_ether_dest(),
            "33:33:ff:0c:41:7a".parse().unwrap(),
        );
        assert_eq!(
            ipv6a("ff01::1").multicast_ether_dest(),
            "33:33:00:00:00:01".parse().unwrap(),
        );
        assert_eq!(
            ipv6a("ff02::db8:f339:f002").multicast_ether_dest(),
            "33:33:f3:39:f0:02".parse().unwrap(),
        );
    }

    #[test]
    fn display_shows_full_addresses() {
        let mut buffer = String::new();
        write!(
            &mut buffer,
            "{}",
            ipv6a("fedc:ba98:7654:3210:fedc:ba98:7654:3210")
        )
        .unwrap();
        assert_eq!(buffer, "fedc:ba98:7654:3210:fedc:ba98:7654:3210");
    }

    #[test]
    fn display_abbreviates_runs_of_zeroes() {
        let mut buffer = String::new();
        write!(&mut buffer, "{}", ipv6a("::1")).unwrap();
        assert_eq!(buffer, "::1");
    }

    #[test]
    fn display_abbreviates_longest_run_of_zeroes() {
        {
            let mut buffer = String::new();
            write!(&mut buffer, "{}", ipv6a("fedc::fedc:0:0:3210")).unwrap();
            assert_eq!(buffer, "fedc::fedc:0:0:3210");
        }

        {
            let mut buffer = String::new();
            write!(&mut buffer, "{}", ipv6a("fedc:0:0:3210::3210")).unwrap();
            assert_eq!(buffer, "fedc:0:0:3210::3210");
        }
    }
}
