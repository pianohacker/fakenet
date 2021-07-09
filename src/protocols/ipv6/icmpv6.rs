use anyhow::{anyhow, Result as AHResult};
use nom::{
    combinator::{consumed, eof, map_res},
    multi::many0,
    number::complete::be_u8,
    sequence::terminated,
};
use std::convert::TryFrom;

use crate::protocols::ether;
use crate::protocols::utils::BIResult;
use crate::{proto_enum_with_unknown, try_parse};

use super::{ipv6_address, Ipv6Address};

// Ref: https://datatracker.ietf.org/doc/html/rfc4443

proto_enum_with_unknown!(Icmpv6Type, u8, {
    DestinationUnreachable = 1,
    TooBig = 2,
    Exceeded = 3,
    Problem = 4,
    EchoRequest = 128,
    EchoReply = 129,
    RouterSolicitation = 133,
    NeighborSolicitation = 135,
    NeighborAdvertisement = 136,
    V2MulticastListenerReport = 143,
});

// Ref: https://datatracker.ietf.org/doc/html/rfc4861
proto_enum_with_unknown!(Icmpv6NeighborSolicitationOptionType, u8, {
    SourceLinkLayerAddress = 1,
    Nonce = 14,
});

#[derive(Debug, PartialEq)]
pub enum Icmpv6NeighborSolicitationOption {
    SourceLinkLayerAddress(ether::EtherAddress),
    Nonce,
}

#[derive(Debug, PartialEq)]
pub enum Icmpv6Packet {
    RouterSolicitation,
    NeighborSolicitation {
        dest: Ipv6Address,
        options: Vec<Icmpv6NeighborSolicitationOption>,
    },
    NeighborAdvertisement,
    V2MulticastListenerReport,
}

fn icmpv6_neighbor_solicitation_option<'a>(
    input: &'a [u8],
) -> BIResult<'a, Icmpv6NeighborSolicitationOption> {
    fn inner<'a>(input: &'a [u8]) -> BIResult<'a, Icmpv6NeighborSolicitationOption> {
        let (input, option_type) =
            map_res(be_u8, Icmpv6NeighborSolicitationOptionType::try_from)(input)?;
        let (input, length) = be_u8(input)?;

        match option_type {
            Icmpv6NeighborSolicitationOptionType::SourceLinkLayerAddress => {
                let (input, address) = ether::ether_address(input)?;

                Ok((
                    input,
                    Icmpv6NeighborSolicitationOption::SourceLinkLayerAddress(address),
                ))
            }
            Icmpv6NeighborSolicitationOptionType::Nonce => {
                let input = &input[(length as usize * 8) - 2..];

                Ok((input, Icmpv6NeighborSolicitationOption::Nonce))
            }
            Icmpv6NeighborSolicitationOptionType::Unknown(t) => {
                todo!("not yet implemented: {}", t)
            }
        }
    }

    let (input, (option_bytes, option)) = consumed(inner)(input)?;

    let input = if option_bytes.len() % 8 == 0 {
        input
    } else {
        let needed_padding = 8 - option_bytes.len() % 8;
        &input[needed_padding..]
    };

    Ok((input, option))
}

fn icmpv6_neighbor_solicitation_packet<'a>(input: &'a [u8]) -> BIResult<'a, Icmpv6Packet> {
    // Skip code, checksum, and reserved
    let input = &input[7..];
    let (input, source) = ipv6_address(input)?;

    let (input, options) = terminated(many0(icmpv6_neighbor_solicitation_option), eof)(input)?;

    let (input, _) = eof(input)?;

    Ok((
        input,
        Icmpv6Packet::NeighborSolicitation {
            dest: source,
            options,
        },
    ))
}

pub fn icmpv6_packet(input: &[u8]) -> AHResult<Icmpv6Packet> {
    try_parse!(
        {
            let (input, packet_type) = map_res(be_u8, Icmpv6Type::try_from)(input)?;

            use Icmpv6Type::*;
            let (input, packet) = match packet_type {
                RouterSolicitation => (input, Icmpv6Packet::RouterSolicitation),
                NeighborSolicitation => icmpv6_neighbor_solicitation_packet(input)?,
                NeighborAdvertisement => (input, Icmpv6Packet::NeighborAdvertisement),
                V2MulticastListenerReport => (input, Icmpv6Packet::V2MulticastListenerReport),
                _ => {
                    todo!("not yet implemented: {:?}", packet_type)
                }
            };

            Ok((input, packet))
        },
        "parsing icmpv6 packet failed: {}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hexstring(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    #[test]
    fn router_solicitation_packet_decodes() {
        assert_eq!(
            icmpv6_packet(&hexstring("85006aea000000000101560d4f2164f3")).unwrap(),
            Icmpv6Packet::RouterSolicitation
        );
    }

    #[test]
    fn solicitation_packet_decodes() {
        assert_eq!(
            icmpv6_packet(&hexstring(
                "87003fc50000000000f400440000000000000000000000120101560d4f2164f3"
            ))
            .unwrap(),
            Icmpv6Packet::NeighborSolicitation {
                dest: "f4:44::12".parse().unwrap(),
                options: vec![Icmpv6NeighborSolicitationOption::SourceLinkLayerAddress(
                    ether::EtherAddress([0x56, 0x0d, 0x4f, 0x21, 0x64, 0xf3]),
                ),],
            },
        );
    }

    #[test]
    fn solicitation_packet_with_nonce_decodes() {
        assert_eq!(
            icmpv6_packet(&hexstring(
                "8700f15d00000000fe80000000000000396df66497e164f30e01d8d14717f0a0"
            ))
            .unwrap(),
            Icmpv6Packet::NeighborSolicitation {
                dest: "fe80::396d:f664:97e1:64f3".parse().unwrap(),
                options: vec![Icmpv6NeighborSolicitationOption::Nonce,],
            },
        );
    }

    #[test]
    fn advertisement_packet_decodes() {
        assert_eq!(
            icmpv6_packet(&hexstring(
                "880079e9e0000000fd00736f746f686e000000000000000102011691822a803b"
            ))
            .unwrap(),
            Icmpv6Packet::NeighborAdvertisement
        );
    }

    #[test]
    fn multicast_listener_packet_decodes() {
        assert_eq!(
            icmpv6_packet(&hexstring(
                "8f008dca0000000104000000ff0200000000000000000001fff9e0c6"
            ))
            .unwrap(),
            Icmpv6Packet::V2MulticastListenerReport
        );
    }
}
