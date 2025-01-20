use etherparse::PacketBuilder;
use std::net::*;
use xdp::packet::{net_types::*, *};

const SRC_MAC: MacAddress = MacAddress([0xb4, 0x2e, 0x99, 0x6f, 0xfa, 0x6b]);
const DST_MAC: MacAddress = MacAddress([0xc4, 0xea, 0x1d, 0xe3, 0x82, 0x4c]);

const IPV4_DATA: &[u8] = b"I'm an IPv4 packet payload";
const IPV6_DATA: &[u8] = b"I'm an IPv6 packet payload";

/// Ensures we can parse an IPv4 UDP packet
#[test]
fn parses_ipv4() {
    let mut buf = [0u8; 2048];
    let mut packet = Packet::testing_new(&mut buf);

    PacketBuilder::ethernet2(SRC_MAC.0, DST_MAC.0)
        .ipv4([192, 168, 1, 139], [192, 168, 1, 1], 64)
        .udp(9000, 10001)
        .write(&mut packet, IPV4_DATA)
        .unwrap();

    let udp = net_types::UdpPacket::parse_packet(&packet)
        .unwrap()
        .unwrap();
    assert_eq!(
        udp.source,
        FullAddress {
            mac: SRC_MAC,
            port: 9000.into(),
        }
    );
    assert_eq!(
        udp.destination,
        FullAddress {
            mac: DST_MAC,
            port: 10001.into(),
        }
    );
    assert_eq!(
        udp.ips,
        IpAddresses::V4 {
            source: Ipv4Addr::new(192, 168, 1, 139),
            destination: Ipv4Addr::new(192, 168, 1, 1),
        }
    );
    assert_eq!(
        packet
            .slice_at_offset(udp.data_offset, udp.data_length)
            .unwrap(),
        IPV4_DATA
    );
}

/// Ensures we can parse an IPv6 UDP packet
#[test]
fn parses_ipv6() {
    let mut buf = [0u8; 2048];
    let mut packet = Packet::testing_new(&mut buf);

    const SRC: std::net::Ipv6Addr =
        std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0x99f0, 0xdcf, 0x4be3, 0xd25a);
    const DST: std::net::Ipv6Addr = std::net::Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);

    PacketBuilder::ethernet2(SRC_MAC.0, DST_MAC.0)
        .ipv6(SRC.octets(), DST.octets(), 64)
        .udp(5353, 1111)
        .write(&mut packet, IPV6_DATA)
        .unwrap();

    let udp = net_types::UdpPacket::parse_packet(&packet)
        .unwrap()
        .unwrap();
    assert_eq!(
        udp.source,
        FullAddress {
            mac: SRC_MAC,
            port: 5353.into(),
        }
    );
    assert_eq!(
        udp.destination,
        FullAddress {
            mac: DST_MAC,
            port: 1111.into(),
        }
    );
    assert_eq!(
        udp.ips,
        IpAddresses::V6 {
            source: SRC,
            destination: DST,
        }
    );
    assert_eq!(
        packet
            .slice_at_offset(udp.data_offset, udp.data_length)
            .unwrap(),
        IPV6_DATA
    );
}

/// Ensures we generate the correct IPv4 header checksum
#[test]
fn checksums_ipv4_header() {
    let mut buf = [0u8; 2048];
    let mut packet = Packet::testing_new(&mut buf);

    PacketBuilder::ethernet2(SRC_MAC.0, DST_MAC.0)
        .ipv4([192, 168, 1, 139], [192, 168, 1, 1], 64)
        .udp(9000, 10001)
        .write(&mut packet, IPV4_DATA)
        .unwrap();

    let ip_hdr = packet.item_at_offset_mut::<Ipv4Hdr>(EthHdr::LEN).unwrap();
    let valid_checksum = ip_hdr.check;
    ip_hdr.check = 0;
    ip_hdr.calc_checksum();
    assert_eq!(valid_checksum, ip_hdr.check);
}

/// Ensures we generate the correct IPv4 UDP checksum
#[test]
fn checksums_ipv4_udp() {
    let mut buf = [0u8; 2048];
    let mut packet = Packet::testing_new(&mut buf);

    PacketBuilder::ethernet2(SRC_MAC.0, DST_MAC.0)
        .ipv4([192, 168, 1, 139], [192, 168, 1, 1], 64)
        .udp(9000, 10001)
        .write(&mut packet, IPV4_DATA)
        .unwrap();

    let udp = net_types::UdpPacket::parse_packet(&packet)
        .unwrap()
        .unwrap();
    assert_eq!(csum::recalc_udp(&mut packet).unwrap(), udp.checksum.0);
}

/// Ensures we generate the correct IPv6 UDP checksum
#[test]
fn checksums_ipv6_udp() {
    let mut buf = [0u8; 2048];
    let mut packet = Packet::testing_new(&mut buf);

    const SRC: std::net::Ipv6Addr =
        std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0x99f0, 0xdcf, 0x4be3, 0xd25a);
    const DST: std::net::Ipv6Addr = std::net::Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);

    PacketBuilder::ethernet2(SRC_MAC.0, DST_MAC.0)
        .ipv6(SRC.octets(), DST.octets(), 64)
        .udp(5353, 1111)
        .write(&mut packet, IPV6_DATA)
        .unwrap();

    let udp = net_types::UdpPacket::parse_packet(&packet)
        .unwrap()
        .unwrap();
    assert_eq!(csum::recalc_udp(&mut packet).unwrap(), udp.checksum.0);
}

#[test]
fn checksum_sizes() {
    const LEN: usize = 2048;
    let mut v = [0u8; LEN];

    let mut mismatches = 0;
    for i in 1..LEN {
        v[i] = (i & 0xff) as u8;

        let block = &v[..i];

        let external = internet_checksum::checksum(block);
        let ours = csum::fold_checksum(csum::partial(block, 0));

        if external != ours.to_ne_bytes() {
            eprintln!(
                "{i} expected: {:04x}, actual: {ours:04x}",
                u16::from_ne_bytes(external)
            );
            mismatches += 1;
        }
    }

    assert_eq!(mismatches, 0);
}
