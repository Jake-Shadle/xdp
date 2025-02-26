#![cfg(not(miri))] // Unfortunately we can't use inline assembly

use etherparse::PacketBuilder;
use std::net::*;
use tests::*;
use xdp::packet::{net_types::*, *};

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

    let mut ip_hdr = packet.get::<Ipv4Hdr>(EthHdr::LEN).unwrap();
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

    let udp = UdpPacket::parse_packet(&packet).unwrap().unwrap();
    assert_eq!(packet.calc_udp_checksum().unwrap(), udp.udp.check);
}

/// Ensures we generate the correct IPv6 UDP checksum
#[test]
fn checksums_ipv6_udp() {
    let mut buf = [0u8; 2048];
    let mut packet = Packet::testing_new(&mut buf);

    const SRC: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0x99f0, 0xdcf, 0x4be3, 0xd25a);
    const DST: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);

    PacketBuilder::ethernet2(SRC_MAC.0, DST_MAC.0)
        .ipv6(SRC.octets(), DST.octets(), 64)
        .udp(5353, 1111)
        .write(&mut packet, IPV6_DATA)
        .unwrap();

    let udp = UdpPacket::parse_packet(&packet).unwrap().unwrap();
    assert_eq!(packet.calc_udp_checksum().unwrap(), udp.udp.check);
}

/// Ensures we can calculate the payload checksum separately and still get
/// the same final result
#[test]
fn combines_partial_checksums() {
    let mut buf = [0u8; 2048];
    let mut packet = Packet::testing_new(&mut buf);

    {
        const SRC: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
        const DST: Ipv4Addr = Ipv4Addr::new(100, 1, 100, 1);

        PacketBuilder::ethernet2(SRC_MAC.0, DST_MAC.0)
            .ipv4(SRC.octets(), DST.octets(), 64)
            .udp(5353, 1111)
            .write(&mut packet, LARGER)
            .unwrap();

        let mut udp = UdpPacket::parse_packet(&packet).unwrap().unwrap();
        let expected = udp.udp.check;
        assert_eq!(packet.calc_udp_checksum().unwrap(), expected);

        let data_checksum = csum::partial(LARGER, 0);
        udp.calc_checksum(LARGER.len(), data_checksum);
        assert_eq!(udp.udp.check, expected);
    }

    packet.clear();

    {
        const SRC: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0x99f0, 0xdcf, 0x4be3, 0xd25a);
        const DST: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);

        PacketBuilder::ethernet2(SRC_MAC.0, DST_MAC.0)
            .ipv6(SRC.octets(), DST.octets(), 64)
            .udp(5353, 1111)
            .write(&mut packet, LARGER)
            .unwrap();

        let mut udp = UdpPacket::parse_packet(&packet).unwrap().unwrap();
        let expected = udp.udp.check;
        assert_eq!(packet.calc_udp_checksum().unwrap(), expected);

        let data_checksum = csum::partial(LARGER, 0);
        udp.calc_checksum(LARGER.len(), data_checksum);
        assert_eq!(udp.udp.check, expected);
    }
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
