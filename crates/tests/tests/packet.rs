use etherparse::PacketBuilder;
use std::net::{Ipv4Addr, Ipv6Addr};
use tests::*;
use xdp::{
    Packet,
    packet::{
        Pod,
        net_types::{self as nt, IpAddresses, MacAddress, UdpHeaders},
    },
};

#[test]
fn simple() {
    let mut buf = [0u8; 2 * 1024];
    let tot_len = buf.len();
    let mut packet = Packet::testing_new(&mut buf);

    assert_eq!(0, packet.len());
    assert!(packet.is_empty());
    assert_eq!(
        packet.capacity(),
        tot_len - xdp::libc::xdp::XDP_PACKET_HEADROOM as usize,
    );
    assert!(packet.adjust_head(-20).is_err());
    assert!(packet.adjust_tail(20).is_ok());
    assert!(packet.adjust_tail(-20).is_ok());
    assert_eq!(0, packet.len());
    assert!(packet.is_empty());
    assert_eq!(
        packet.capacity(),
        tot_len - xdp::libc::xdp::XDP_PACKET_HEADROOM as usize,
    );

    packet.adjust_tail(21).unwrap();
    packet.adjust_head(21).unwrap();

    let val = b"deadbeef";

    packet.insert(0, val).unwrap();
    assert_eq!(packet.len(), val.len());
    let inside = &packet[..val.len()];
    assert_eq!(val, inside);

    let start = packet.len() as u32;
    for i in 0..20u32 {
        packet.insert((i * 5 + start) as _, &[1]).unwrap();

        packet
            .insert((i * 5 + start + 1) as _, &i.to_ne_bytes())
            .unwrap();
        let mut islice = [0u8; 4];
        packet
            .array_at_offset((i * 5 + start + 1) as _, &mut islice)
            .unwrap();
        assert_eq!(i, u32::from_ne_bytes(islice));
    }

    let new = 0xcafefeedu32;

    packet.insert(0, &new.to_ne_bytes()).unwrap();
    let mut uarr = [0u8; 4];
    packet.array_at_offset(0, &mut uarr).unwrap();
    assert_eq!(new, u32::from_ne_bytes(uarr));
    let inside = &packet[4..4 + val.len()];
    assert_eq!(val, inside);

    assert_eq!(20 * 5 + 4 + val.len(), packet.len());
    packet.adjust_head(4).unwrap();
    assert_eq!(20 * 5 + val.len(), packet.len());
    let inside = &packet[..val.len()];
    assert_eq!(val, inside);
    packet.adjust_head(-4).unwrap();
    packet.array_at_offset(0, &mut uarr).unwrap();
    assert_eq!(new, u32::from_ne_bytes(uarr));

    packet.adjust_tail(-(packet.len() as i32)).unwrap();
    assert!(packet.is_empty());

    packet
        .insert(0, &0xf3f3f3f3f3f3f3f3u64.to_ne_bytes())
        .unwrap();
    packet.append(&0x1212121212121212u64.to_ne_bytes()).unwrap();

    assert_eq!(packet.len(), 16);
    let mut arr6 = [0u8; 8];
    packet.array_at_offset(0, &mut arr6).unwrap();
    assert_eq!(0xf3f3f3f3f3f3f3f3, u64::from_ne_bytes(arr6));
    packet.array_at_offset(8, &mut arr6).unwrap();
    assert_eq!(0x1212121212121212, u64::from_ne_bytes(arr6));
}

#[test]
fn udp_recv() {
    let mut buf = [0u8; 2 * 1024];
    let mut packet = Packet::testing_new(&mut buf);
    let payload = [0xf2; 1001];

    PacketBuilder::ethernet2([1; 6], [2; 6])
        .ipv4(
            Ipv4Addr::new(10, 20, 30, 40).octets(),
            Ipv4Addr::new(1, 1, 1, 1).octets(),
            64,
        )
        .udp(8900, 9001)
        .write(&mut packet, &payload)
        .unwrap();

    assert_eq!(
        packet.len(),
        nt::EthHdr::LEN + nt::Ipv4Hdr::LEN + nt::UdpHdr::LEN + 1001
    );

    let udp = UdpHeaders::parse_packet(&packet).unwrap().unwrap();
    assert_eq!(udp.eth.source.0, [1; 6]);
    assert_eq!(udp.eth.destination.0, [2; 6]);
    assert_eq!(udp.eth.ether_type, nt::EtherType::Ipv4);
    assert_eq!(
        udp.ip,
        IpAddresses::V4 {
            source: Ipv4Addr::new(10, 20, 30, 40),
            destination: Ipv4Addr::new(1, 1, 1, 1)
        }
    );
    assert_eq!(udp.udp.source.host(), 8900);
    assert_eq!(udp.udp.destination.host(), 9001);
}

#[test]
#[cfg_attr(miri, ignore)]
fn udp_send() {
    let mut buf = [0u8; 2 * 1024];
    let mut packet = Packet::testing_new(&mut buf);
    let payload = [0xf2; 1001];

    packet
        .adjust_tail((nt::EthHdr::LEN + nt::Ipv6Hdr::LEN + nt::UdpHdr::LEN) as _)
        .unwrap();

    let mut ipv6 = nt::Ipv6Hdr::zeroed();
    ipv6.reset(64, nt::IpProto::Udp);
    ipv6.source = [10; 16];
    ipv6.destination = [1; 16];
    let data_offset = nt::EthHdr::LEN + nt::Ipv6Hdr::LEN + nt::UdpHdr::LEN;

    let mut udp = UdpHeaders::new(
        nt::EthHdr {
            source: MacAddress([1; 6]),
            destination: MacAddress([2; 6]),
            ether_type: nt::EtherType::Ipv6,
        },
        nt::IpHdr::V6(ipv6),
        nt::UdpHdr {
            source: 8900.into(),
            destination: 9001.into(),
            length: 0.into(),
            check: 0,
        },
        data_offset..data_offset + payload.len(),
    );

    udp.set_packet_headers(&mut packet).unwrap();
    packet.insert(udp.data.start, &payload).unwrap();

    let check = packet.calc_udp_checksum().unwrap();

    let packet_headers = etherparse::PacketHeaders::from_ethernet_slice(&packet).unwrap();
    assert_eq!(
        check,
        packet_headers
            .transport
            .as_ref()
            .unwrap()
            .clone()
            .udp()
            .as_ref()
            .unwrap()
            .calc_checksum_ipv6_raw(ipv6.source, ipv6.destination, &payload)
            .unwrap()
            .to_be()
    );
    assert_eq!(packet_headers.payload.slice(), &payload);

    {
        let eth = packet_headers.link.unwrap().ethernet2().unwrap();
        assert_eq!(eth.source, [1; 6]);
        assert_eq!(eth.destination, [2; 6]);
        assert_eq!(eth.ether_type, etherparse::ether_type::IPV6);
    }

    {
        let (ip, ext) = packet_headers.net.as_ref().unwrap().ipv6_ref().unwrap();
        assert!(ext.is_empty());
        assert_eq!(ip.source, [10; 16]);
        assert_eq!(ip.destination, [1; 16]);
        assert_eq!(ip.hop_limit, 64);
        assert_eq!(ip.payload_length, (nt::UdpHdr::LEN + payload.len()) as u16);
    }

    {
        let udp = packet_headers.transport.unwrap().udp().unwrap();
        assert_eq!(udp.checksum, check.to_be());
        assert_eq!(udp.source_port, 8900);
        assert_eq!(udp.destination_port, 9001);
        assert_eq!(udp.length, (nt::UdpHdr::LEN + payload.len()) as u16);
    }
}

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

    let udp = UdpHeaders::parse_packet(&packet).unwrap().unwrap();
    assert_eq!(udp.eth.source, SRC_MAC);
    assert_eq!(udp.udp.source, 9000.into());
    assert_eq!(udp.eth.destination, DST_MAC);
    assert_eq!(udp.udp.destination.host(), 10001);
    assert_eq!(
        udp.ip,
        IpAddresses::V4 {
            source: Ipv4Addr::new(192, 168, 1, 139),
            destination: Ipv4Addr::new(192, 168, 1, 1),
        }
    );
    assert_eq!(&packet[udp.data], IPV4_DATA);
}

/// Ensures we can parse an IPv6 UDP packet
#[test]
fn parses_ipv6() {
    let mut buf = [0u8; 2048];
    let mut packet = Packet::testing_new(&mut buf);

    const SRC: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0x99f0, 0xdcf, 0x4be3, 0xd25a);
    const DST: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);

    PacketBuilder::ethernet2(SRC_MAC.0, DST_MAC.0)
        .ipv6(SRC.octets(), DST.octets(), 64)
        .udp(5353, 1111)
        .write(&mut packet, IPV6_DATA)
        .unwrap();

    let udp = UdpHeaders::parse_packet(&packet).unwrap().unwrap();
    assert_eq!(udp.eth.source, SRC_MAC);
    assert_eq!(udp.udp.source, 5353.into());
    assert_eq!(udp.eth.destination, DST_MAC);
    assert_eq!(udp.udp.destination.host(), 1111);
    assert_eq!(
        udp.ip,
        IpAddresses::V6 {
            source: SRC,
            destination: DST,
        }
    );
    assert_eq!(&packet[udp.data], IPV6_DATA);
}

/// Ensures the UDP length field matches the packet
#[test]
fn rejects_invalid_udp_length() {
    let mut buf = [0u8; 2048];
    let mut packet = Packet::testing_new(&mut buf);

    PacketBuilder::ethernet2(SRC_MAC.0, DST_MAC.0)
        .ipv6([20; 16], [33; 16], 64)
        .udp(5353, 1111)
        .write(&mut packet, IPV6_DATA)
        .unwrap();

    let mut udp_hdr: nt::UdpHdr = packet.read(nt::EthHdr::LEN + nt::Ipv6Hdr::LEN).unwrap();
    assert_eq!(udp_hdr.source.host(), 5353);
    assert_eq!(udp_hdr.destination.host(), 1111);
    assert_eq!(
        udp_hdr.length.host() as usize,
        IPV6_DATA.len() + nt::UdpHdr::LEN
    );

    // too long
    {
        udp_hdr.length = u16::MAX.into();
        packet
            .write(nt::EthHdr::LEN + nt::Ipv6Hdr::LEN, udp_hdr)
            .unwrap();
        assert!(UdpHeaders::parse_packet(&packet).is_err());
    }

    // too short
    {
        udp_hdr.length = (nt::UdpHdr::LEN as u16).into();
        packet
            .write(nt::EthHdr::LEN + nt::Ipv6Hdr::LEN, udp_hdr)
            .unwrap();
        assert!(UdpHeaders::parse_packet(&packet).is_err());
    }

    // off by 1
    {
        udp_hdr.length = ((nt::UdpHdr::LEN + IPV6_DATA.len() + 1) as u16).into();
        packet
            .write(nt::EthHdr::LEN + nt::Ipv6Hdr::LEN, udp_hdr)
            .unwrap();
        assert!(UdpHeaders::parse_packet(&packet).is_err());
    }
}
