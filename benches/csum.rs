use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;
use xdp::frame::{net_types as nt, Pod as _};

fn generate(packet: &mut Vec<u8>, len: usize, ipv4: bool) -> u16 {
    const PAYLOAD: &[u8] = &[0xc0; 2048];

    let ip_headers = if ipv4 {
        etherparse::IpHeaders::Ipv4(
            etherparse::Ipv4Header::new(
                len as _,
                64,
                etherparse::IpNumber::UDP,
                [192, 168, 1, 139],
                [192, 168, 1, 1],
            )
            .unwrap(),
            etherparse::Ipv4Extensions { auth: None },
        )
    } else {
        etherparse::IpHeaders::Ipv6(
            etherparse::Ipv6Header {
                payload_length: len as _,
                hop_limit: 64,
                source: [1; 16],
                destination: [3; 16],
                ..Default::default()
            },
            etherparse::Ipv6Extensions::default(),
        )
    };

    let pb = etherparse::PacketBuilder::ethernet2([1, 1, 1, 1, 1, 1], [2, 2, 2, 2, 2, 2])
        .ip(ip_headers)
        .udp(8888, 54321);

    packet.clear();
    packet.reserve(pb.size(len));
    pb.write(packet, &PAYLOAD[..len]).unwrap();

    unsafe {
        (*packet
            .as_ptr()
            .byte_offset(
                (nt::EthHdr::LEN
                    + if ipv4 {
                        nt::Ipv4Hdr::LEN
                    } else {
                        nt::Ipv6Hdr::LEN
                    }) as isize,
            )
            .cast::<nt::UdpHdr>())
        .check
    }
}

#[inline]
fn csum_xdp(packet: &mut xdp::Frame) -> u16 {
    xdp::frame::csum::recalc_udp(packet).unwrap()
}

fn csum_ic(frame: &mut xdp::Frame) -> u16 {
    use nt::*;
    let mut offset = 0;
    let eth = frame.item_at_offset::<EthHdr>(offset).unwrap();
    offset += EthHdr::LEN;

    let mut csum = internet_checksum::Checksum::new();

    let udp_hdr = match eth.ether_type {
        EtherType::Ipv4 => {
            let ipv4 = frame.item_at_offset::<Ipv4Hdr>(offset).unwrap();
            offset += Ipv4Hdr::LEN;

            let udp_hdr = frame.item_at_offset::<UdpHdr>(offset).unwrap();
            csum.add_bytes(&udp_hdr.len.0.to_ne_bytes());
            csum.add_bytes(&(IpProto::Udp as u16).to_be_bytes());
            csum.add_bytes(&ipv4.source.0.to_ne_bytes());
            csum.add_bytes(&ipv4.destination.0.to_ne_bytes());

            udp_hdr
        }
        EtherType::Ipv6 => {
            let ipv6 = frame.item_at_offset::<Ipv6Hdr>(offset).unwrap();
            offset += Ipv6Hdr::LEN;

            let udp_hdr = frame.item_at_offset::<UdpHdr>(offset).unwrap();
            csum.add_bytes(&udp_hdr.len.0.to_ne_bytes());
            csum.add_bytes(&(IpProto::Udp as u16).to_be_bytes());
            csum.add_bytes(&ipv6.source);
            csum.add_bytes(&ipv6.destination);

            udp_hdr
        }
        _ => unreachable!(),
    };

    let mut udp_hdr = *udp_hdr;
    udp_hdr.check = 0;
    csum.add_bytes(udp_hdr.as_bytes());

    offset += UdpHdr::LEN;

    let data_payload = frame.slice_at_offset(offset, frame.len() - offset).unwrap();
    csum.add_bytes(data_payload);
    u16::from_ne_bytes(csum.checksum())
}

fn csum_ep(frame: &mut xdp::Frame) -> u16 {
    use nt::*;
    let mut offset = 0;
    let eth = frame.item_at_offset::<EthHdr>(offset).unwrap();
    offset += EthHdr::LEN;

    match eth.ether_type {
        EtherType::Ipv4 => {
            let ipv4 = frame.item_at_offset::<Ipv4Hdr>(offset).unwrap();
            offset += Ipv4Hdr::LEN;

            let udp_hdr = frame.item_at_offset::<UdpHdr>(offset).unwrap();
            let hdr = etherparse::UdpHeader {
                source_port: udp_hdr.source.host(),
                destination_port: udp_hdr.dest.host(),
                length: udp_hdr.len.host(),
                checksum: udp_hdr.check,
            };

            offset += UdpHdr::LEN;

            let data_payload = frame.slice_at_offset(offset, frame.len() - offset).unwrap();

            hdr.calc_checksum_ipv4_raw(
                ipv4.source.0.to_ne_bytes(),
                ipv4.destination.0.to_ne_bytes(),
                data_payload,
            )
            .unwrap()
            .to_be()
        }
        EtherType::Ipv6 => {
            let ipv6 = frame.item_at_offset::<Ipv6Hdr>(offset).unwrap();
            offset += Ipv6Hdr::LEN;

            let udp_hdr = frame.item_at_offset::<UdpHdr>(offset).unwrap();
            let hdr = etherparse::UdpHeader {
                source_port: udp_hdr.source.host(),
                destination_port: udp_hdr.dest.host(),
                length: udp_hdr.len.host(),
                checksum: 0,
            };
            offset += UdpHdr::LEN;

            let data_payload = frame.slice_at_offset(offset, frame.len() - offset).unwrap();
            hdr.calc_checksum_ipv6_raw(ipv6.source, ipv6.destination, data_payload)
                .unwrap()
                .to_be()
        }
        _ => unreachable!(),
    }
}

fn bench_csum(c: &mut Criterion) {
    use criterion::BenchmarkId;

    let mut group = c.benchmark_group("csum");
    let mut packet = Vec::new();
    let mut buf = [0; 2048];

    for i in [
        0usize, 1, 10, 32, 33, 63, 72, 80, 81, 127, 128, 256, 512, 773, 919, 1024, 1409,
    ] {
        let expected = generate(&mut packet, i, true);

        let mut frame = xdp::Frame::testing_new(&mut buf);
        frame.push_slice(&packet).unwrap();

        // Sanity check that all algorithms calculate the same
        assert_eq!(csum_xdp(&mut frame), expected);
        assert_eq!(csum_ic(&mut frame), expected);
        assert_eq!(csum_ep(&mut frame), expected);

        group.bench_function(BenchmarkId::new("ipv4 xdp", i), |b| {
            b.iter(|| csum_xdp(black_box(&mut frame)))
        });
        group.bench_function(BenchmarkId::new("ipv4 internet-checksum", i), |b| {
            b.iter(|| csum_ic(black_box(&mut frame)));
        });
        group.bench_function(BenchmarkId::new("ipv4 etherparse", i), |b| {
            b.iter(|| csum_ep(black_box(&mut frame)))
        });

        let expected = generate(&mut packet, i, false);

        let mut frame = xdp::Frame::testing_new(&mut buf);
        frame.push_slice(&packet).unwrap();

        // Sanity check that all algorithms calculate the same
        assert_eq!(csum_xdp(&mut frame), expected);
        assert_eq!(csum_ic(&mut frame), expected);
        assert_eq!(csum_ep(&mut frame), expected);

        group.bench_function(BenchmarkId::new("ipv6 xdp", i), |b| {
            b.iter(|| csum_xdp(black_box(&mut frame)))
        });
        group.bench_function(BenchmarkId::new("ipv6 internet-checksum", i), |b| {
            b.iter(|| csum_ic(black_box(&mut frame)));
        });
        group.bench_function(BenchmarkId::new("ipv6 etherparse", i), |b| {
            b.iter(|| csum_ep(black_box(&mut frame)))
        });
    }
    group.finish();
}

criterion_group!(benches, bench_csum);
criterion_main!(benches);
