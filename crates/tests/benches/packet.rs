use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use xdp::packet::net_types as nt;

fn generate(packet: &mut xdp::Packet, len: usize, ipv4: bool) {
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

    etherparse::PacketBuilder::ethernet2([1, 1, 1, 1, 1, 1], [2, 2, 2, 2, 2, 2])
        .ip(ip_headers)
        .udp(8888, 54321)
        .write(packet, &PAYLOAD[..len])
        .unwrap();
}

#[inline]
fn swap_copy(packet: &mut xdp::Packet) {
    let udp = nt::UdpPacket::parse_packet(packet).unwrap().unwrap();

    let mut offset = 0;
    packet
        .set(
            offset,
            nt::EthHdr {
                destination: udp.eth.source,
                source: udp.eth.destination,
                ether_type: udp.eth.ether_type,
            },
        )
        .unwrap();
    offset += nt::EthHdr::LEN;

    match udp.ip {
        nt::IpHdr::V4(mut v4) => {
            std::mem::swap(&mut v4.source, &mut v4.destination);
            packet.set(offset, v4).unwrap();
            offset += nt::Ipv4Hdr::LEN;
        }
        nt::IpHdr::V6(mut v6) => {
            std::mem::swap(&mut v6.source, &mut v6.destination);
            packet.set(offset, v6).unwrap();
            offset += nt::Ipv6Hdr::LEN;
        }
    }

    packet
        .set(
            offset,
            nt::UdpHdr {
                source: udp.udp.destination,
                destination: udp.udp.source,
                check: udp.udp.check,
                length: udp.udp.length,
            },
        )
        .unwrap();
}

fn bench_packet(c: &mut Criterion) {
    use criterion::BenchmarkId;

    let mut group = c.benchmark_group("packet");
    let mut buf = [0; 2048];

    for i in [
        0usize, 1, 10, 32, 33, 63, 72, 80, 81, 127, 128, 256, 512, 773, 919, 1024, 1409,
    ] {
        let mut packet = xdp::Packet::testing_new(&mut buf);
        generate(&mut packet, i, true);

        // group.bench_function(BenchmarkId::new("ipv4 pointer", i), |b| {
        //     b.iter(|| swap_pointer(black_box(&mut packet)));
        // });
        group.bench_function(BenchmarkId::new("ipv4 copy", i), |b| {
            b.iter(|| swap_copy(black_box(&mut packet)));
        });

        let mut packet = xdp::Packet::testing_new(&mut buf);
        generate(&mut packet, i, false);

        // group.bench_function(BenchmarkId::new("ipv6 pointer", i), |b| {
        //     b.iter(|| swap_pointer(black_box(&mut packet)));
        // });
        group.bench_function(BenchmarkId::new("ipv6 copy", i), |b| {
            b.iter(|| swap_copy(black_box(&mut packet)));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_packet);
criterion_main!(benches);
