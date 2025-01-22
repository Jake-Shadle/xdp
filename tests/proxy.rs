#![cfg(any())]

use std::net::{IpAddr, SocketAddr, ToSocketAddrs as _};
use test_utils::{
    netlink::*,
    nt::{Ipv4Hdr, Ipv6Hdr},
};
use umem::UmemCfgBuilder;
use xdp::{socket::*, *};

const PACKET_COUNT: usize = 1000;

struct DualEndpoint {
    mac: [u8; 6],
    ipv4: std::net::SocketAddrV4,
    ipv6: std::net::SocketAddrV6,
}

const MAX_TP_LEN: usize = 4 + 6 + 16 + 2;
const MIN_TP_LEN: usize = 4 + 6 + 4 + 2;

struct TestPacket {
    buf: [u8; MAX_TP_LEN],
    len: usize,
    counter: u32,
}

impl TestPacket {
    fn new(mac: [u8; 6], addr: SocketAddr) -> Self {
        let mut buf = [0u8; MAX_TP_LEN];
        let mut len = 4;

        buf[len..len + 6].copy_from_slice(&mac);
        len += mac.len();

        match addr.ip() {
            std::net::IpAddr::V4(v4) => {
                buf[len..len + 4].copy_from_slice(&v4.to_bits().to_ne_bytes());
                len += 4;
            }
            std::net::IpAddr::V6(v6) => {
                buf[len..len + 16].copy_from_slice(&v6.octets());
                len += 16;
            }
        };

        buf[len..len + 2].copy_from_slice(&addr.port().to_ne_bytes());
        len += 2;

        Self {
            buf,
            len,
            counter: 0,
        }
    }

    fn inc(&mut self) {
        self.counter += 1;
        self.buf[..4].copy_from_slice(&self.counter.to_ne_bytes());
    }

    fn parse(buf: &[u8]) -> (u32, [u8; 6], SocketAddr) {
        let counter = u32::from_ne_bytes(buf[..4].try_into().unwrap());
        let port = u16::from_ne_bytes(buf[buf.len() - 2..].try_into().unwrap());
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&buf[4..10]);
        let ip = match buf.len() {
            MIN_TP_LEN => {
                std::net::Ipv4Addr::from_bits(u32::from_ne_bytes(buf[10..14].try_into().unwrap()))
                    .into()
            }
            MAX_TP_LEN => std::net::IpAddr::from(
                <[u8; 16] as TryFrom<&[u8]>>::try_from(&buf[10..26]).unwrap(),
            ),
            _ => unreachable!("invalid payload length"),
        };

        (counter, mac, (ip, port).into())
    }
}

impl AsRef<[u8]> for TestPacket {
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

struct Targets {
    client4: std::net::UdpSocket,
    client6: std::net::UdpSocket,
    server4: std::net::UdpSocket,
    server6: std::net::UdpSocket,
}

impl Targets {
    fn run(&self, proxy: DualEndpoint, server: DualEndpoint) {
        let mut ipv4_recvd = 0;
        let mut ipv4_to_4 = 0;
        let mut ipv6_to_6 = 0;
        let mut ipv6_to_4 = 0;
        let mut ipv4_to_6 = 0;
        let mut ipv6_recvd = 0;

        std::thread::scope(|s| {
            s.spawn(|| {
                let mut buf = [0u8; 4];
                self.client4
                    .set_read_timeout(Some(std::time::Duration::from_secs(1)))
                    .unwrap();

                let expected = PACKET_COUNT * 2;

                while ipv4_recvd < expected {
                    match self.client4.recv_from(&mut buf) {
                        Ok((read, addr)) => {
                            if read != 4 {
                                eprintln!("ipv4 recv was {read} bytes");
                            } else {
                                match addr {
                                    SocketAddr::V4(v4) => {
                                        if v4 != proxy.ipv4 {
                                            eprintln!("ipv4 recv had incorrect addr {v4}");
                                        } else {
                                            ipv4_recvd += 1;
                                        }
                                    }
                                    SocketAddr::V6(v6) => {
                                        unreachable!("ipv6 {v6}");
                                    }
                                }
                            }
                        }
                        Err(err) => {
                            if err.raw_os_error() != Some(11) {
                                eprintln!("failed ipv4 recv: {err:#}");
                            }
                        }
                    }
                }
            });

            s.spawn(|| {
                let mut buf = [0u8; 4];
                self.client6
                    .set_read_timeout(Some(std::time::Duration::from_secs(1)))
                    .unwrap();

                let expected = PACKET_COUNT * 2;

                while ipv6_recvd < expected {
                    match self.client6.recv_from(&mut buf) {
                        Ok((read, addr)) => {
                            if read != 4 {
                                eprintln!("ipv6 recv was {read} bytes");
                            } else {
                                match addr {
                                    SocketAddr::V4(v4) => {
                                        unreachable!("ipv4 {v4}");
                                    }
                                    SocketAddr::V6(v6) => {
                                        if v6 != proxy.ipv6 {
                                            eprintln!("ipv6 recv had incorrect addr {v6}");
                                        } else {
                                            ipv6_recvd += 1;
                                        }
                                    }
                                }
                            }
                        }
                        Err(err) => {
                            if err.raw_os_error() != Some(11) {
                                eprintln!("failed ipv6 recv: {err:#}");
                            }
                        }
                    }
                }
            });

            s.spawn(|| {
                let mut buf = [0u8; MAX_TP_LEN];
                self.server4
                    .set_read_timeout(Some(std::time::Duration::from_secs(1)))
                    .unwrap();

                let mut expected = PACKET_COUNT * 2;

                while expected > 0 {
                    match self.server4.recv_from(&mut buf) {
                        Ok((read, addr)) => {
                            expected -= 1;
                            print!(".");
                            if let Err(err) = self.server4.send_to(&buf[..read], addr) {
                                eprintln!("ipv4 server failed to echo {err}");
                            }
                        }
                        Err(err) => {
                            if err.raw_os_error() != Some(11) {
                                eprintln!("failed server ipv4 recv: {err:#}");
                            }
                        }
                    }
                }
            });

            s.spawn(|| {
                let mut buf = [0u8; MAX_TP_LEN];
                self.server6
                    .set_read_timeout(Some(std::time::Duration::from_secs(1)))
                    .unwrap();

                let mut expected = PACKET_COUNT * 2;

                while expected > 0 {
                    match self.server6.recv_from(&mut buf) {
                        Ok((read, addr)) => {
                            expected -= 1;
                            print!(";");
                            if let Err(err) = self.server6.send_to(&buf[..read], addr) {
                                eprintln!("ipv6 server failed to echo {err:#}");
                            }
                        }
                        Err(err) => {
                            if err.raw_os_error() != Some(11) {
                                eprintln!("failed server ipv6 recv: {err:#}");
                            }
                        }
                    }
                }
            });

            s.spawn(|| {
                let packet = TestPacket::new(server.mac, server.ipv4.into());
                self.send(proxy.ipv4.into(), packet, &mut ipv4_to_4);
            });

            s.spawn(|| {
                let packet = TestPacket::new(server.mac, server.ipv6.into());
                self.send(proxy.ipv6.into(), packet, &mut ipv6_to_6);
            });

            s.spawn(|| {
                let packet = TestPacket::new(server.mac, server.ipv6.into());
                self.send(proxy.ipv4.into(), packet, &mut ipv4_to_6);
            });

            s.spawn(|| {
                let packet = TestPacket::new(server.mac, server.ipv4.into());
                self.send(proxy.ipv6.into(), packet, &mut ipv6_to_4);
            });
        });
    }

    fn send(&self, addr: SocketAddr, tp: TestPacket, counter: &mut u32) {
        let socket = match addr {
            SocketAddr::V4(_) => &self.client4,
            SocketAddr::V6(_) => &self.client6,
        };
        Self::send_inner(socket, addr, tp, counter);
    }

    fn send_inner(
        s: &std::net::UdpSocket,
        addr: SocketAddr,
        mut tp: TestPacket,
        counter: &mut u32,
    ) {
        while *counter < PACKET_COUNT as u32 {
            match s.send_to(tp.as_ref(), addr) {
                Ok(written) => {
                    if written != tp.len {
                        eprintln!("failed to write all {written}");
                    } else {
                        *counter += 1;
                        tp.inc();
                    }
                }
                Err(err) => {
                    if err.raw_os_error() != Some(101) {
                        eprintln!("send failed {err:#}");
                    }
                }
            }
        }
    }
}

const BATCH_SIZE: usize = 64;

struct Proxy {
    tb: TestBed,
    fr: FillRing,
    rx: RxRing,
    cr: CompletionRing,
    tx: TxRing,
    umem: Umem,
    socketfd: std::os::fd::RawFd,
}

impl Proxy {
    fn new(tb: TestBed, rings: xdp::Rings, mut umem: Umem, socketfd: std::os::fd::RawFd) -> Self {
        // Enqueue a buffer to receive the packet
        let mut fr = rings.fill_ring;
        assert_eq!(fr.enqueue(&mut umem, BATCH_SIZE), BATCH_SIZE);

        Self {
            tb,
            fr,
            rx: rings.rx_ring.expect("rx ring not created"),
            tx: rings.tx_ring.expect("tx ring not created"),
            cr: rings.completion_ring,
            umem,
            socketfd,
        }
    }

    fn run(&mut self) {
        let mut rx_slab = Slab::with_capacity(BATCH_SIZE);
        let mut tx_slab = Slab::with_capacity(BATCH_SIZE);

        let mut expected = PACKET_COUNT * 4 * 4;

        let (src_ip4, src_ip6) = {
            let out = self.tb.outside();
            (out.ipv4.to_bits().to_be(), out.ipv6.octets())
        };

        while expected > 0 {
            // The entry we queued up in the fill ring is now filled, get it
            loop {
                if self.rx.recv(&self.umem, &mut rx_slab) > 0 {
                    break;
                }
            }

            expected -= rx_slab.len();
            self.fr.enqueue(
                &mut self.umem,
                std::cmp::min(BATCH_SIZE, BATCH_SIZE - rx_slab.len()),
            );

            while let Some(mut packet) = rx_slab.pop_front() {
                let udp_packet = test_utils::UdpPacket::parse_packet(&packet);

                let (counter, target_mac, target_addr) = TestPacket::parse(
                    packet
                        .slice_at_offset(udp_packet.data_offset, udp_packet.data_length)
                        .unwrap(),
                );

                packet
                    .adjust_tail(-(udp_packet.data_length as i32))
                    .unwrap();

                use test_utils::nt::*;

                match (udp_packet.source.socket.ip(), target_addr.ip()) {
                    (IpAddr::V4(_), IpAddr::V6(_)) => {
                        packet.adjust_head(-(V4_V6_DIFF as i32)).unwrap();
                    }
                    (IpAddr::V6(_), IpAddr::V4(_)) => {
                        packet.adjust_head(V4_V6_DIFF as i32).unwrap();
                    }
                    _ => {}
                }

                // Mutate the packet, swapping the source and destination in each layer
                let mut offset = 0;
                {
                    let eth: &mut EthHdr = packet.item_at_offset_mut(offset).unwrap();
                    offset += EthHdr::LEN;
                    eth.dst_addr = target_mac;
                    eth.src_addr = udp_packet.destination.mac;
                }

                let client = TestPacket::new(udp_packet.source.mac, udp_packet.source.socket);

                match target_addr.ip() {
                    IpAddr::V4(v4) => {
                        let ip: &mut Ipv4Hdr = packet.item_at_offset_mut(offset).unwrap();
                        offset += Ipv4Hdr::LEN;
                        ip.src_addr = src_ip4;
                        ip.dst_addr = v4.to_bits().to_be();
                        ip.ttl -= 1;
                        ip.tot_len = ((Ipv4Hdr::LEN + 8 + client.len) as u16).to_be();

                        ip.check = test_utils::etherparse::Ipv4Header {
                            time_to_live: ip.ttl,
                            destination: ip.dst_addr.to_ne_bytes(),
                            source: ip.src_addr.to_ne_bytes(),
                            total_len: (Ipv4Hdr::LEN + 8 + client.len) as _,
                            protocol: test_utils::etherparse::IpNumber::UDP,
                            ..Default::default()
                        }
                        .calc_header_checksum();

                        // ip.check = xdp::packet::fold_checksum(xdp::packet::bpf_csum_diff(
                        //     &[],
                        //     unsafe {
                        //         std::slice::from_raw_parts(
                        //             (ip as *const Ipv4Hdr).cast(),
                        //             std::mem::size_of::<Ipv4Hdr>(),
                        //         )
                        //     },
                        //     0,
                        // ) as _);
                    }
                    IpAddr::V6(v6) => {
                        let ip: &mut Ipv6Hdr = packet.item_at_offset_mut(offset).unwrap();
                        offset += Ipv6Hdr::LEN;
                        ip.src_addr.in6_u.u6_addr8 = src_ip6;
                        ip.dst_addr.in6_u.u6_addr8 = v6.octets();
                        ip.payload_len = ((client.len + 8) as u16).to_be();
                        ip.hop_limit -= 1;
                    }
                }

                {
                    let udp: &mut UdpHdr = packet.item_at_offset_mut(offset).unwrap();
                    offset += UdpHdr::LEN;
                    udp.dest = target_addr.port().to_be();
                    udp.source = PROXY_PORT_NO;
                    udp.len = ((client.len + 8) as u16).to_be();

                    let uhdr = test_utils::etherparse::UdpHeader {
                        source_port: PROXY_PORT,
                        destination_port: target_addr.port(),
                        length: (client.len + 8) as _,
                        checksum: 0,
                    };

                    udp.check = match target_addr.ip() {
                        IpAddr::V4(v4) => uhdr
                            .calc_checksum_ipv4_raw(
                                src_ip4.to_ne_bytes(),
                                v4.to_bits().to_be_bytes(),
                                client.as_ref(),
                            )
                            .unwrap(),
                        IpAddr::V6(v6) => uhdr
                            .calc_checksum_ipv6_raw(src_ip6, v6.octets(), client.as_ref())
                            .unwrap(),
                    };
                };

                packet.push_slice(client.as_ref()).unwrap();

                {
                    let nudp_packet = test_utils::UdpPacket::parse_packet(&packet);
                    assert_eq!(nudp_packet.data_length, client.len);
                    assert_eq!(nudp_packet.destination.mac, target_mac);
                    assert_eq!(nudp_packet.destination.socket, target_addr);

                    let (counter, target_mac, target_addr) = TestPacket::parse(
                        packet
                            .slice_at_offset(nudp_packet.data_offset, nudp_packet.data_length)
                            .unwrap(),
                    );

                    assert_eq!(target_mac, udp_packet.destination.mac);
                    assert_eq!(target_addr, udp_packet.destination.socket);
                }

                tx_slab.push_back(packet);
            }

            let mut enqueued = self.tx.send(&mut tx_slab);

            while enqueued > 0 {
                unsafe {
                    let boop = libc::sendto(
                        self.socketfd,
                        std::ptr::null(),
                        0,
                        libc::MSG_DONTWAIT,
                        std::ptr::null(),
                        0,
                    );

                    if boop < 0 {
                        let err = std::io::Error::last_os_error();
                        if err.raw_os_error() != Some(11) {
                            eprintln!("{err}");
                        }
                    }
                }

                enqueued -= self.cr.dequeue(&mut self.umem, enqueued);
            }
        }
    }
}

const PROXY_PORT: u16 = 7777;
const PROXY_PORT_NO: u16 = PROXY_PORT.to_be();
const V4_V6_DIFF: usize = Ipv6Hdr::LEN - Ipv4Hdr::LEN;

//#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn proxy() {
    let bed = TestBed::setup("proxy", 1);
    bed.up();

    let outside = bed.outside();
    let mut inside = bed.inside();

    let umem = Umem::map(
        // We're going to be converting ipv4 <-> ipv6 packets, so make enough
        // headroom so that we don't need to copy any data
        UmemCfgBuilder {
            head_room: V4_V6_DIFF as _,
            ..Default::default()
        }
        .build()
        .expect("invalid umem cfg"),
    )
    .expect("failed to map umem");

    let mut sb = XdpSocketBuilder::new().expect("failed to create socket builder");
    let (rings, bind_flags) = sb
        .build_rings(&umem, RingConfigBuilder::default().build().unwrap())
        .expect("failed to build rings");

    let socket = sb
        .bind(outside.index.into(), 0, bind_flags)
        .expect("failed to bind socket");

    let mut proxy = Proxy::new(bed, rings, umem, socket.raw_fd());

    let mut bpf = test_utils::Bpf::load(std::iter::once(socket.raw_fd()));
    let mut dummy = test_utils::Bpf::dummy();
    let _attach2 = {
        let _ns = inside.ns.as_mut().unwrap().enter();
        dummy.attach(inside.index.into(), test_utils::XdpFlags::DRV_MODE);
    };
    let _attach1 = bpf.attach(outside.index.into(), test_utils::XdpFlags::DRV_MODE);

    // let cbed = TestBed::setup("client", 2);
    // cbed.up();

    let ipv4 = std::net::SocketAddrV4::new(outside.ipv4, 11111);
    let ipv6 = std::net::SocketAddrV6::new(
        std::net::Ipv6Addr::UNSPECIFIED,
        22222,
        0,
        outside.index.into(),
    );
    let server4 = std::net::UdpSocket::bind(ipv4).unwrap();
    let server6 = std::net::UdpSocket::bind(ipv6).unwrap();

    let (targets, server_endpoints) = {
        let _cinside = inside.ns.as_ref().unwrap().enter();

        let client4 = std::net::UdpSocket::bind((inside.ipv4, 8888)).unwrap();

        let client6 = std::net::UdpSocket::bind(std::net::SocketAddrV6::new(
            std::net::Ipv6Addr::UNSPECIFIED,
            9999,
            0,
            inside.index.into(),
        ))
        .unwrap();

        let mac = outside.mac;
        let ipv6 = std::net::SocketAddrV6::new(inside.ipv6, 22222, 0, inside.index.into());
        drop(_cinside);

        (
            Targets {
                client4,
                client6,
                server4,
                server6,
            },
            DualEndpoint { mac, ipv4, ipv6 },
        )
    };

    let sbed = TestBed::setup("server", 3);
    sbed.up();

    // let (server, server_endpoints) = {
    //     let mut inside = sbed.inside();
    //     let _sinside = inside.ns.as_mut().unwrap().enter();

    //     let ipv4 = std::net::SocketAddrV4::new(inside.ipv4, 11111);
    //     let ipv6 = std::net::SocketAddrV6::new(
    //         std::net::Ipv6Addr::UNSPECIFIED,
    //         22222,
    //         0,
    //         inside.index.into(),
    //     );

    //     let server4 = std::net::UdpSocket::bind(ipv4).unwrap();
    //     let server6 = std::net::UdpSocket::bind(ipv6).unwrap();

    //     let mac = inside.mac;
    //     drop(_sinside);

    //     (
    //         Server {
    //             tb: sbed,
    //             inside,
    //             server4,
    //             server6,
    //         },
    //         DualEndpoint { ipv4, ipv6, mac },
    //     )
    // };

    let proxy_endpoints = DualEndpoint {
        ipv4: std::net::SocketAddrV4::new(outside.ipv4, PROXY_PORT),
        mac: outside.mac,
        ipv6: std::net::SocketAddrV6::new(outside.ipv6, PROXY_PORT, 0, outside.index.into()),
    };

    std::thread::scope(|s| {
        s.spawn(|| {
            std::thread::sleep(std::time::Duration::from_millis(10000));
            targets.run(proxy_endpoints, server_endpoints);
        });

        s.spawn(|| {
            proxy.run();
        });
    });
}
