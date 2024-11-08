pub mod netlink;
pub use aya::programs::XdpFlags;

pub mod nt {
    pub use network_types::{eth::*, ip::*, udp::*};
}

static LOGGER: std::sync::Once = std::sync::Once::new();

/// Needs ./build_ebpf.sh to be run
const PROGRAM: &[u8] = include_bytes!("../../../target/bpfel-unknown-none/release/socket-router");
const DUMMY: &[u8] = include_bytes!("../../../target/bpfel-unknown-none/release/dummy");

pub struct Bpf {
    bpf: aya::Ebpf,
}

impl Bpf {
    pub fn load(sockets: impl Iterator<Item = std::os::fd::RawFd>) -> Self {
        let mut loader = aya::EbpfLoader::new();

        let sockets: Vec<_> = sockets.collect();
        // let socket_count = sockets.len() as u64;
        // loader.set_global("SOCKET_COUNT", &socket_count, true);

        // if let Err(err) = object::read::File::parse(PROGRAM) {
        //     panic!("{err}");
        // }

        let mut bpf = loader.load(PROGRAM).expect("failed to load socket-router");

        let mut xsk_map =
            aya::maps::XskMap::try_from(bpf.map_mut("XSK").expect("failed to retrieve XSK map"))
                .expect("XSK was not an XskMap");

        for (i, fd) in sockets.into_iter().enumerate() {
            xsk_map.set(i as _, fd, 0).expect("failed to add socket");
        }

        LOGGER.call_once(|| {
            env_logger::init();
        });

        if let Err(e) = aya_log::EbpfLogger::init(&mut bpf) {
            // This can happen if we don't have any log statements
            eprintln!("failed to initialize eBPF logger: {e}");
        }

        let program: &mut aya::programs::Xdp = bpf
            .program_mut("socket_router")
            .expect("failed to find entrypoint")
            .try_into()
            .expect("not an XDP program");
        program.load().expect("failed to load program");

        Self { bpf }
    }

    pub fn dummy() -> Self {
        let mut loader = aya::EbpfLoader::new();
        // if let Err(err) = object::read::File::parse(DUMMY) {
        //     panic!("{err}");
        // }

        let mut bpf = loader.load(DUMMY).expect("failed to load socket-router");
        let program: &mut aya::programs::Xdp = bpf
            .program_mut("socket_router")
            .expect("failed to find entrypoint")
            .try_into()
            .expect("not an XDP program");
        program.load().expect("failed to load program");
        Self { bpf }
    }

    pub fn attach(&mut self, interface: u32, flags: XdpFlags) -> aya::programs::xdp::XdpLinkId {
        let program: &mut aya::programs::Xdp = self
            .bpf
            .program_mut("socket_router")
            .expect("failed to find entrypoint")
            .try_into()
            .expect("not an XDP program");
        program
            .attach_to_if_index(interface, flags)
            .expect("failed to attach program")
    }
}

use std::{
    fmt,
    net::{IpAddr, SocketAddr},
};

pub struct FullAddress {
    pub ethernet: [u8; 6],
    pub socket: SocketAddr,
}

impl fmt::Debug for FullAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entry(
                &"eth",
                &format!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    self.ethernet[0],
                    self.ethernet[1],
                    self.ethernet[2],
                    self.ethernet[3],
                    self.ethernet[4],
                    self.ethernet[5]
                ),
            )
            .entry(&"ip", &self.socket)
            .finish()
    }
}

pub struct UdpPacket {
    pub source: FullAddress,
    pub destination: FullAddress,
    pub data_offset: usize,
    pub data_length: usize,
    pub checksum: u16,
}

impl UdpPacket {
    pub fn parse_frame(frame: &xdp::Frame<'_>) -> Self {
        use nt::*;
        use std::net::IpAddr;

        let mut offset = 0;
        let ether: &EthHdr = frame.item_at_offset(offset).expect("eth hdr");
        offset += EthHdr::LEN;

        let source;
        let destination;

        let udp: &UdpHdr = match ether.ether_type {
            EtherType::Ipv4 => {
                let ipv4: &Ipv4Hdr = frame.item_at_offset(offset).expect("ipv4 hdr");
                offset += Ipv4Hdr::LEN;

                match ipv4.proto {
                    IpProto::Udp => {
                        source = IpAddr::V4(ipv4.src_addr());
                        destination = IpAddr::V4(ipv4.dst_addr());
                        frame.item_at_offset(offset).expect("udp hdr")
                    }
                    other => {
                        panic!("ipv4 had unexpected protocol {other:?}");
                    }
                }
            }
            EtherType::Ipv6 => {
                let ipv6: &Ipv6Hdr = frame.item_at_offset(offset).expect("ipv6 hdr");
                offset += Ipv6Hdr::LEN;

                match ipv6.next_hdr {
                    IpProto::Udp => {
                        source = IpAddr::V6(ipv6.src_addr());
                        destination = IpAddr::V6(ipv6.dst_addr());
                        frame.item_at_offset(offset).expect("udp hdr")
                    }
                    other => {
                        panic!("ipv6 had unexpected protocol {other:?}");
                    }
                }
            }
            other => {
                panic!("unexpected ethernet type {other:?}");
            }
        };

        offset += UdpHdr::LEN;

        let source = FullAddress {
            ethernet: ether.src_addr,
            socket: SocketAddr::new(source, u16::from_be(udp.source)),
        };
        let destination = FullAddress {
            ethernet: ether.dst_addr,
            socket: SocketAddr::new(destination, u16::from_be(udp.dest)),
        };

        Self {
            source,
            destination,
            data_offset: offset,
            data_length: u16::from_be(udp.len) as usize - UdpHdr::LEN,
            checksum: u16::from_be(udp.check),
        }
    }
}

pub fn swap_ipv4(ip: &mut nt::Ipv4Hdr, original: &UdpPacket) {
    let IpAddr::V4(src) = &original.source.socket.ip() else {
        panic!("source was not ipv4")
    };
    let IpAddr::V4(dst) = &original.destination.socket.ip() else {
        panic!("destination was not ipv4")
    };

    ip.dst_addr = u32::to_be(src.to_bits());
    ip.src_addr = u32::to_be(dst.to_bits());
}

pub fn swap_ipv6(ip: &mut nt::Ipv6Hdr, original: &UdpPacket) {
    let IpAddr::V6(src) = original.source.socket.ip() else {
        panic!("source was not ipv6")
    };
    let IpAddr::V6(dst) = original.destination.socket.ip() else {
        panic!("destination was not ipv6")
    };

    ip.dst_addr.in6_u.u6_addr8 = src.octets();
    ip.src_addr.in6_u.u6_addr8 = dst.octets();
}
