pub mod netlink;
pub use aya::programs::XdpFlags;

pub use etherparse;

static LOGGER: std::sync::Once = std::sync::Once::new();

/// Needs `./build_ebpf.sh` to be run
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
