use test_utils::netlink::VethPair;
use xdp::{
    packet::{net_types as nt, *},
    socket::*,
    umem::*,
    *,
};

/// Validates that we can offload (most of) the layer 4 checksum calculation to
/// hardware when the hardware + driver supports the `XDP_TXMD_FLAGS_CHECKSUM`
/// flag
#[test]
fn offloads_tx_checksum() {
    if std::env::var_os("CI").is_some() {
        println!("::notice file={},line={}::Skipping TX offload test with sofware checksum, Ubunut kernel version is too old", file!(), line!());
        return;
    }

    let vpair = test_utils::veth_pair!("tx_off", 0);

    do_checksum_test(true, &vpair);
}

/// Full end-to-end check that checksum are calculated correctly
#[test]
fn verify_checksum() {
    let vpair = test_utils::veth_pair!("tx_chk", 0);

    do_checksum_test(false, &vpair);
}

fn do_checksum_test(software: bool, vpair: &VethPair) {
    let mut umem = Umem::map(
        UmemCfgBuilder {
            frame_size: FrameSize::TwoK,
            head_room: 20,
            frame_count: 64,
            tx_metadata: software,
            software_checksum: software,
        }
        .build()
        .expect("invalid umem cfg"),
    )
    .expect("failed to map umem");

    const BATCH_SIZE: usize = 2;

    let (xdp_socket, _bpf, _attach, rings) = {
        let _ns = vpair.inside.namespace.enter();
        let mut sb = XdpSocketBuilder::new().expect("failed to create socket builder");
        let (rings, mut bind_flags) = sb
            .build_rings(&umem, RingConfigBuilder::default().build().unwrap())
            .expect("failed to build rings");

        let nic = xdp::nic::NicIndex::lookup_by_name(&vpair.inside.name)
            .expect("failed to resolve NIC")
            .expect("failed to find NIC");
        // We are doing software checksums, which requires copy mode
        bind_flags.force_copy();
        let xs = sb.bind(nic, 0, bind_flags).expect("failed to bind socket");
        let xfd = xs.raw_fd();

        // Ensure there is only 1 queue, otherwise we could drop packets
        assert_eq!(nic.queue_count().unwrap().rx_current, 1);

        let mut bpf = test_utils::Bpf::load(std::iter::once(xfd));
        let attach = bpf.attach(nic.into(), Default::default());

        (xs, bpf, attach, rings)
    };

    // Enqueue a buffer to receive the packet
    let mut fr = rings.fill_ring;
    assert_eq!(unsafe { fr.enqueue(&mut umem, BATCH_SIZE) }, BATCH_SIZE);
    let mut rx = rings.rx_ring.expect("rx ring not created");
    let mut cr = rings.completion_ring;
    let mut tx = rings.tx_ring.expect("tx ring not created");

    let client_socket = {
        let _ns = vpair.outside.namespace.enter();

        std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 8999))
            .expect("failed to bind client socket")
    };

    let clientp = b"client request";
    let serverp = b"server response";

    let sport = 64000;

    std::thread::scope(|s| {
        s.spawn(|| {
            let dest: std::net::SocketAddr = (vpair.inside.ipv4, 7777).into();
            let local = client_socket.local_addr().unwrap();
            println!("sending {}b {local} -> {dest}", clientp.len());
            client_socket
                .send_to(clientp, dest)
                .expect("failed to send first request");

            let mut response = [0u8; 20];

            println!("receiving {}b {local} <- {dest}", serverp.len());
            let (read, addr) = client_socket
                .recv_from(&mut response)
                .expect("failed to receive first response");
            assert_eq!(&response[..read], serverp);
            assert_eq!(addr, (vpair.inside.ipv4, 64000).into());

            println!("sending {}b {local} -> {dest}", clientp.len());
            client_socket
                .send_to(clientp, dest)
                .expect("failed to send first request");

            println!("receiving {}b {local} <- {dest}", serverp.len());
            let (read, addr) = client_socket
                .recv_from(&mut response)
                .expect("failed to receive first response");
            assert_eq!(&response[..read], serverp);
            assert_eq!(addr, (vpair.inside.ipv4, 64000).into());
        });

        s.spawn(|| {
            let timeout = PollTimeout::new(Some(std::time::Duration::from_millis(100)));

            let mut slab = xdp::HeapSlab::with_capacity(BATCH_SIZE);

            unsafe {
                loop {
                    xdp_socket.poll(timeout).unwrap();
                    if rx.recv(&umem, &mut slab) == 1 {
                        break;
                    }
                }

                let mut packet = slab.pop_back().unwrap();
                let udp = nt::UdpPacket::parse_packet(&packet)
                    .expect("failed to parse packet")
                    .expect("not a UDP packet");

                // For this packet, we calculate the full checksum
                packet.adjust_tail(-(udp.data_length as i32)).unwrap();
                packet.insert(udp.data_offset, serverp).unwrap();

                let nt::IpAddresses::V4 {
                    source,
                    destination,
                } = udp.ips
                else {
                    unreachable!()
                };

                let mut new = nt::UdpPacket {
                    ips: nt::IpAddresses::V4 {
                        source: destination,
                        destination: source,
                    },
                    src_mac: udp.dst_mac,
                    dst_mac: udp.src_mac,
                    src_port: sport.into(),
                    dst_port: udp.src_port,
                    data_offset: udp.data_offset,
                    data_length: serverp.len(),
                    hop: udp.hop - 1,
                    checksum: 0.into(),
                };

                new.set_packet_headers(&mut packet).unwrap();

                // For this packet, we calculate the full checksum
                let data_checksum = csum::partial(serverp, 0);
                new.calc_checksum(serverp.len(), data_checksum);
                println!("Full checksum: {:04x}", new.checksum.host());

                slab.push_back(packet);
                assert_eq!(tx.send(&mut slab), 1);

                loop {
                    xdp_socket.poll(timeout).unwrap();
                    if cr.dequeue(&mut umem, 1) == 1 {
                        break;
                    }
                }

                loop {
                    xdp_socket.poll(timeout).unwrap();
                    if rx.recv(&umem, &mut slab) == 1 {
                        break;
                    }
                }

                let mut packet = slab.pop_back().unwrap();
                let udp = nt::UdpPacket::parse_packet(&packet)
                    .expect("failed to parse packet")
                    .expect("not a UDP packet");

                packet.adjust_tail(-(udp.data_length as i32)).unwrap();
                packet.insert(udp.data_offset, serverp).unwrap();

                let new = nt::UdpPacket {
                    ips: nt::IpAddresses::V4 {
                        source: destination,
                        destination: source,
                    },
                    src_mac: udp.dst_mac,
                    dst_mac: udp.src_mac,
                    src_port: sport.into(),
                    dst_port: udp.src_port,
                    data_offset: udp.data_offset,
                    data_length: serverp.len(),
                    hop: udp.hop - 1,
                    checksum: 0.into(),
                };

                new.set_packet_headers(&mut packet).unwrap();
                println!(
                    "partial checksum: {:04x}",
                    packet.calc_udp_checksum().unwrap()
                );

                slab.push_back(packet);
                assert_eq!(tx.send(&mut slab), 1);

                loop {
                    xdp_socket.poll(timeout).unwrap();
                    if cr.dequeue(&mut umem, 1) == 1 {
                        break;
                    }
                }
            }
        });
    });
}
