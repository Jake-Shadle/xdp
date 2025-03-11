use test_utils::netlink::VethPair;
use xdp::{
    packet::{net_types as nt, *},
    slab::Slab,
    socket::*,
    umem::*,
    *,
};

/// Validates that we can offload (most of) the layer 4 checksum calculation to
/// hardware when the hardware + driver supports the `XDP_TXMD_FLAGS_CHECKSUM`
/// flag. Note that this will fail if the kernel version is too low.
#[test]
fn offloads_tx_checksum() {
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
            software_checksum: software,
            ..Default::default()
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

        let cs = std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 8999))
            .expect("failed to bind client socket");

        cs.set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();

        cs
    };

    let clientp = b"client request";
    let serverp = b"server response";

    let sport = 64000;
    let run = std::sync::atomic::AtomicBool::new(true);

    macro_rules! poll_loop {
        ($b:block) => {{
            loop {
                if !run.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }

                $b
            }
        }};
    }

    std::thread::spawn(move || {
        let timeout = PollTimeout::new(Some(std::time::Duration::from_millis(100)));

        let mut slab = xdp::slab::StackSlab::<BATCH_SIZE>::new();

        unsafe {
            poll_loop!({
                xdp_socket.poll_read(timeout).unwrap();
                if rx.recv(&umem, &mut slab) == 1 {
                    break;
                }
            });

            let mut packet = slab.pop_back().unwrap();
            let udp = nt::UdpHeaders::parse_packet(&packet)
                .expect("failed to parse packet")
                .expect("not a UDP packet");

            // For this packet, we calculate the full checksum
            packet.adjust_tail(-(udp.data_length() as i32)).unwrap();
            packet.insert(udp.data.start, serverp).unwrap();

            let nt::IpHdr::V4(mut copy) = udp.ip else {
                unreachable!()
            };
            std::mem::swap(&mut copy.destination, &mut copy.source);
            copy.time_to_live -= 1;

            let mut new = nt::UdpHeaders::new(
                nt::EthHdr {
                    source: udp.eth.destination,
                    destination: udp.eth.source,
                    ether_type: udp.eth.ether_type,
                },
                nt::IpHdr::V4(copy),
                nt::UdpHdr {
                    destination: udp.udp.source,
                    source: sport.into(),
                    length: 0.into(),
                    check: 0,
                },
                udp.data.start..udp.data.start + serverp.len(),
            );

            // For this packet, we calculate the full checksum
            let full_checksum = new.calc_checksum(csum::DataChecksum::calculate(serverp));
            new.set_packet_headers(&mut packet).unwrap();
            println!("Full checksum: {full_checksum:04x}");

            slab.push_front(packet);
            assert_eq!(tx.send(&mut slab), 1);

            poll_loop!({
                xdp_socket.poll(timeout).unwrap();
                if cr.dequeue(&mut umem, 1) == 1 {
                    break;
                }
            });

            poll_loop!({
                xdp_socket.poll_read(timeout).unwrap();
                if rx.recv(&umem, &mut slab) == 1 {
                    break;
                }
            });

            let mut packet = slab.pop_back().unwrap();
            let udp = nt::UdpHeaders::parse_packet(&packet)
                .expect("failed to parse packet")
                .expect("not a UDP packet");

            packet.adjust_tail(-(udp.data_length() as i32)).unwrap();
            packet.insert(udp.data.start, serverp).unwrap();

            let nt::IpHdr::V4(mut copy) = udp.ip else {
                unreachable!()
            };
            std::mem::swap(&mut copy.destination, &mut copy.source);
            copy.time_to_live -= 1;

            let mut new = nt::UdpHeaders::new(
                nt::EthHdr {
                    source: udp.eth.destination,
                    destination: udp.eth.source,
                    ether_type: udp.eth.ether_type,
                },
                nt::IpHdr::V4(copy),
                nt::UdpHdr {
                    destination: udp.udp.source,
                    source: sport.into(),
                    length: 0.into(),
                    check: 0,
                },
                udp.data.start..udp.data.start + serverp.len(),
            );
            new.set_packet_headers(&mut packet).unwrap();
            println!(
                "partial checksum: {:04x}",
                packet.calc_udp_checksum().unwrap()
            );

            slab.push_front(packet);
            assert_eq!(tx.send(&mut slab), 1);

            poll_loop!({
                xdp_socket.poll(timeout).unwrap();
                if cr.dequeue(&mut umem, 1) == 1 {
                    break;
                }
            });
        }
    });

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
    assert_eq!(addr, (vpair.inside.ipv4, sport).into());

    println!("sending {}b {local} -> {dest}", clientp.len());
    client_socket
        .send_to(clientp, dest)
        .expect("failed to send second request");

    println!("receiving {}b {local} <- {dest}", serverp.len());
    let (read, addr) = client_socket
        .recv_from(&mut response)
        .expect("failed to receive second response");

    assert_eq!(&response[..read], serverp);
    assert_eq!(addr, (vpair.inside.ipv4, sport).into());
}
