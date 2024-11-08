//! Tests ping ponging a UDP packet between a client and server on separate veth interfaces

use test_utils::netlink::*;
use umem::UmemCfgBuilder;
use xdp::{socket::*, *};

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn ping_pong() {
    //let vdevs = VirtualDevices::new();

    //const QUEUE_COUNT: u32 = 1;

    // let pair = vdevs
    //     .add_pair("client-one".into(), "server-one".into(), QUEUE_COUNT)
    //     .await;

    // let mut ns = vdevs.open_namespace("ping-pong-ns").await;

    //pair.assign_to_ns(&pair.second, "ping-pong-ns").await;
    //pair.up().await;

    let bed = TestBed::setup("ping-pong", 0);
    bed.up();

    let outside = bed.outside();
    let mut inside = bed.inside();

    let mut umem = Umem::map(UmemCfgBuilder::default().build().expect("invalid umem cfg"))
        .expect("failed to map umem");

    let mut sb = XdpSocketBuilder::new().expect("failed to create socket builder");
    let (rings, bind_flags) = sb
        .build_rings(&umem, RingConfigBuilder::default().build().unwrap())
        .expect("failed to build rings");

    const BATCH_SIZE: usize = 64;

    // Enqueue a buffer to receive the packet
    let mut fr = rings.fill_ring;
    assert_eq!(fr.enqueue(&mut umem, BATCH_SIZE), BATCH_SIZE);
    let mut rx = rings.rx_ring.expect("rx ring not created");
    let mut cr = rings.completion_ring;
    let mut tx = rings.tx_ring.expect("tx ring not created");

    //bind_flags.force_zerocopy();
    let socket = sb
        .bind(outside.index.into(), 0, bind_flags)
        .expect("failed to bind socket");

    // let mut cumem = Umem::map(UmemCfgBuilder::default().build().expect("invalid umem cfg"))
    //     .expect("failed to map umem");
    // let mut sb = XdpSocketBuilder::new().expect("failed to create socket builder");
    // let (rings, mut bind_flags) = sb
    //     .build_rings(&cumem, RingConfigBuilder::default().build().unwrap())
    //     .expect("failed to build rings");

    // let mut cfr = rings.fill_ring;
    // let mut crx = rings.rx_ring.expect("rx ring not created");
    // let mut ccr = rings.completion_ring;
    // let mut ctx = rings.tx_ring.expect("tx ring not created");

    // let csocket = sb
    //     .bind(NicIndex::new(pair.first.index), 0, bind_flags)
    //     .expect("failed to bind socket");

    let mut bpf = test_utils::Bpf::load(std::iter::once(socket.raw_fd()));
    let mut dummy = test_utils::Bpf::dummy();
    let _attach2 = {
        let _ns = inside.ns.as_mut().unwrap().enter();

        dummy.attach(inside.index.into(), test_utils::XdpFlags::DRV_MODE);
    };
    let _attach1 = bpf.attach(outside.index.into(), test_utils::XdpFlags::DRV_MODE);

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let rxed = std::sync::atomic::AtomicBool::new(false);

    std::thread::scope(|s| {
        s.spawn(|| {
            let _ctx = inside.ns.as_mut().unwrap().enter();

            let client =
                std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 50000)).unwrap();

            let addr = std::net::SocketAddr::from((outside.ipv4, 7777));
            while !rxed.load(std::sync::atomic::Ordering::Relaxed) {
                println!("sending ping {}->{addr}...", client.local_addr().unwrap());
                client
                    .send_to(&[1, 2, 3, 4], addr)
                    .expect("failed to send_to");
                std::thread::sleep(std::time::Duration::from_millis(100));
            }

            println!("waiting on pong...");
            let mut buf = [0u8; 4];
            let (_size, addr) = client.recv_from(&mut buf).expect("failed to recv_from");
            println!("got pong from {addr}");
            assert_eq!(addr, (outside.ipv4, 7777).into());

            // assert_eq!(cfr.enqueue(&mut cumem, 1), 1);

            // {
            //     let mut frame = cumem.alloc();
            //     frame
            //         .adjust_tail((EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + 4) as _)
            //         .expect("failed to adjust tail");

            //     let mut offset = 0;

            //     {
            //         let eth = frame.item_at_offset_mut::<EthHdr>(offset).unwrap();
            //         offset += EthHdr::LEN;
            //         eth.dst_addr = pair.second.ethernet;
            //         eth.src_addr = pair.first.ethernet;
            //         eth.ether_type = EtherType::Ipv4;
            //     }

            //     {
            //         let ip = frame.item_at_offset_mut::<Ipv4Hdr>(offset).unwrap();
            //         offset += Ipv4Hdr::LEN;
            //         ip.dst_addr = pair.second.ipv4.to_bits().to_be();
            //         ip.src_addr = pair.first.ipv4.to_bits().to_be();
            //         ip.check = 0;
            //         ip.proto = IpProto::Udp;
            //         ip.set_ihl(0);
            //         ip.set_version(4);
            //     }

            //     {
            //         let udp = frame.item_at_offset_mut::<UdpHdr>(offset).unwrap();
            //         offset += UdpHdr::LEN;
            //         udp.check = 0;
            //         udp.dest = 7777u16.to_be();
            //         udp.source = 9999u16.to_be();
            //         udp.len = ((UdpHdr::LEN + 4) as u16).to_be();
            //     }

            //     {
            //         let slice = frame.slice_at_offset_mut(offset, 4).unwrap();
            //         slice.copy_from_slice(&[1, 2, 3, 4]);
            //     }

            //     let mut slab = Slab::with_capacity(1);
            //     slab.push_front(frame);
            //     println!("sending...");
            //     assert_eq!(ctx.send(&mut slab), 1);
            // }

            // loop {
            //     if ccr.dequeue(&mut cumem, 1) == 1 {
            //         break;
            //     }
            // }

            // println!("finished sending");
            // let mut slab = Slab::with_capacity(1);

            // loop {
            //     if crx.recv(&cumem, &mut slab) == 1 {
            //         println!("received");
            //         break;
            //     }
            // }
        });

        s.spawn(|| {
            println!("waiting on ping...");

            let mut slab = Slab::with_capacity(1);

            // The entry we queued up in the fill ring is now filled, get it
            loop {
                if rx.recv(&umem, &mut slab) > 0 {
                    println!("received packet");
                    break;
                }
            }

            rxed.store(true, std::sync::atomic::Ordering::Relaxed);

            let mut frame = slab.pop_front().unwrap();

            let udp_packet = test_utils::UdpPacket::parse_frame(&frame);

            assert_eq!(udp_packet.data_length, 4);

            use test_utils::nt::*;

            // Mutate the packet, swapping the source and destination in each layer
            let mut offset = 0;
            {
                let eth: &mut EthHdr = frame.item_at_offset_mut(offset).unwrap();
                offset += EthHdr::LEN;
                eth.dst_addr = udp_packet.source.ethernet;
                eth.src_addr = outside.mac; //udp_packet.destination.ethernet;
            }

            {
                let ip: &mut Ipv4Hdr = frame.item_at_offset_mut(offset).unwrap();
                offset += Ipv4Hdr::LEN;
                test_utils::swap_ipv4(ip, &udp_packet);
            }

            {
                let udp: &mut UdpHdr = frame.item_at_offset_mut(offset).unwrap();
                //offset += UdpHdr::LEN;
                udp.check = 0;
                udp.dest = udp_packet.source.socket.port().to_be();
                udp.source = udp_packet.destination.socket.port().to_be();
            }

            println!("sending pong to {}...", udp_packet.source.socket);
            slab.push_back(frame);
            assert_eq!(tx.send(&mut slab), 1);

            println!("waiting tx finish...");
            loop {
                unsafe {
                    let boop = libc::sendto(
                        socket.raw_fd(),
                        std::ptr::null(),
                        0,
                        libc::MSG_DONTWAIT,
                        std::ptr::null(),
                        0,
                    );

                    if boop < 0 {
                        panic!("{}", std::io::Error::last_os_error());
                    }
                }
                if cr.dequeue(&mut umem, 1) == 1 {
                    println!("tx finished...");
                    break;
                }
            }
        });
    });
}
