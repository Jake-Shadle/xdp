//! Tests ping ponging a UDP packet between a client and server on separate veth interfaces

use test_utils::netlink::*;
use umem::UmemCfgBuilder;
use xdp::{frame::net_types::*, socket::*, *};

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn ping_pong() {
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
    assert_eq!(unsafe { fr.enqueue(&mut umem, BATCH_SIZE) }, BATCH_SIZE);
    let mut rx = rings.rx_ring.expect("rx ring not created");
    let mut cr = rings.completion_ring;
    let mut tx = rings.tx_ring.expect("tx ring not created");

    //bind_flags.force_zerocopy();
    let socket = sb
        .bind(outside.index.into(), 0, bind_flags)
        .expect("failed to bind socket");

    let mut bpf = test_utils::Bpf::load(std::iter::once(socket.raw_fd()));
    let mut dummy = test_utils::Bpf::dummy();
    let _attach2 = {
        let _ns = inside.ns.as_mut().unwrap().enter();

        dummy.attach(inside.index.into(), test_utils::XdpFlags::DRV_MODE);
    };
    let _attach1 = bpf.attach(outside.index.into(), test_utils::XdpFlags::DRV_MODE);

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let rxed = std::sync::atomic::AtomicBool::new(false);

    let client = {
        let _ctx = inside.ns.as_mut().unwrap().enter();
        std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 50000)).unwrap()
    };

    std::thread::scope(|s| {
        s.spawn(|| {
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
        });

        s.spawn(|| {
            println!("waiting on ping...");

            let mut slab = Slab::with_capacity(1);

            // The entry we queued up in the fill ring is now filled, get it
            loop {
                if unsafe { rx.recv(&umem, &mut slab) } > 0 {
                    println!("received packet");
                    break;
                }
            }

            rxed.store(true, std::sync::atomic::Ordering::Relaxed);

            let mut frame = slab.pop_front().unwrap();

            let udp_packet = UdpPacket::parse_frame(&frame).unwrap().unwrap();

            assert_eq!(udp_packet.data_length, 4);

            // Mutate the packet, swapping the source and destination in each layer
            let mut offset = 0;
            {
                let eth: &mut EthHdr = frame.item_at_offset_mut(offset).unwrap();
                offset += EthHdr::LEN;
                eth.destination = udp_packet.source.mac;
                eth.source.0 = outside.mac; //udp_packet.destination.ethernet;
            }

            {
                let ip: &mut Ipv4Hdr = frame.item_at_offset_mut(offset).unwrap();
                offset += Ipv4Hdr::LEN;
                let std::net::IpAddr::V4(source) = udp_packet.destination.ip else {
                    unreachable!()
                };
                let std::net::IpAddr::V4(destination) = udp_packet.source.ip else {
                    unreachable!()
                };

                ip.source = source.to_bits().into();
                ip.destination = destination.to_bits().into();
            }

            {
                let udp: &mut UdpHdr = frame.item_at_offset_mut(offset).unwrap();
                //offset += UdpHdr::LEN;
                udp.check = 0;
                udp.dest = udp_packet.source.port.into();
                udp.source = udp_packet.destination.port.into();
            }

            println!(
                "sending pong to {}:{}...",
                udp_packet.source.ip, udp_packet.source.port
            );
            slab.push_back(frame);
            assert_eq!(unsafe { tx.send(&mut slab) }, 1);

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
