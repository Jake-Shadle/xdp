#![no_std]
#![no_main]
#![allow(internal_features)]
#![feature(core_intrinsics)]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::XskMap,
    programs::XdpContext,
};
//use aya_log_ebpf::warn;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    udp::UdpHdr,
};

type Action = xdp_action::Type;

#[map]
static XSK: XskMap = XskMap::with_max_entries(128, 0);

// Number of sockets in the `XSK` map
// #[no_mangle]
// static SOCKET_COUNT: u64 = 0;

const TEST_PORT: u16 = u16::to_be(7777);

/// eBPF doesn't support 32-bit atomic operations, but AtomicU64 doesn't provide
/// fetch_add when targeting eBPF for some reason, so we just roll our own
// struct Atomic(core::cell::UnsafeCell<u64>);

// unsafe impl Sync for Atomic {}

// static COUNTER: Atomic = Atomic(core::cell::UnsafeCell::new(0));

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *mut T)
}

pub fn real_socket_router(ctx: XdpContext) -> Result<Action, ()> {
    let eth_hdr = unsafe { &mut *ptr_at::<EthHdr>(&ctx, 0)? };

    // Get the destination UDP port, passing all packets we don't care about
    let dest_port = unsafe {
        match eth_hdr.ether_type {
            EtherType::Ipv4 => {
                let ipv4hdr = ptr_at::<Ipv4Hdr>(&ctx, EthHdr::LEN)?;
                let v4hdr = &*ipv4hdr;

                match v4hdr.proto {
                    IpProto::Udp => {
                        let udp_hdr = &*ptr_at::<UdpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                        udp_hdr.dest
                    }
                    _ => {
                        return Err(());
                    }
                }
            }
            EtherType::Ipv6 => {
                let ipv6hdr = ptr_at::<Ipv6Hdr>(&ctx, EthHdr::LEN)?;
                let v6hdr = &*ipv6hdr;

                // Note this means that we ignore packets that have extensions
                match v6hdr.next_hdr {
                    IpProto::Udp => {
                        let udp_hdr = &*ptr_at::<UdpHdr>(&ctx, EthHdr::LEN + Ipv6Hdr::LEN)?;
                        udp_hdr.dest
                    }
                    _ => {
                        return Err(());
                    }
                }
            }
            _other => {
                return Err(());
            }
        }
    };

    if dest_port != TEST_PORT {
        return Err(());
    }

    // aya_log_ebpf::info!(&ctx, "UDP packet on {}", unsafe {
    //     (*ctx.ctx).rx_queue_index
    // });
    // Ok(xdp_action::XDP_DROP)
    let queue_id = unsafe { (*ctx.ctx).rx_queue_index };
    XSK.redirect(queue_id, 0).map_err(|_| ())

    // unsafe {
    //     let i = core::intrinsics::atomic_xadd_relaxed(COUNTER.0.get(), 1);
    //     let index = i % core::ptr::read_volatile(&SOCKET_COUNT);
    //     XSK.redirect(index as _, 0).map_err(|_| ())
    // }
}

/// The "main" of our program
#[xdp]
pub fn socket_router(ctx: XdpContext) -> Action {
    match real_socket_router(ctx) {
        Ok(action) => action,
        Err(()) => xdp_action::XDP_PASS,
    }
}

/// We can't panic, but we still need to satisfy the linker
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
