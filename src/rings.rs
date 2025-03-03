//! Contains the code for initializing and operating the various ring buffers
//! used in XDP I/O loops

mod fill;
pub use fill::{FillRing, WakableFillRing};
mod completion;
pub use completion::CompletionRing;
mod rx;
pub use rx::RxRing;
mod tx;
pub use tx::{TxRing, WakableTxRing};

use crate::error;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::libc::rings as libc;

pub const XSK_RING_PROD_DEFAULT_NUM_DESCS: u32 = 2048;
pub const XSK_RING_CONS_DEFAULT_NUM_DESCS: u32 = 2048;

macro_rules! non_zero_and_power_of_2 {
    ($ctx:expr, $name:ident) => {{
        let val = $ctx.$name;
        if val == 0 {
            return Err($crate::error::ConfigError {
                name: stringify!($name),
                kind: $crate::error::ConfigErrorKind::Zero,
            }
            .into());
        } else if !val.is_power_of_two() {
            return Err($crate::error::ConfigError {
                name: stringify!($name),
                kind: $crate::error::ConfigErrorKind::NonPowerOf2,
            }
            .into());
        }

        val
    }};
}

macro_rules! zero_or_power_of_2 {
    ($ctx:expr, $name:ident) => {{
        let val = $ctx.$name;
        if val != 0 && !val.is_power_of_two() {
            return Err($crate::error::ConfigError {
                name: stringify!($name),
                kind: $crate::error::ConfigErrorKind::NonPowerOf2,
            }
            .into());
        }

        val
    }};
}

#[derive(Debug)]
pub enum Ring {
    Fill,
    Rx,
    Completion,
    Tx,
}

/// Builder for the rings that will be created for an XDP socket.
///
/// All fields _must_ be a power of two, and both `fill_count` and `completion_count`
/// must not be zero.
///
/// `rx_count` OR `tx_count` may be zero, but not both
pub struct RingConfigBuilder {
    /// The maximum number of entries in the [`RxRing`]
    pub rx_count: u32,
    /// The maximum number of entries in the [`TxRing`] or [`WakableTxRing`]
    pub tx_count: u32,
    /// The maximum number of entries in the [`FillRing`] or [`WakableFillRing`]
    pub fill_count: u32,
    /// The maximum number of entries in the [`CompletionRing`]
    pub completion_count: u32,
}

impl Default for RingConfigBuilder {
    fn default() -> Self {
        Self {
            fill_count: XSK_RING_PROD_DEFAULT_NUM_DESCS,
            completion_count: XSK_RING_CONS_DEFAULT_NUM_DESCS,
            rx_count: XSK_RING_CONS_DEFAULT_NUM_DESCS,
            tx_count: XSK_RING_PROD_DEFAULT_NUM_DESCS,
        }
    }
}

impl RingConfigBuilder {
    /// Attempts to build a valid [`RingConfig`]
    pub fn build(self) -> Result<RingConfig, error::Error> {
        if self.rx_count == 0 && self.tx_count == 0 {
            return Err(error::ConfigError {
                name: "rx_count, tx_count",
                kind: error::ConfigErrorKind::MustSendOrRecv,
            }
            .into());
        }

        let fill_count = non_zero_and_power_of_2!(self, fill_count);
        let completion_count = non_zero_and_power_of_2!(self, completion_count);
        let rx_count = zero_or_power_of_2!(self, rx_count);
        let tx_count = zero_or_power_of_2!(self, tx_count);

        Ok(RingConfig {
            rx_count,
            tx_count,
            fill_count,
            completion_count,
        })
    }
}

/// Used to configure the rings created by the kernel in [`crate::socket::XdpSocketBuilder::build_rings`]
#[derive(Copy, Clone)]
pub struct RingConfig {
    /// The maximum number of entries in the [`RxRing`] or [`WakableRxRing`]
    pub(crate) rx_count: u32,
    /// The maximum number of entries in the [`TxRing`]
    pub(crate) tx_count: u32,
    /// The maximum number of entries in the [`FillRing`] or [`WakableFillRing`]
    pub(crate) fill_count: u32,
    /// The maximum number of entries in the [`CompletionRing`]
    pub(crate) completion_count: u32,
}

/// The set of rings tied to an XDP socket
pub struct Rings {
    /// The ring used by userspace to inform the kernel of memory addresses that
    /// you wish it to fill with packet received on the bound NIC
    pub fill_ring: FillRing,
    /// The ring used by the kernel to place packets that have finished receiving
    pub rx_ring: Option<RxRing>,
    /// The ring used by the kernel to inform userspace when packets have finished sending
    pub completion_ring: CompletionRing,
    /// The ring used by userspace to enqueue packets to be sent on the bound NIC
    pub tx_ring: Option<TxRing>,
}

/// The set of rings tied to an XDP socket
pub struct WakableRings {
    /// The ring used by userspace to inform the kernel of memory addresses that
    /// you wish it to fill with packet received on the bound NIC
    pub fill_ring: WakableFillRing,
    /// The ring used by the kernel to place packets that have finished receiving
    pub rx_ring: Option<RxRing>,
    /// The ring used by the kernel to inform userspace when packets have finished sending
    pub completion_ring: CompletionRing,
    /// The ring used by userspace to enqueue packets to be sent on the bound NIC
    pub tx_ring: Option<WakableTxRing>,
}

/// The equivalent of `xsk_ring_prod/cons`
struct XskRing<T: 'static> {
    producer: &'static AtomicU32,
    consumer: &'static AtomicU32,
    ring: &'static mut [T],
    cached_produced: u32,
    cached_consumed: u32,
    /// Total number of entries in the ring
    count: u32,
}

/// Creates a memory map for a ring
///
/// - `socket` - the file descriptor we are mapping
/// - `count` - the number of items in the mapping
/// - `offset` - the ring specific offset at which the kernel has allocated the buffer we are mapping
/// - `offsets` - the ring specific offsets
fn map_ring<T>(
    socket: std::os::fd::RawFd,
    count: u32,
    offset: libc::RingPageOffsets,
    offsets: &libc::xdp_ring_offset,
) -> std::io::Result<(crate::mmap::Mmap, XskRing<T>)> {
    let mmap = crate::mmap::Mmap::map_ring(
        offsets.desc as usize + (count as usize * std::mem::size_of::<T>()),
        offset as u64,
        socket,
    )?;

    // SAFETY: The lifetime of the pointers are the same as the mmap
    let ring = unsafe {
        let map = mmap.ptr;

        let producer = AtomicU32::from_ptr(map.byte_offset(offsets.producer as _).cast());
        let consumer = AtomicU32::from_ptr(map.byte_offset(offsets.consumer as _).cast());
        let ring =
            std::slice::from_raw_parts_mut(map.byte_offset(offsets.desc as _).cast(), count as _);

        XskRing {
            producer,
            consumer,
            count,
            ring,
            cached_produced: 0,
            cached_consumed: 0,
        }
    };

    Ok((mmap, ring))
}

/// Used for fill and tx rings where userspace is the producer
struct XskProducer<T: 'static>(XskRing<T>);

impl<T> XskProducer<T> {
    #[inline]
    fn mask(&self) -> usize {
        self.0.count as usize - 1
    }

    /// The equivalent of [`xsk_ring_prod__reserve`](https://docs.ebpf.io/ebpf-library/libxdp/functions/xsk_ring_prod__reserve/)
    #[inline]
    fn reserve(&mut self, nb: u32) -> (usize, usize) {
        if self.free(nb) < nb {
            return (0, 0);
        }

        let idx = self.0.cached_produced;
        self.0.cached_produced += nb;

        (nb as _, idx as _)
    }

    /// The equivalent of `xsk_prod_nb_free`
    #[inline]
    fn free(&mut self, nb: u32) -> u32 {
        let free_entries = self.0.cached_consumed - self.0.cached_produced;

        if free_entries >= nb {
            return free_entries;
        }

        // Refresh the local tail
        // cached_consumed is `size` bigger than the real consumer pointer so
        // that this addition can be avoided in the more frequently
        // executed code that computes free_entries in the beginning of
        // this function. Without this optimization it whould have been
        // free_entries = r->cached_prod - r->cached_cons + r->size.
        self.0.cached_consumed = self.0.consumer.load(Ordering::Acquire);
        self.0.cached_consumed += self.0.count;

        self.0.cached_consumed - self.0.cached_produced
    }

    /// The equivalent of [`xsk_ring_prod__submit`](https://docs.ebpf.io/ebpf-library/libxdp/functions/xsk_ring_prod__submit/)
    #[inline]
    fn submit(&mut self, nb: u32) {
        self.0.producer.fetch_add(nb, Ordering::Release);
    }
}

impl<T> std::ops::Index<usize> for XskProducer<T> {
    type Output = T;

    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        // SAFETY: each ring impl ensures the index is valid
        unsafe { self.0.ring.get_unchecked(index) }
    }
}

impl<T> std::ops::IndexMut<usize> for XskProducer<T> {
    #[inline]
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        // SAFETY: each ring impl ensures the index is valid
        unsafe { self.0.ring.get_unchecked_mut(index) }
    }
}

/// Used for rx and completion rings where userspace is the consumer
struct XskConsumer<T: 'static>(XskRing<T>);

impl<T> XskConsumer<T> {
    #[inline]
    fn mask(&self) -> usize {
        self.0.count as usize - 1
    }

    /// The equivalent of [`xsk_ring_cons__peek`](https://docs.ebpf.io/ebpf-library/libxdp/functions/xsk_ring_cons__peek/)
    #[inline]
    fn peek(&mut self, nb: u32) -> (usize, usize) {
        let entries = self.available(nb);

        if entries == 0 {
            return (0, 0);
        }

        let consumed = self.0.cached_consumed;
        self.0.cached_consumed += entries;

        (entries as _, consumed as _)
    }

    /// The equivalent of `xsk_cons_nb_avail`
    #[inline]
    fn available(&mut self, nb: u32) -> u32 {
        let mut entries = self.0.cached_produced - self.0.cached_consumed;

        if entries == 0 {
            self.0.cached_produced = self.0.producer.load(Ordering::Acquire);
            entries = self.0.cached_produced - self.0.cached_consumed;
        }

        std::cmp::min(entries, nb)
    }

    /// The equivalent of [`xsk_ring_cons__release`](https://docs.ebpf.io/ebpf-library/libxdp/functions/xsk_ring_cons__release/)
    #[inline]
    fn release(&mut self, nb: u32) {
        self.0.consumer.fetch_add(nb, Ordering::Release);
    }
}

impl<T> std::ops::Index<usize> for XskConsumer<T> {
    type Output = T;

    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        // SAFETY: Since we force power of 2 the same as libxdp, we know
        // it will always be within bounds
        unsafe { self.0.ring.get_unchecked(index) }
    }
}
