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

use crate::bindings::rings as bindings;

pub const XSK_RING_PROD_DEFAULT_NUM_DESCS: u32 = 2048;
pub const XSK_RING_CONS_DEFAULT_NUM_DESCS: u32 = 2048;

#[derive(Debug)]
pub enum Ring {
    Fill,
    Rx,
    Completion,
    Tx,
}

pub struct RingConfigBuilder {
    /// The maximum number of entries in the [`RxRing`] or [`WakableRxRing`]
    pub rx_count: u32,
    /// The maximum number of entries in the [`TxRing`]
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
    pub fn build(self) -> Result<RingConfig, error::Error> {
        if self.rx_count == 0 && self.tx_count == 0 {
            return Err(error::ConfigError {
                name: "rx_count, tx_count",
                kind: error::ConfigErrorKind::MustSendOrRecv,
            }
            .into());
        }

        let fill_count = crate::non_zero_and_power_of_2!(self, fill_count);
        let completion_count = crate::non_zero_and_power_of_2!(self, completion_count);
        let rx_count = crate::zero_or_power_of_2!(self, rx_count);
        let tx_count = crate::zero_or_power_of_2!(self, tx_count);

        Ok(RingConfig {
            rx_count,
            tx_count,
            fill_count,
            completion_count,
        })
    }
}

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

pub struct Rings {
    pub fill_ring: FillRing,
    pub rx_ring: Option<RxRing>,
    pub completion_ring: CompletionRing,
    pub tx_ring: Option<TxRing>,
}

pub struct WakableRings {
    pub fill_ring: WakableFillRing,
    pub rx_ring: Option<RxRing>,
    pub completion_ring: CompletionRing,
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
    offset: bindings::RingPageOffsets,
    offsets: &bindings::xdp_ring_offset,
) -> std::io::Result<(memmap2::MmapMut, XskRing<T>)> {
    // SAFETY: This is called before actually binding the socket, and should be safe barring kernel bugs
    let mut mmap = unsafe {
        memmap2::MmapOptions::new()
            .len(offsets.desc as usize + (count as usize * std::mem::size_of::<T>()))
            .offset(offset as u64)
            .populate()
            .map_mut(socket)?
    };

    // SAFETY: The lifetime of the pointers are the same as the mmap
    let ring = unsafe {
        let map = mmap.as_mut_ptr();

        let producer = AtomicU32::from_ptr(map.byte_offset(offsets.producer as _) as *mut u32);
        let consumer = AtomicU32::from_ptr(map.byte_offset(offsets.consumer as _) as *mut u32);
        let ring = std::slice::from_raw_parts_mut(
            map.byte_offset(offsets.desc as _) as *mut T,
            count as _,
        );

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
        unsafe { self.0.ring.get_unchecked(index) }
    }
}

impl<T> std::ops::IndexMut<usize> for XskProducer<T> {
    #[inline]
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        unsafe { self.0.ring.get_unchecked_mut(index) }
    }
}

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
