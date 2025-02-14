#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

macro_rules! within_range {
    ($ctx:expr, $name:ident, $range:expr) => {{
        let val = $ctx.$name;
        let uval = val as usize;

        if !$range.contains(&uval) {
            return Err($crate::error::ConfigError {
                name: stringify!($name),
                kind: $crate::error::ConfigErrorKind::OutOfRange {
                    size: uval,
                    range: $range,
                },
            }
            .into());
        }

        val
    }};
}

pub mod affinity;
pub mod error;
pub mod packet;
pub use packet::Packet;
pub mod libc;
mod mmap;
pub mod nic;
mod rings;
pub mod socket;
pub mod umem;

pub use umem::Umem;

pub use rings::{
    CompletionRing, FillRing, RingConfig, RingConfigBuilder, Rings, RxRing, TxRing,
    WakableFillRing, WakableRings, WakableTxRing,
};

// TODO: This is using VecDequeue (heap) internally, but in most situations this
// could just be fixed sizes with a const N: usize and stored on the stack, so
// might be worth doing that implementation inline, just not super important
/// A ring buffer used to do bulk pops from a [`RxRing`] or pushes to a [`TxRing`]
///
/// This is allocated on the heap, but will _not_ grow, and is intended to be
/// allocated once before entering an I/O loop
pub struct HeapSlab {
    vd: std::collections::VecDeque<Packet>,
}

impl HeapSlab {
    /// Allocates a new [`Self`] with the maximum specified capacity
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            vd: std::collections::VecDeque::with_capacity(capacity),
        }
    }

    /// The number of packets in the slab
    #[inline]
    pub fn len(&self) -> usize {
        self.vd.len()
    }

    /// True if the slab is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.vd.is_empty()
    }

    /// The number of packets that can be pushed to the slab
    #[inline]
    pub fn available(&self) -> usize {
        self.vd.capacity() - self.vd.len()
    }

    /// Pops the front packet if any
    #[inline]
    pub fn pop_front(&mut self) -> Option<Packet> {
        self.vd.pop_front()
    }

    /// Pops the back packet if any
    #[inline]
    pub fn pop_back(&mut self) -> Option<Packet> {
        self.vd.pop_back()
    }

    /// Pushes a packet to the front, returning `Some` if the slab is at capacity
    #[inline]
    pub fn push_front(&mut self, item: Packet) -> Option<Packet> {
        if self.available() > 0 {
            self.vd.push_front(item);
            None
        } else {
            Some(item)
        }
    }

    /// Pushes a packet to the back, returning `Some` if the slab is at capacity
    #[inline]
    pub fn push_back(&mut self, item: Packet) -> Option<Packet> {
        if self.available() > 0 {
            self.vd.push_back(item);
            None
        } else {
            Some(item)
        }
    }
}
