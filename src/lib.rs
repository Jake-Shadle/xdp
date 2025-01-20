pub mod affinity;
pub mod error;
pub mod packet;
pub use packet::Packet;
pub mod bindings;
pub mod nic;
mod rings;
pub mod socket;
pub mod umem;

pub use umem::Umem;

pub use rings::{
    CompletionRing, FillRing, RingConfig, RingConfigBuilder, Rings, RxRing, TxRing,
    WakableFillRing, WakableRings,
};

// TODO: This is using VecDequeue (heap) internally, but in most situations this
// could just be fixed sizes with a const N: usize and stored on the stack, so
// might be worth doing that implementation inline, just not super important
pub struct HeapSlab {
    vd: std::collections::VecDeque<Packet>,
}

impl HeapSlab {
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            vd: std::collections::VecDeque::with_capacity(capacity),
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.vd.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.vd.is_empty()
    }

    #[inline]
    pub fn available(&self) -> usize {
        self.vd.capacity() - self.vd.len()
    }

    #[inline]
    pub fn pop_front(&mut self) -> Option<Packet> {
        self.vd.pop_front()
    }

    #[inline]
    pub fn pop_back(&mut self) -> Option<Packet> {
        self.vd.pop_back()
    }

    #[inline]
    pub fn push_front(&mut self, item: Packet) -> Option<Packet> {
        if self.available() > 0 {
            self.vd.push_front(item);
            None
        } else {
            Some(item)
        }
    }

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
