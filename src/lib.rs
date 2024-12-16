pub mod affinity;
pub mod error;
pub mod frame;
pub use frame::Frame;
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

pub struct Slab<T> {
    vd: std::collections::VecDeque<T>,
}

impl<T> Slab<T> {
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
    pub fn available(&self) -> usize {
        self.vd.capacity() - self.vd.len()
    }

    #[inline]
    pub fn pop_front(&mut self) -> Option<T> {
        self.vd.pop_front()
    }

    #[inline]
    pub fn pop_back(&mut self) -> Option<T> {
        self.vd.pop_back()
    }

    #[inline]
    pub fn push_front(&mut self, item: T) -> Option<T> {
        if self.available() > 0 {
            self.vd.push_front(item);
            None
        } else {
            Some(item)
        }
    }

    #[inline]
    pub fn push_back(&mut self, item: T) -> Option<T> {
        if self.available() > 0 {
            self.vd.push_back(item);
            None
        } else {
            Some(item)
        }
    }
}
