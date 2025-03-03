//! Contains simple slab data structures for use with the TX and RX rings

use crate::Packet;

/// A fixed size buffer of packets
pub trait Slab {
    /// The number of free slots available
    fn available(&self) -> usize;
    /// The number of occupied slots
    fn len(&self) -> usize;
    /// True if the slab is empty
    fn is_empty(&self) -> bool;
    /// Pushes a packet to the slab, returning the packet if the slab is at capacity
    fn push_front(&mut self, packet: Packet) -> Option<Packet>;
    /// Pops the back packet if any
    fn pop_back(&mut self) -> Option<Packet>;
}

// A heap allocated slab, using [`std::collections::VecDequeue`]
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
}

impl Slab for HeapSlab {
    /// The number of packets in the slab
    #[inline]
    fn len(&self) -> usize {
        self.vd.len()
    }

    /// True if the slab is empty
    #[inline]
    fn is_empty(&self) -> bool {
        self.vd.is_empty()
    }

    /// The number of packets that can be pushed to the slab
    #[inline]
    fn available(&self) -> usize {
        self.vd.capacity() - self.vd.len()
    }

    /// Pops the front packet if any
    #[inline]
    fn pop_back(&mut self) -> Option<Packet> {
        self.vd.pop_back()
    }

    /// Pushes a packet to the front, returning `Some` if the slab is at capacity
    #[inline]
    fn push_front(&mut self, item: Packet) -> Option<Packet> {
        if self.available() > 0 {
            self.vd.push_front(item);
            None
        } else {
            Some(item)
        }
    }
}

struct AssertPowerOf2<const N: usize>;

impl<const N: usize> AssertPowerOf2<N> {
    const OK: () = assert!(usize::is_power_of_two(N), "must be a power of 2");
}

#[doc(hidden)]
pub const fn assert_power_of_2<const N: usize>() {
    let () = AssertPowerOf2::<N>::OK;
}

/// Slab impl macro, only public for creating testing slabs with integer types < usize
#[cfg_attr(debug_assertions, macro_export)]
macro_rules! slab {
    ($name:ident, $int:ty) => {
        /// A stack allocated, fixed size, ring buffer
        pub struct $name<const N: usize> {
            ring: [$crate::Packet; N],
            read: $int,
            write: $int,
        }

        impl<const N: usize> $name<N> {
            /// Creates a new slab, `N` must be a power of 2
            #[allow(clippy::new_without_default)]
            pub fn new() -> Self {
                $crate::slab::assert_power_of_2::<N>();

                Self {
                    // SAFETY: Packet is just a POD
                    ring: unsafe { std::mem::zeroed() },
                    read: 0,
                    write: 0,
                }
            }
        }

        impl<const N: usize> $crate::slab::Slab for $name<N> {
            /// The current number of packets in the slab
            #[inline]
            fn len(&self) -> usize {
                if self.write >= self.read {
                    (self.write - self.read) as _
                } else {
                    <$int>::MAX as usize - self.read as usize + self.write as usize + 1
                }
            }

            /// True if the slab is empty
            #[inline]
            fn is_empty(&self) -> bool {
                self.write == self.read
            }

            /// The number of packets that can be pushed to the slab
            #[inline]
            fn available(&self) -> usize {
                N - self.len()
            }

            /// Pops the back packet if any
            #[inline]
            fn pop_back(&mut self) -> Option<$crate::Packet> {
                if self.is_empty() {
                    return None;
                }

                let index = self.read as usize % N;
                self.read = self.read.wrapping_add(1);
                Some(self.ring[index].inner_copy())
            }

            /// Pushes a packet to the front, returning `Some` if the slab is at capacity
            #[inline]
            fn push_front(&mut self, item: $crate::Packet) -> Option<$crate::Packet> {
                if self.available() > 0 {
                    let index = self.write as usize % N;
                    self.write = self.write.wrapping_add(1);
                    self.ring[index] = item;
                    None
                } else {
                    Some(item)
                }
            }
        }
    };
}

slab!(StackSlab, usize);
