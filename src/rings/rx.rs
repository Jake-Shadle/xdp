use super::bindings::*;
use crate::{HeapSlab, Umem};

/// Ring from which we can dequeue packets that have been filled by the kernel
pub struct RxRing {
    ring: super::XskConsumer<crate::bindings::xdp_desc>,
    _mmap: memmap2::MmapMut,
}

impl RxRing {
    pub(crate) fn new(
        socket: std::os::fd::RawFd,
        cfg: &super::RingConfig,
        offsets: &xdp_mmap_offsets,
    ) -> Result<Self, crate::socket::SocketError> {
        let (_mmap, mut ring) =
            super::map_ring(socket, cfg.rx_count, RingPageOffsets::Rx, &offsets.rx).map_err(
                |inner| crate::socket::SocketError::RingMap {
                    inner,
                    ring: super::Ring::Rx,
                },
            )?;

        ring.cached_consumed = ring.consumer.load(std::sync::atomic::Ordering::Relaxed);
        ring.cached_produced = ring.producer.load(std::sync::atomic::Ordering::Relaxed);

        Ok(Self {
            ring: super::XskConsumer(ring),
            _mmap,
        })
    }

    /// Pops packets that have finished receiving
    ///
    /// The number of packets returned will be the minimum of the number of packets
    /// actually available in the ring, and the remaining capacity in the slab
    ///
    /// # Returns
    ///
    /// The number of actual packets that were pushed to the slab
    ///
    /// # Safety
    ///
    /// The packets returned in the slab must not outlive the [`Umem`]
    #[inline]
    pub unsafe fn recv(&mut self, umem: &Umem, packets: &mut HeapSlab) -> usize {
        let nb = packets.available();
        if nb == 0 {
            return 0;
        }

        let (actual, idx) = self.ring.peek(nb as _);

        if actual > 0 {
            self.do_recv(actual, idx, umem, packets);
        }

        actual
    }

    #[inline]
    unsafe fn do_recv(&mut self, actual: usize, idx: usize, umem: &Umem, packets: &mut HeapSlab) {
        let mask = self.ring.mask();
        for i in idx..idx + actual {
            let desc = self.ring[i & mask];
            packets.push_back(umem.packet(desc));
        }

        self.ring.release(actual as _);
    }
}

// pub struct WakableRxRing {
//     inner: RxRing,
//     socket: std::os::fd::RawFd,
// }

// impl WakableRxRing {
//     pub(crate) fn new(
//         socket: std::os::fd::RawFd,
//         cfg: &super::RingConfig,
//         offsets: &libc::xdp_mmap_offsets,
//     ) -> std::io::Result<Self> {
//         let inner = RxRing::new(socket, cfg, offsets)?;

//         Ok(Self { inner, socket })
//     }

//     pub fn recv<'umem>(&mut self, umem: &'umem Umem, frames: &mut Slab<Frame<'umem>>) -> usize {
//         let nb = frames.available();
//         if nb == 0 {
//             return 0;
//         }

//         let (actual, idx) = self.inner.ring.peek(nb as _);
//         if actual == 0 {
//             // SAFETY: should be safe even if the socket descriptor is invalid
//             unsafe {
//                 libc::recvfrom(
//                     self.socket,
//                     std::ptr::null_mut(),
//                     0,
//                     libc::MSG_DONTWAIT,
//                     std::ptr::null_mut(),
//                     std::ptr::null_mut(),
//                 )
//             };
//             return 0;
//         }

//         self.inner.do_recv(actual, idx, umem, frames);
//         actual
//     }
// }
