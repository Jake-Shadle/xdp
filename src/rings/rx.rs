//! The [`RxRing`] is a consumer ring that userspace can dequeue packets that have
//! been received on the NIC queue the ring is bound to

use crate::{libc, HeapSlab, Umem};

/// Ring from which we can dequeue packets that have been filled by the kernel
pub struct RxRing {
    ring: super::XskConsumer<libc::xdp::xdp_desc>,
    _mmap: crate::mmap::Mmap,
}

impl RxRing {
    pub(crate) fn new(
        socket: std::os::fd::RawFd,
        cfg: &super::RingConfig,
        offsets: &libc::rings::xdp_mmap_offsets,
    ) -> Result<Self, crate::socket::SocketError> {
        let (_mmap, mut ring) = super::map_ring(
            socket,
            cfg.rx_count,
            libc::rings::RingPageOffsets::Rx,
            &offsets.rx,
        )
        .map_err(|inner| crate::socket::SocketError::RingMap {
            inner,
            ring: super::Ring::Rx,
        })?;

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
