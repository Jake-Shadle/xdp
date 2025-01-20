use super::bindings::*;
use crate::Umem;

/// The ring used to enqueue buffers for the kernel to fill in with packets
/// received from a NIC
pub struct FillRing {
    ring: super::XskProducer<u64>,
    _mmap: memmap2::MmapMut,
}

impl FillRing {
    pub(crate) fn new(
        socket: std::os::fd::RawFd,
        cfg: &super::RingConfig,
        offsets: &xdp_mmap_offsets,
    ) -> Result<Self, crate::socket::SocketError> {
        let (_mmap, mut ring) =
            super::map_ring(socket, cfg.fill_count, RingPageOffsets::Fill, &offsets.fill).map_err(
                |inner| crate::socket::SocketError::RingMap {
                    inner,
                    ring: super::Ring::Fill,
                },
            )?;

        ring.cached_consumed = cfg.fill_count;
        ring.cached_produced = 0;

        Ok(Self {
            ring: super::XskProducer(ring),
            _mmap,
        })
    }

    /// Enqueues up to `num_packets` to be received and filled by the kernel
    ///
    /// # Safety
    ///
    /// The [`Umem`] must outlive the `AF_XDP` socket
    ///
    /// # Returns
    ///
    /// The number of packets that were actually enqueued. This number can be
    /// lower than the requested `num_packets` if the [`Umem`] didn't have enough
    /// open slots, or the rx ring had insufficient capacity
    pub unsafe fn enqueue(&mut self, umem: &mut Umem, num_packets: usize) -> usize {
        let mut popper = umem.popper();
        let requested = std::cmp::min(popper.len(), num_packets);
        if requested == 0 {
            return 0;
        }

        let (actual, idx) = self.ring.reserve(requested as _);

        if actual > 0 {
            let mask = self.ring.mask();
            for i in idx..idx + actual {
                self.ring[i & mask] = popper.pop();
            }

            self.ring.submit(actual as _);
        }

        actual
    }
}

/// The wakable version of [`FillRing`], which requires that we notify the kernel
/// when there are new buffers available to receive packets
pub struct WakableFillRing {
    inner: FillRing,
    socket: std::os::fd::RawFd,
}

impl WakableFillRing {
    pub(crate) fn new(
        socket: std::os::fd::RawFd,
        cfg: &super::RingConfig,
        offsets: &xdp_mmap_offsets,
    ) -> Result<Self, crate::socket::SocketError> {
        let inner = FillRing::new(socket, cfg, offsets)?;

        Ok(Self { inner, socket })
    }

    /// The same as [`FillRing::enqueue`], except the additional `wakeup` parameter
    /// determines if the kernel is actually informed of the new buffer(s) available
    /// to fill with data
    ///
    /// # Safety
    ///
    /// The [`Umem`] must outlive the `AF_XDP` socket
    #[inline]
    pub unsafe fn enqueue(
        &mut self,
        umem: &mut Umem,
        num_packets: usize,
        wakeup: bool,
    ) -> std::io::Result<usize> {
        let queued = self.inner.enqueue(umem, num_packets);

        if queued > 0 && wakeup {
            // SAFETY: This is safe, even if the socket descriptor is invalid.
            let ret = unsafe {
                libc::recvfrom(
                    self.socket,
                    std::ptr::null_mut(),
                    0,
                    libc::MSG_DONTWAIT,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };

            if ret < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() != std::io::ErrorKind::Interrupted {
                    return Err(err);
                }
            }
        }

        Ok(queued)
    }
}
