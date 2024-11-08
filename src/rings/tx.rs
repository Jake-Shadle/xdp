use crate::{Frame, Slab};
use libc::xdp_desc;

/// The ring used to enqueue frames for the kernel to send
pub struct TxRing {
    ring: super::XskProducer<xdp_desc>,
    _mmap: memmap2::MmapMut,
}

impl TxRing {
    pub(crate) fn new(
        socket: std::os::fd::RawFd,
        cfg: &super::RingConfig,
        offsets: &libc::xdp_mmap_offsets,
    ) -> Result<Self, crate::socket::SocketError> {
        let (_mmap, mut ring) = super::map_ring(
            socket,
            cfg.tx_count,
            libc::XDP_PGOFF_TX_RING as _,
            &offsets.tx,
        )
        .map_err(|inner| crate::socket::SocketError::RingMap {
            inner,
            ring: super::Ring::Tx,
        })?;

        ring.cached_produced = ring.producer.load(std::sync::atomic::Ordering::Relaxed);
        // cached_consumed is tx_count bigger than the real consumer pointer so
        // that this addition can be avoided in the more frequently
        // executed code that computs free_entries in the beginning of
        // this function. Without this optimization it whould have been
        // free_entries = r->cached_prod - r->cached_cons + r->size.
        ring.cached_consumed =
            ring.consumer.load(std::sync::atomic::Ordering::Relaxed) + cfg.tx_count;

        Ok(Self {
            ring: super::XskProducer(ring),
            _mmap,
        })
    }

    /// Enqueues frames to be sent by the kernel
    ///
    /// # Returns
    ///
    /// The number of frames that were actually enqueued. This number can be
    /// lower than the requested `num_frames` if the Umem didn't have enough
    /// open slots, or the rx ring had insufficient capacity
    pub fn send(&mut self, frames: &mut Slab<Frame<'_>>) -> usize {
        let requested = frames.len();
        if requested == 0 {
            return 0;
        }

        let (actual, idx) = self.ring.reserve(requested as _);

        if actual > 0 {
            let mask = self.ring.mask();
            for i in idx..idx + actual {
                let Some(frame) = frames.pop_front() else {
                    unreachable!()
                };

                self.ring[i & mask] = frame.into();
            }

            self.ring.submit(actual as _);
        }

        actual
    }
}

/// Wakable version of [`TxRing`]
pub struct WakableTxRing {
    inner: TxRing,
    socket: std::os::fd::RawFd,
}

impl WakableTxRing {
    pub(crate) fn new(
        socket: std::os::fd::RawFd,
        cfg: &super::RingConfig,
        offsets: &libc::xdp_mmap_offsets,
    ) -> Result<Self, crate::socket::SocketError> {
        let inner = TxRing::new(socket, cfg, offsets)?;
        Ok(Self { inner, socket })
    }

    /// Enqueues frames to be sent by the kernel
    ///
    /// # Returns
    ///
    /// The number of frames that were actually enqueued. This number can be
    /// lower than the requested `num_frames` if the Umem didn't have enough
    /// open slots, or the rx ring had insufficient capacity
    pub fn send(&mut self, frames: &mut Slab<Frame<'_>>, wakeup: bool) -> std::io::Result<usize> {
        let queued = self.inner.send(frames);

        if queued > 0 && wakeup {
            // SAFETY: This is safe, even if the socket descriptor is invalid.
            let ret = unsafe {
                libc::sendto(
                    self.socket,
                    std::ptr::null_mut(),
                    0,
                    libc::MSG_DONTWAIT,
                    std::ptr::null_mut(),
                    0,
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
