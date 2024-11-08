use crate::Umem;

/// The ring used to dequeue buffers that the kernel has finished sending
pub struct CompletionRing {
    ring: super::XskConsumer<u64>,
    _mmap: memmap2::MmapMut,
}

impl CompletionRing {
    pub(crate) fn new(
        socket: std::os::fd::RawFd,
        cfg: &super::RingConfig,
        offsets: &libc::xdp_mmap_offsets,
    ) -> Result<Self, crate::socket::SocketError> {
        let (_mmap, mut ring) = super::map_ring(
            socket,
            cfg.completion_count,
            libc::XDP_UMEM_PGOFF_COMPLETION_RING,
            &offsets.cr,
        )
        .map_err(|inner| crate::socket::SocketError::RingMap {
            inner,
            ring: super::Ring::Completion,
        })?;

        ring.cached_consumed = 0;
        ring.cached_produced = 0;

        Ok(Self {
            ring: super::XskConsumer(ring),
            _mmap,
        })
    }

    /// Dequeues up to `num_frames` and makes them available for use again
    ///
    /// # Returns
    ///
    /// The number of frames that were actually dequeued.
    pub fn dequeue(&mut self, umem: &mut Umem, num_frames: usize) -> usize {
        let requested = num_frames;
        if requested == 0 {
            return 0;
        }

        let (actual, idx) = self.ring.peek(requested as _);

        if actual > 0 {
            let mask = self.ring.mask();
            for i in idx..idx + actual {
                let addr = self.ring[i & mask];
                umem.free(addr);
            }

            self.ring.release(actual as _);
        }

        actual
    }

    /// The same as [`Self::dequeue`], except the timestamp each frame was
    /// transmitted is written to the provided slice.
    ///
    /// Note this requires that [`Frame::set_tx_metadata`] was called
    pub fn dequeue_with_timestamps(&mut self, umem: &mut Umem, timestamps: &mut [u64]) -> usize {
        let requested = timestamps.len();
        if requested == 0 {
            return 0;
        }

        let (actual, idx) = self.ring.peek(requested as _);

        if actual > 0 {
            let mask = self.ring.mask();
            for (ts, i) in timestamps.iter_mut().zip(idx..idx + actual) {
                let addr = self.ring[i & mask];
                *ts = umem.free_get_timestamp(addr);
            }

            self.ring.release(actual as _);
        }

        actual
    }
}
