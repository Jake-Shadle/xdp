//! The [`TxRing`] is a producer ring that userspace can enqueue packets to be
//! sent by the NIC the ring is bound to

use crate::{
    libc::{self, rings},
    slab::Slab,
};

/// The ring used to enqueue packets for the kernel to send
pub struct TxRing {
    ring: super::XskProducer<libc::xdp::xdp_desc>,
    _mmap: crate::mmap::Mmap,
}

impl TxRing {
    pub(crate) fn new(
        socket: std::os::fd::RawFd,
        cfg: &super::RingConfig,
        offsets: &rings::xdp_mmap_offsets,
    ) -> Result<Self, crate::socket::SocketError> {
        let (_mmap, mut ring) = super::map_ring(
            socket,
            cfg.tx_count,
            rings::RingPageOffsets::Tx,
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

    /// Enqueues packets to be sent by the kernel
    ///
    /// # Safety
    ///
    /// The [`crate::Umem`] that owns the packets being sent must outlive the `AF_XDP`
    /// socket
    ///
    /// # Returns
    ///
    /// The number of packets that were actually enqueued. This number can be
    /// lower than the requested `num_packets` if the ring doesn't have sufficient
    /// capacity
    pub unsafe fn send<S: Slab>(&mut self, packets: &mut S) -> usize {
        let requested = packets.len();
        if requested == 0 {
            return 0;
        }

        let (actual, idx) = self.ring.reserve(requested as _);

        if actual > 0 {
            for i in idx..idx + actual {
                let Some(packet) = packets.pop_back() else {
                    unreachable!()
                };

                self.ring.set(i, packet.into());
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
        offsets: &rings::xdp_mmap_offsets,
    ) -> Result<Self, crate::socket::SocketError> {
        let inner = TxRing::new(socket, cfg, offsets)?;
        Ok(Self { inner, socket })
    }

    /// Enqueues packets to be sent by the kernel
    ///
    /// # Safety
    ///
    /// The [`crate::Umem`] that owns the packets being sent must outlive the `AF_XDP`
    /// socket
    ///
    /// # Returns
    ///
    /// The number of packets that were actually enqueued. This number can be
    /// lower than the requested `num_packets` if the ring doesn't have sufficient
    /// capacity
    pub unsafe fn send<S: Slab>(
        &mut self,
        packets: &mut S,
        wakeup: bool,
    ) -> std::io::Result<usize> {
        // SAFETY: TxRing::send is unsafe
        let queued = unsafe { self.inner.send(packets) };

        if queued > 0 && wakeup {
            // SAFETY: This is safe, even if the socket descriptor is invalid.
            let ret = unsafe {
                libc::socket::sendto(
                    self.socket,
                    std::ptr::null_mut(),
                    0,
                    libc::socket::MsgFlags::DONTWAIT,
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
