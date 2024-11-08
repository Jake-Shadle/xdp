use crate::{Frame, Slab, Umem};
use libc::xdp_desc;

/// Ring from which we can dequeue frames that have been filled by the kernel
pub struct RxRing {
    ring: super::XskConsumer<xdp_desc>,
    _mmap: memmap2::MmapMut,
}

impl RxRing {
    pub(crate) fn new(
        socket: std::os::fd::RawFd,
        cfg: &super::RingConfig,
        offsets: &libc::xdp_mmap_offsets,
    ) -> Result<Self, crate::socket::SocketError> {
        let (_mmap, mut ring) = super::map_ring(
            socket,
            cfg.rx_count,
            libc::XDP_PGOFF_RX_RING as _,
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

    pub fn recv<'umem>(&mut self, umem: &'umem Umem, frames: &mut Slab<Frame<'umem>>) -> usize {
        let nb = frames.available();
        if nb == 0 {
            return 0;
        }

        let (actual, idx) = self.ring.peek(nb as _);

        if actual > 0 {
            self.do_recv(actual, idx, umem, frames);
        }

        actual
    }

    #[inline]
    fn do_recv<'umem>(
        &mut self,
        actual: usize,
        idx: usize,
        umem: &'umem Umem,
        frames: &mut Slab<Frame<'umem>>,
    ) {
        let mask = self.ring.mask();
        for i in idx..idx + actual {
            let desc = self.ring[i & mask];

            // this should never happen
            assert!(desc.options & libc::XDP_PKT_CONTD == 0);

            frames.push_back(umem.frame(desc));
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
