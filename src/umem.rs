use crate::{
    bindings::{self, xdp_desc},
    error::{ConfigError, Error},
    Packet,
};
use std::collections::VecDeque;

/// The packet size (`libc::xdp_umem_reg::chunk_size`) can only be [>=2048 or <=4096](https://github.com/torvalds/linux/blob/c2ee9f594da826bea183ed14f2cc029c719bf4da/Documentation/networking/af_xdp.rst#xdp_umem_reg-setsockopt)
///
/// Note: [Kernel source](https://github.com/torvalds/linux/blob/ae90f6a6170d7a7a1aa4fddf664fbd093e3023bc/net/xdp/xdp_umem.c#L166-L174)
#[derive(Copy, Clone)]
pub enum FrameSize {
    /// The minimum size
    TwoK,
    /// The maximum size, same as `PAGE_SIZE`
    FourK,
    // Non power of sizes are allowed, but forces the [`Umem`] to use huge tables
    //Unaligned(usize),
}

impl TryFrom<FrameSize> for u32 {
    type Error = ConfigError;

    fn try_from(value: FrameSize) -> Result<Self, Self::Error> {
        let ret = match value {
            FrameSize::TwoK => 2048,
            FrameSize::FourK => 4096,
            //FrameSize::Unaligned(size) => {
            // TODO: Support unaligned frames, I don't particularly care about
            // it since 2k is plenty enough for my use case, and would mean
            // changing the easy masking of addresses currently done, as well
            // as require huge pages for the memory mapping

            //}
        };

        Ok(ret)
    }
}

pub struct Umem {
    pub(crate) mmap: memmap2::MmapMut,
    /// Frames available to be written to by the kernel or userspace
    available: VecDeque<u64>,
    pub(crate) frame_size: usize,
    frame_mask: u64,
    pub(crate) head_room: usize,
    pub(crate) tx_metadata: bool,
    //pub(crate) frame_count: usize,
}

impl Umem {
    pub fn map(cfg: UmemCfg) -> std::io::Result<Self> {
        let mmap = memmap2::MmapOptions::new()
            .len(cfg.frame_count as usize * cfg.frame_size as usize)
            .map_anon()?;

        let mut available = VecDeque::with_capacity(cfg.frame_count as _);
        let frame_size = cfg.frame_size as u64;
        available.extend((0..cfg.frame_count as u64).map(|i| i * frame_size));

        Ok(Self {
            mmap,
            available,
            frame_size: cfg.frame_size as _,
            frame_mask: !(cfg.frame_size as u64 - 1),
            head_room: cfg.head_room as _,
            tx_metadata: cfg.tx_metadata,
            //frame_count: cfg.frame_count as _,
        })
    }

    /// Given an [`xdp_desc`] filled by the kernel, retrieves the memory block
    /// it points to as a [`Packet`]
    ///
    /// # Safety
    ///
    /// The [`Packet`] returned by this function is pointing to memory owned by
    /// this [`Umem`], it must not outlive this [`Umem`]
    #[inline]
    pub unsafe fn packet(&self, desc: xdp_desc) -> Packet {
        // SAFETY: Barring kernel bugs, we should only ever get valid addresses
        // within the range of our map
        unsafe {
            let addr = self
                .mmap
                .as_ptr()
                .byte_offset((desc.addr - self.head_room as u64) as _)
                as *mut u8;
            let data = std::slice::from_raw_parts_mut(addr, self.frame_size);

            Packet {
                data,
                head: self.head_room,
                tail: self.head_room + desc.len as usize,
                base: self.mmap.as_ptr(),
                options: desc.options,
            }
        }
    }

    /// Attempts to allocate a packet from the [`Umem`], returning `None` if there
    /// are no available frames.
    ///
    /// # Safety
    ///
    /// The [`Frame`] returned by this function is pointing to memory owned by
    /// this [`Umem`], it must not outlive this [`Umem`]
    #[inline]
    pub unsafe fn alloc(&mut self) -> Option<Packet> {
        let addr = self.available.pop_front()?;

        unsafe {
            let addr = self
                .mmap
                .as_ptr()
                .byte_offset((addr + bindings::XDP_PACKET_HEADROOM) as _)
                as *mut u8;
            let data = std::slice::from_raw_parts_mut(addr, self.frame_size);

            Some(Packet {
                data,
                head: self.head_room,
                tail: self.head_room,
                base: self.mmap.as_ptr(),
                options: 0,
            })
        }
    }

    /// Given an address offset, adds the packet it points to to the free list
    ///
    /// This function assumes that frames are power of 2, and thus it doesn't
    /// matter where the offset is relative to the packet offset
    #[inline]
    pub(crate) fn free_addr(&mut self, address: u64) {
        self.available.push_front(address & self.frame_mask);
    }

    #[inline]
    pub fn free_packet(&mut self, packet: Packet) {
        self.free_addr(unsafe {
            packet
                .data
                .as_ptr()
                .byte_offset(packet.head as _)
                .offset_from(packet.base) as _
        });
    }

    #[inline]
    pub(crate) fn free_get_timestamp(&mut self, address: u64) -> u64 {
        let align_offset = address % self.frame_size as u64;
        let timestamp = if align_offset >= std::mem::size_of::<bindings::xsk_tx_metadata>() as u64 {
            unsafe {
                let tx_meta = &*(self.mmap.as_ptr().byte_offset(
                    (address - std::mem::size_of::<bindings::xsk_tx_metadata>() as u64) as _,
                ) as *const bindings::xsk_tx_metadata);
                tx_meta.offload.completion
            }
        } else {
            0
        };

        self.free_addr(address);
        timestamp
    }

    #[inline]
    pub(crate) fn popper(&mut self) -> UmemPopper<'_> {
        UmemPopper {
            available: &mut self.available,
        }
    }
}

pub(crate) struct UmemPopper<'umem> {
    available: &'umem mut VecDeque<u64>,
}

impl UmemPopper<'_> {
    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.available.len()
    }

    #[inline]
    pub(crate) fn pop(&mut self) -> u64 {
        let Some(addr) = self.available.pop_front() else {
            unreachable!()
        };
        addr
    }
}

/// Builder for a [`Umem`].
///
/// Using [`UmemCfgBuilder::Default`] will result in a [`Umem`] with 8k frames of
/// size 4k for a total of 32MiB.
pub struct UmemCfgBuilder {
    /// The size of each packet/chunk. Defaults to 4096.
    pub frame_size: FrameSize,
    /// The size of the headroom, an offset from the beginning of the packet
    /// which the kernel will not write data to. Defaults to 0.
    pub head_room: u32,
    /// The number of total frames. Defaults to 8192.
    pub frame_count: u32,
    /// If true, the [`Umem`] will be registered with the socket with an
    /// additional section before the packet that may be filled with TX metadata
    /// that either request a checksum be calculated by the NIC, and/or that the
    /// transmission timestamp is set before being added to the completion queue
    pub tx_metadata: bool,
}

impl Default for UmemCfgBuilder {
    fn default() -> Self {
        Self {
            frame_size: FrameSize::FourK, // XSK_UMEM_DEFAULT_FRAME_SIZE
            head_room: 0,
            frame_count: 8 * 1024,
            tx_metadata: false,
        }
    }
}

impl UmemCfgBuilder {
    pub fn build(self) -> Result<UmemCfg, Error> {
        let frame_size = self.frame_size.try_into()?;

        let head_room = crate::within_range!(
            self,
            head_room,
            0..(frame_size - bindings::XDP_PACKET_HEADROOM as u32) as _
        );
        let frame_count = crate::within_range!(self, frame_count, 1..u32::MAX as _);

        Ok(UmemCfg {
            frame_size,
            frame_count,
            head_room,
            tx_metadata: self.tx_metadata,
        })
    }
}

#[derive(Copy, Clone)]
pub struct UmemCfg {
    frame_size: u32,
    frame_count: u32,
    head_room: u32,
    tx_metadata: bool,
}
