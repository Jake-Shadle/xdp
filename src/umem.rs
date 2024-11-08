use crate::error::{ConfigError, Error};
use std::collections::VecDeque;

pub const XSK_UMEM_DEFAULT_FRAME_SIZE: u32 = 4096;
/// The size in bytes of the [headroom](https://github.com/torvalds/linux/blob/ae90f6a6170d7a7a1aa4fddf664fbd093e3023bc/include/uapi/linux/bpf.h#L6432) reserved by the kernel for each xdp frame
pub const XDP_PACKET_HEADROOM: u64 = 256;

/// The frame size (`libc::xdp_umem_reg::chunk_size`) can only be [>=2048 or <=4096](https://github.com/torvalds/linux/blob/c2ee9f594da826bea183ed14f2cc029c719bf4da/Documentation/networking/af_xdp.rst#xdp_umem_reg-setsockopt)
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
            //frame_count: cfg.frame_count as _,
        })
    }

    #[inline]
    pub fn frame(&self, desc: libc::xdp_desc) -> crate::Frame<'_> {
        // SAFETY: Barring kernel bugs, we should only ever get valid addresses
        // within the range of our map
        unsafe {
            let addr = self
                .mmap
                .as_ptr()
                .byte_offset((desc.addr - self.head_room as u64) as _)
                as *mut u8;
            let data = std::slice::from_raw_parts_mut(addr, self.frame_size);

            crate::Frame {
                data,
                head: self.head_room,
                tail: self.head_room + desc.len as usize,
                base: self.mmap.as_ptr(),
                has_tx_metadata: false,
            }
        }
    }

    #[inline]
    pub fn alloc(&mut self) -> crate::Frame<'_> {
        let addr = self.available.pop_front().unwrap();

        unsafe {
            let addr = self
                .mmap
                .as_ptr()
                .byte_offset((addr + XDP_PACKET_HEADROOM) as _) as *mut u8;
            let data = std::slice::from_raw_parts_mut(addr, self.frame_size);

            crate::Frame {
                data,
                head: 0,
                tail: 0,
                base: self.mmap.as_ptr(),
                has_tx_metadata: false,
            }
        }
    }

    #[inline]
    pub(crate) fn free(&mut self, address: u64) {
        self.available.push_front(address & self.frame_mask);
    }

    #[inline]
    pub(crate) fn free_get_timestamp(&mut self, address: u64) -> u64 {
        let align_offset = address % self.frame_size as u64;
        let timestamp = if align_offset >= std::mem::size_of::<crate::frame::XskTxMetadata>() as u64
        {
            unsafe {
                let tx_meta = &*(self.mmap.as_ptr().byte_offset(
                    (address - std::mem::size_of::<crate::frame::XskTxMetadata>() as u64) as _,
                ) as *const crate::frame::XskTxMetadata);
                tx_meta.which.timestamp
            }
        } else {
            0
        };

        self.free(address);
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

impl<'umem> UmemPopper<'umem> {
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
    /// The size of each frame/chunk. Defaults to 4096.
    pub frame_size: FrameSize,
    /// The size of the headroom, an offset from the beginning of the frame
    /// which the kernel will not write data to. Defaults to 0.
    pub head_room: u32,
    /// The number of total frames. Defaults to 8192.
    pub frame_count: u32,
    /// If true, the [`Umem`] will be registered with the socket with an additional
    ///
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
            0..(frame_size - XDP_PACKET_HEADROOM as u32) as _
        );
        let frame_count = crate::within_range!(self, frame_count, 1..u32::MAX as _);

        Ok(UmemCfg {
            frame_size,
            frame_count,
            head_room,
        })
    }
}

pub struct UmemCfg {
    frame_size: u32,
    frame_count: u32,
    head_room: u32,
}
