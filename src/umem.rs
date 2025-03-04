//! [`Umem`] creation and operation

use crate::{
    Packet,
    error::{ConfigError, Error},
    libc::{self, InternalXdpFlags, xdp::xdp_desc},
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

/// A memory region that is shared between kernel and userspace where packet
/// data can be written to (recv) and read from (send)
///
/// ```txt
/// ┌──────┌──────┌──────┌──────┌──────┌──────┌──────┐
/// │chunk0│chunk1│chunk2│chunk3│chunk4│chunk5│...   │
/// └──────└──────└──────└──────└──────└──────└──────┘
/// ```
///
/// A [`Umem`] can best be thought of as a specialized memory allocator that
/// is only capable of returning buffers of the same size, and cannot grow after
/// initialization.
///
/// This is the single source of `unsafe` that is exposed in the public API, along
/// with the [`crate::TxRing::send`], [`crate::RxRing::recv`], and
/// [`crate::FillRing::enqueue`] methods as it vastly simplifies the API to
/// require the user to guarantee that [`Packet`]s cannot outlive the [`Umem`]
/// they are allocated from
pub struct Umem {
    /// The actual memory mapping
    pub(crate) mmap: crate::mmap::Mmap,
    /// Addresses available to be written to by the kernel or userspace
    available: VecDeque<u64>,
    /// The size of each individual packet within the mapping
    pub(crate) frame_size: usize,
    /// Masked used to determine the true start address of a packet regardless
    /// of the address used when freeing the packet back to this Umem
    frame_mask: u64,
    /// The headroom configured for the Umem, a number of bytes (after the kernel
    /// reserved [`XDP_PACKET_HEADROOM`]) where the kernel will not place packet
    /// data when receiving, which allows the packet to grow downward when eg.
    /// changing from IPv4 -> IPv6 without needing to copying data upwards
    pub(crate) head_room: usize,
    /// Flags that control how the umem is registered and thus what capabilities
    /// each packet has
    pub(crate) options: InternalXdpFlags::Enum,
}

impl Umem {
    /// Attempts to build a [`Self`] by mapping a memory region
    ///
    /// # Examples
    ///
    /// ```
    /// let mut _umem = xdp::Umem::map(xdp::umem::UmemCfgBuilder::default().build().expect("failed to build umem cfg")).expect("failed to map memory");
    /// ```
    pub fn map(cfg: UmemCfg) -> std::io::Result<Self> {
        let mmap = crate::mmap::Mmap::map_umem(cfg.frame_count as usize * cfg.frame_size as usize)?;

        let mut available = VecDeque::with_capacity(cfg.frame_count as _);
        let frame_size = cfg.frame_size as u64;
        available.extend((0..cfg.frame_count as u64).map(|i| i * frame_size));

        Ok(Self {
            mmap,
            available,
            frame_size: cfg.frame_size as usize - libc::xdp::XDP_PACKET_HEADROOM as usize,
            frame_mask: cfg.frame_mask,
            head_room: cfg.head_room as _,
            options: cfg.options,
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
    pub(crate) unsafe fn packet(&self, desc: xdp_desc) -> Packet {
        // SAFETY: Barring kernel bugs, we should only ever get valid addresses
        // within the range of our map
        unsafe {
            let data = self
                .mmap
                .ptr
                .byte_offset((desc.addr - self.head_room as u64) as _);

            Packet {
                data,
                capacity: self.frame_size,
                head: self.head_room,
                tail: self.head_room + desc.len as usize,
                base: self.mmap.ptr,
                options: desc.options | self.options,
            }
        }
    }

    /// Attempts to allocate a packet from the [`Umem`], returning `None` if there
    /// are no available frames.
    ///
    /// # Safety
    ///
    /// The [`Packet`] returned by this function is pointing to memory owned by
    /// this [`Umem`], it must not outlive this [`Umem`]
    ///
    /// # Examples
    ///
    /// ```
    /// let mut umem = xdp::Umem::map(xdp::umem::UmemCfgBuilder::default().build().expect("failed to build umem cfg")).expect("failed to map memory");
    ///
    /// unsafe {
    ///     let mut packet = umem.alloc().expect("failed to allocate packet");
    ///     assert!(packet.is_empty());
    /// }
    /// ```
    #[inline]
    pub unsafe fn alloc(&mut self) -> Option<Packet> {
        let addr = self.available.pop_front()?;

        // SAFETY: The free list of addresses will always be within the range
        // of the mmap
        unsafe {
            let data = self
                .mmap
                .ptr
                .byte_offset((addr + libc::xdp::XDP_PACKET_HEADROOM) as _);

            Some(Packet {
                data,
                capacity: self.frame_size,
                head: self.head_room,
                tail: self.head_room,
                base: self.mmap.ptr,
                options: self.options,
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

    /// Returns the memory block where the [`Packet`] resides to the available
    /// pool for future use
    ///
    /// # Examples
    ///
    /// ```
    /// let mut umem = xdp::Umem::map(xdp::umem::UmemCfgBuilder {
    ///     frame_count: 1,
    ///     ..Default::default()
    /// }.build().expect("failed to build umem cfg")).expect("failed to map memory");
    ///
    /// unsafe {
    ///     let mut packet = umem.alloc().expect("failed to allocate packet");
    ///     packet.insert(0, &[1, 2, 3, 4]).expect("failed to insert bytes");
    ///     // Only 1 frame was requested when building the umem
    ///     assert!(umem.alloc().is_none());
    ///     umem.free_packet(packet);
    ///
    ///     let mut packet = umem.alloc().expect("failed to allocate packet");
    ///     // The packet will be the same memory region, but will be empty, but
    ///     // we can cheat and recover the data we wrote
    ///     packet.adjust_tail(4).unwrap();
    ///     assert_eq!(&packet[..4], &[1, 2, 3, 4]);
    /// }
    /// ```
    #[inline]
    pub fn free_packet(&mut self, packet: Packet) {
        debug_assert_eq!(
            packet.base, self.mmap.ptr,
            "the packet was not allocated from this Umem"
        );

        self.free_addr(
            // SAFETY: We've checked that the packet is owned by this Umem
            unsafe {
                packet
                    .data
                    .byte_offset(packet.head as _)
                    .offset_from(packet.base) as _
            },
        );
    }

    /// The equivalent of [`Self::free_addr`], but returns the timestamp the
    /// NIC recorded the send completed
    #[inline]
    pub(crate) fn free_get_timestamp(&mut self, address: u64) -> u64 {
        use libc::xdp::xsk_tx_metadata;

        let align_offset = address % self.frame_size as u64;
        let timestamp = if align_offset >= std::mem::size_of::<xsk_tx_metadata>() as u64 {
            // SAFETY: This is a pod, so even if this wasn't actually enabled when
            // the packet was enqueued, it shouldn't result in UB
            unsafe {
                let tx_meta = std::ptr::read_unaligned(
                    self.mmap
                        .ptr
                        .byte_offset((address - std::mem::size_of::<xsk_tx_metadata>() as u64) as _)
                        .cast::<xsk_tx_metadata>(),
                );
                tx_meta.offload.completion
            }
        } else {
            0
        };

        self.free_addr(address);
        timestamp
    }

    #[inline]
    pub(crate) fn available(&mut self) -> &mut VecDeque<u64> {
        &mut self.available
    }
}

/// Builder for a [`Umem`].
///
/// Using [`UmemCfgBuilder::default`] will result in a [`Umem`] with 8k frames of
/// size 4KiB for a total of 32MiB.
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
    /// that either request a checksum be calculated by the NIC
    pub tx_checksum: bool,
    /// If true, the [`Umem`] will be , and/or that the
    /// transmission timestamp is set before being added to the completion queue
    pub tx_timestamp: bool,
    /// For testing purposes only, enables the
    /// [`libc::xdp::UmemFlags::XDP_UMEM_TX_SW_CSUM`] flag so the checksum is
    /// calculated by the driver in software
    #[cfg(debug_assertions)]
    pub software_checksum: bool,
}

impl Default for UmemCfgBuilder {
    fn default() -> Self {
        Self {
            frame_size: FrameSize::FourK, // XSK_UMEM_DEFAULT_FRAME_SIZE
            head_room: 0,
            frame_count: 8 * 1024,
            tx_checksum: false,
            tx_timestamp: false,
            #[cfg(debug_assertions)]
            software_checksum: false,
        }
    }
}

impl UmemCfgBuilder {
    /// Creates a builder with TX checksum offload and/or timestamping if supported
    /// by the NIC
    ///
    /// # Examples
    ///
    /// ```no_run
    /// let nic = xdp::nic::NicIndex(0);
    /// let caps = nic.query_capabilities().expect("failed to query NIC capabilities");
    /// let _umem_cfg = xdp::umem::UmemCfgBuilder::new(caps.tx_metadata).build().expect("failed to build umem cfg");
    /// ```
    pub fn new(tx_flags: crate::nic::XdpTxMetadata) -> Self {
        Self {
            tx_checksum: tx_flags.checksum(),
            tx_timestamp: tx_flags.timestamp(),
            ..Default::default()
        }
    }

    /// Attempts build a [`UmemCfg`] that can be used with [`Umem::map`]
    ///
    /// # Examples
    ///
    /// ```
    /// let umem_cfg = xdp::umem::UmemCfgBuilder::default().build().expect("failed to build umem cfg");
    /// let umem = xdp::Umem::map(umem_cfg).expect("failed to map umem");
    /// ```
    pub fn build(self) -> Result<UmemCfg, Error> {
        let frame_size = self.frame_size.try_into()?;
        // For now we only allow 2k and 4k sizes, but if we supported unaligned
        // frames in the future we'd need to change this
        let frame_mask = !(frame_size as u64 - 1);

        let head_room = within_range!(
            self,
            head_room,
            0..(frame_size - libc::xdp::XDP_PACKET_HEADROOM as u32) as _
        );
        let frame_count = within_range!(self, frame_count, 1..u32::MAX as _);

        let total_size = frame_count as usize * frame_size as usize;
        if total_size > isize::MAX as usize {
            return Err(Error::Cfg(crate::error::ConfigError {
                name: "frame_count * frame_size",
                kind: crate::error::ConfigErrorKind::OutOfRange {
                    size: total_size,
                    range: frame_size as usize..isize::MAX as usize,
                },
            }));
        }

        let mut options = 0;
        if self.tx_checksum {
            options |= InternalXdpFlags::SUPPORTS_CHECKSUM_OFFLOAD;
        }
        if self.tx_timestamp {
            options |= InternalXdpFlags::SUPPORTS_TIMESTAMP;
        }
        #[cfg(debug_assertions)]
        if self.software_checksum {
            options |= InternalXdpFlags::USE_SOFTWARE_OFFLOAD;
        }

        Ok(UmemCfg {
            frame_size,
            frame_mask,
            frame_count,
            head_room,
            options,
        })
    }
}

/// The configuration used to create a [`Umem`]
#[derive(Copy, Clone)]
pub struct UmemCfg {
    frame_size: u32,
    frame_mask: u64,
    frame_count: u32,
    head_room: u32,
    options: InternalXdpFlags::Enum,
}
