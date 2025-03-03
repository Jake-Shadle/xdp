//! Utilities for raw [`Packet`] reading and writing

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod csum;
pub mod net_types;

use crate::libc;
use std::fmt;

/// Errors that can occur when reading/writing [`Packet`] contents
#[derive(Debug)]
pub enum PacketError {
    /// The packet head could not be moved down as there was not enough headroom
    InsufficientHeadroom {
        /// The amount of bytes that the head attempted to move down
        diff: usize,
        /// The head position
        head: usize,
    },
    /// Attempted to move the head past the tail, or the tail past the end of the
    /// packet's maximum
    InvalidPacketLength {},
    /// Attempted to get or set data at an invalid offset
    InvalidOffset {
        /// The invalid offset
        offset: usize,
        /// The length the offset must be below
        length: usize,
    },
    /// Attempt to retrieve data outside the bounds of the currently valid contents
    InsufficientData {
        /// The offset the data would start at
        offset: usize,
        /// The size of the data requested
        size: usize,
        /// The length of the actual valid contents
        length: usize,
    },
    /// TX checksum offload is not supported
    ChecksumUnsupported,
    /// TX timestamp is not supported
    TimestampUnsupported,
}

impl PacketError {
    /// Gets a static string description of the error
    #[inline]
    pub fn discriminant(&self) -> &'static str {
        match self {
            Self::InsufficientHeadroom { .. } => "insufficient headroom",
            Self::InvalidPacketLength {} => "invalid packet length",
            Self::InvalidOffset { .. } => "invalid offset",
            Self::InsufficientData { .. } => "insufficient data",
            Self::ChecksumUnsupported => "TX checksum unsupported",
            Self::TimestampUnsupported => "TX timestamp unsupported",
        }
    }
}

impl std::error::Error for PacketError {}

impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Marker trait used to indicate the type is a POD and can be safely converted
/// to and from raw bytes
///
/// # Safety
///
/// See [`std::mem::zeroed`]
pub unsafe trait Pod: Sized {
    /// Gets the size of the type in bytes
    #[inline]
    fn size() -> usize {
        std::mem::size_of::<Self>()
    }

    /// Gets a zeroed [`Self`]
    #[inline]
    fn zeroed() -> Self {
        // SAFETY: by implementing Pod the user is saying that an all zero block
        // is a valid representation of this type
        unsafe { std::mem::zeroed() }
    }

    /// Gets [`Self`] as a byte slice
    #[inline]
    fn as_bytes(&self) -> &[u8] {
        // SAFETY: by implementing Pod the user is saying that the struct can be
        // represented safely by a byte slice
        unsafe {
            std::slice::from_raw_parts((self as *const Self).cast(), std::mem::size_of::<Self>())
        }
    }
}

/// Configures TX checksum offload when setting TX metadata via [`Packet::set_tx_metadata`]
pub enum CsumOffload {
    /// Requests checksum offload
    Request(libc::xdp::xsk_tx_request),
    /// Offload is not requested
    None,
}

/// A packet of data which can be received by the kernel or sent by userspace
///
/// ```text
/// ┌──────────────────┌─────────────────┌───────────────────────┌─────────────┐
/// │headroom (kernel) │headroom (opt)   │packet                 │remainder    │
/// └──────────────────└─────────────────└───────────────────────└─────────────┘
///                                      ▲                       ▲              
///                                      │                       │              
///                                      │                       │              
///                                      head                    tail           
/// ```
///
/// 1. The first ([`libc::xdp::XDP_PACKET_HEADROOM`]) segment of the buffer is
///     reserved for kernel usage
/// 1. `headroom` is an optional segment that can be configured on the [`crate::umem::UmemCfgBuilder::head_room`]
///     the packet is allocated from which the kernel will not fill with data,
///     allowing the packet to grow downwards (eg. IPv4 -> IPv6) without copying
///     bytes
/// 1. The next segment is the actual packet contents as received by the NIC or
///     sent by userspace
/// 1. The last segment is the uninitialized portion of the chunk occupied by this
///     packet, up to the size configured on the owning [`crate::Umem`].
///
/// The packet portion of the packet is then composed of the various layers/data,
/// for example an IPv4 UDP packet:
///
/// ```text
/// ┌───────────────┌────────────────────┌────────┌──────────┐    
/// │ethernet       │ipv4                │udp     │data...   │    
/// └───────────────└────────────────────└────────└──────────┘    
/// ▲               ▲                    ▲        ▲          ▲    
/// │               │                    │        │          │    
/// │               │                    │        │          │    
///  head            +14                  +34      +42        tail
/// ```
pub struct Packet {
    /// The entire packet buffer, including headroom, initialized packet contents,
    /// and uninitialized/empty remainder
    pub(crate) data: *mut u8,
    pub(crate) capacity: usize,
    /// The offset in data where the packet starts
    pub(crate) head: usize,
    /// The offset in data where the packet ends
    pub(crate) tail: usize,
    pub(crate) base: *const u8,
    pub(crate) options: u32,
}

impl Packet {
    /// Only used for testing
    #[doc(hidden)]
    pub fn testing_new(buf: &mut [u8; 2 * 1024]) -> Self {
        let data = &mut buf[libc::xdp::XDP_PACKET_HEADROOM as usize..];
        Self {
            data: data.as_mut_ptr(),
            capacity: data.len(),
            head: 0,
            tail: 0,
            base: std::ptr::null(),
            options: 0,
        }
    }

    /// The number of initialized/valid bytes in the packet
    #[inline]
    pub fn len(&self) -> usize {
        self.tail - self.head
    }

    /// True if the packet is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.head == self.tail
    }

    /// The total capacity of the packet.
    ///
    /// Note that this never includes the [`libc::xdp::XDP_PACKET_HEADROOM`]
    /// part of every packet
    #[inline]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Resets the tail of this packet, causing it to become empty
    #[inline]
    pub fn clear(&mut self) {
        self.tail = self.head;
    }

    /// If true, this packet is partial, and the next packet in the RX continues
    /// this packet, until this returns fals
    #[inline]
    pub fn is_continued(&self) -> bool {
        (self.options & libc::xdp::XdpPktOptions::XDP_PKT_CONTD) != 0
    }

    /// Checks if the NIC this packet is being sent on supports tx checksum offload
    ///
    /// TODO: Create a different type to indicate checksum since it's not going
    /// to change so the user can choose at init time whether they want checksum
    /// offload or not
    #[inline]
    pub fn can_offload_checksum(&self) -> bool {
        (self.options & libc::InternalXdpFlags::SUPPORTS_CHECKSUM_OFFLOAD) != 0
    }

    /// Adjust the head of the packet up or down by `diff` bytes
    ///
    /// This method is the equivalent of [`bpf_xdp_adjust_head`](https://docs.ebpf.io/linux/helper-function/bpf_xdp_adjust_head/),
    /// allowing modification of layers (eg. layer 3 IPv4 <-> IPv6) without needing
    /// to copy the entirety of the packet data up or down.
    ///
    /// Adjusting the head down requires that headroom was configured for the [`crate::Umem`]
    #[inline]
    pub fn adjust_head(&mut self, diff: i32) -> Result<(), PacketError> {
        if diff < 0 {
            let diff = diff.unsigned_abs() as usize;
            if diff > self.head {
                return Err(PacketError::InsufficientHeadroom {
                    diff,
                    head: self.head,
                });
            }

            self.head -= diff;
        } else {
            let diff = diff as usize;
            if self.head + diff > self.tail {
                return Err(PacketError::InvalidPacketLength {});
            }

            self.head += diff;
        }

        Ok(())
    }

    /// Adjust the tail of the packet up or down by `diff` bytes
    ///
    /// This method is the equivalent of [`bpf_xdp_adjust_tail`](https://docs.ebpf.io/linux/helper-function/bpf_xdp_adjust_tail/),
    /// and allows extending or truncating the data portion of a packet
    #[inline]
    pub fn adjust_tail(&mut self, diff: i32) -> Result<(), PacketError> {
        if diff < 0 {
            let diff = diff.unsigned_abs() as usize;
            if diff > self.tail || self.tail - diff < self.head {
                return Err(PacketError::InsufficientHeadroom {
                    diff,
                    head: self.head,
                });
            }

            self.tail -= diff;
        } else {
            let diff = diff as usize;
            if self.tail + diff > self.capacity {
                return Err(PacketError::InvalidPacketLength {});
            }

            self.tail += diff;
        }

        Ok(())
    }

    /// Reads a `T` at the specified offset
    ///
    /// # Errors
    ///
    /// - The offset is not within bounds
    /// - The offset + size of `T` is not within bounds
    #[inline]
    pub fn read<T: Pod>(&self, offset: usize) -> Result<T, PacketError> {
        let start = self.head + offset;
        if start > self.tail {
            return Err(PacketError::InvalidOffset {
                offset,
                length: self.tail - self.head,
            });
        }

        let size = std::mem::size_of::<T>();
        if start + size > self.tail {
            return Err(PacketError::InsufficientData {
                offset,
                size,
                length: self.tail - offset,
            });
        }

        // SAFETY: we've validated the pointer read is within bounds
        Ok(unsafe { std::ptr::read_unaligned(self.data.byte_offset(start as _).cast()) })
    }

    /// Writes the contents of `item` at the specified `offset`
    ///
    /// This does an in-place write, memory above or below `[offset..offset + sizeof(T)]`
    /// is not affected
    ///
    /// # Errors
    ///
    /// - The offset is not within bounds
    /// - The offset + size of `T` is not within bounds
    #[inline]
    pub fn write<T: Pod>(&mut self, offset: usize, item: T) -> Result<(), PacketError> {
        let start = self.head + offset;
        if start > self.tail {
            return Err(PacketError::InvalidOffset {
                offset,
                length: self.tail - self.head,
            });
        }

        let size = std::mem::size_of::<T>();
        if start + size > self.tail {
            return Err(PacketError::InsufficientData {
                offset,
                size,
                length: self.tail - offset,
            });
        }

        // SAFETY: we've validated the pointer write is within bounds
        unsafe {
            std::ptr::write_unaligned(
                self.data.byte_offset((self.head + offset) as _).cast(),
                item,
            );
        }
        Ok(())
    }

    /// Retrieves a fixed size array of bytes beginning at the specified offset
    ///
    /// # Errors
    ///
    /// - The offset is not within bounds
    /// - The offset + `N` is not within bounds
    #[inline]
    pub fn array_at_offset<const N: usize>(
        &self,
        offset: usize,
        array: &mut [u8; N],
    ) -> Result<(), PacketError> {
        let start = self.head + offset;
        if start + N > self.tail {
            return Err(PacketError::InsufficientData {
                offset,
                size: N,
                length: self.tail - offset,
            });
        }

        // SAFETY: we've validated the range of data we are reading is valid
        unsafe {
            std::ptr::copy_nonoverlapping(
                self.data.byte_offset(offset as _),
                array.as_mut_ptr(),
                N,
            );
        }
        Ok(())
    }

    /// Inserts a slice at the specified offset, shifting any bytes above `offset`
    /// upwards by `slice.len()`
    ///
    /// # Errors
    ///
    /// - The offset is not within bounds
    /// - The offset + `slice.len()` would exceed the capacity
    #[inline]
    pub fn insert(&mut self, offset: usize, slice: &[u8]) -> Result<(), PacketError> {
        if self.tail + slice.len() > self.capacity {
            return Err(PacketError::InvalidPacketLength {});
        } else if offset > self.tail {
            return Err(PacketError::InvalidOffset {
                offset,
                length: self.len(),
            });
        }

        let adjusted_offset = self.head + offset;
        let shift = self.tail + self.head - adjusted_offset;

        // SAFETY: we validate we're within bounds before doing any writes to the
        // pointer, which is alive as long as the owning mmap
        unsafe {
            if shift > 0 {
                std::ptr::copy(
                    self.data.byte_offset(adjusted_offset as isize),
                    self.data
                        .byte_offset((adjusted_offset + slice.len()) as isize),
                    shift,
                );
            }

            std::ptr::copy_nonoverlapping(
                slice.as_ptr(),
                self.data.byte_offset(adjusted_offset as _),
                slice.len(),
            );
        }

        self.tail += slice.len();
        Ok(())
    }

    /// Sets the specified [TX metadata](https://github.com/torvalds/linux/blob/ae90f6a6170d7a7a1aa4fddf664fbd093e3023bc/Documentation/networking/xsk-tx-metadata.rst)
    ///
    /// Calling this function requires that the [`crate::umem::UmemCfgBuilder::tx_metadata`]
    /// was true.
    ///
    /// - If `csum` is `CsumOffload::Request`, this will request that the Layer 4
    ///     checksum computation be offload to the NIC before transmission. Note that
    ///     this requires that the IP pseudo header checksum be calculated and stored
    ///     in the same location.
    /// - If `request_timestamp` is true, requests that the NIC write the timestamp
    ///     the packet was transmitted. This can be retrieved using [`crate::CompletionRing::dequeue_with_timestamps`]
    #[inline]
    pub fn set_tx_metadata(
        &mut self,
        csum: CsumOffload,
        request_timestamp: bool,
    ) -> Result<(), PacketError> {
        use libc::xdp;

        // This would mean the user is making a request that won't actually do anything
        debug_assert!(request_timestamp || matches!(csum, CsumOffload::Request { .. }));

        if matches!(csum, CsumOffload::Request { .. })
            && (self.options & libc::InternalXdpFlags::SUPPORTS_CHECKSUM_OFFLOAD) == 0
        {
            return Err(PacketError::ChecksumUnsupported);
        } else if request_timestamp
            && (self.options & libc::InternalXdpFlags::SUPPORTS_TIMESTAMP) == 0
        {
            return Err(PacketError::TimestampUnsupported);
        }

        // SAFETY: While this looks pretty dangerous because we are getting a pointer
        // before the base packet, it's actually safe as the presence of either the
        // checksum offload or timestamp flags means the umem was registered with
        // space for an xsk_tx_metadata that the kernel will also know the location
        // of
        unsafe {
            let mut tx_meta = std::mem::zeroed::<xdp::xsk_tx_metadata>();

            if let CsumOffload::Request(csum_req) = csum {
                tx_meta.flags |= xdp::XdpTxFlags::XDP_TXMD_FLAGS_CHECKSUM;
                tx_meta.offload.request = csum_req;
            }

            if request_timestamp {
                tx_meta.flags |= xdp::XdpTxFlags::XDP_TXMD_FLAGS_TIMESTAMP;
            }

            std::ptr::write_unaligned(
                self.data
                    .byte_offset(
                        self.head as isize - std::mem::size_of::<xdp::xsk_tx_metadata>() as isize,
                    )
                    .cast(),
                tx_meta,
            );
        }

        self.options |= xdp::XdpPktOptions::XDP_TX_METADATA;

        Ok(())
    }

    #[doc(hidden)]
    #[inline]
    pub fn inner_copy(&mut self) -> Self {
        Self {
            data: self.data,
            capacity: self.capacity,
            head: self.head,
            tail: self.tail,
            base: self.base,
            options: self.options,
        }
    }
}

impl std::ops::Deref for Packet {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        // SAFETY: the pointer is valid as long as the mmap is alive
        unsafe { &std::slice::from_raw_parts(self.data, self.capacity)[self.head..self.tail] }
    }
}

impl std::ops::DerefMut for Packet {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: the pointer is valid as long as the mmap is alive
        unsafe {
            &mut std::slice::from_raw_parts_mut(self.data, self.capacity)[self.head..self.tail]
        }
    }
}

impl From<Packet> for libc::xdp::xdp_desc {
    fn from(packet: Packet) -> Self {
        libc::xdp::xdp_desc {
            // SAFETY: the pointer is valid as long as the mmap it is allocated
            // from is alive
            addr: unsafe {
                packet
                    .data
                    .byte_offset(packet.head as _)
                    .offset_from(packet.base) as _
            },
            len: (packet.tail - packet.head) as _,
            options: packet.options & !libc::InternalXdpFlags::MASK,
        }
    }
}

impl std::io::Write for Packet {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self.insert(self.tail - self.head, buf) {
            Ok(()) => Ok(buf.len()),
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::StorageFull,
                "not enough space available in packet",
            )),
        }
    }

    #[inline]
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
