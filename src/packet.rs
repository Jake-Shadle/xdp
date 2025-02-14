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
        unsafe { std::mem::zeroed() }
    }

    /// Gets [`Self`] as a byte slice
    #[inline]
    fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts((self as *const Self).cast(), std::mem::size_of::<Self>())
        }
    }
}

const fn tx_metadata_diff() -> i32 {
    -(std::mem::size_of::<libc::xdp::xsk_tx_metadata>() as i32)
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
///
///
pub struct Packet {
    /// The entire packet buffer, including headroom, initialized packet contents,
    /// and uninitialized/empty remainder
    pub(crate) data: &'static mut [u8],
    /// The offset in data where the packet starts
    pub(crate) head: usize,
    /// The offset in data where the packet ends
    pub(crate) tail: usize,
    pub(crate) base: *const u8,
    pub(crate) options: u32,
}

impl Packet {
    /// Only used for testing
    pub fn testing_new(buf: &mut [u8]) -> Self {
        assert_eq!(buf.len(), 2 * 1024);
        unsafe {
            Self {
                data: std::mem::transmute::<&mut [u8], &'static mut [u8]>(buf),
                head: libc::xdp::XDP_PACKET_HEADROOM as _,
                tail: libc::xdp::XDP_PACKET_HEADROOM as _,
                base: std::ptr::null(),
                options: 0,
            }
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
        self.data.len()
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
        (self.options & libc::InternalXdpFlags::SupportsChecksumOffload as u32) != 0
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
            if self.tail + diff > self.data.len() {
                return Err(PacketError::InvalidPacketLength {});
            }

            self.tail += diff;
        }

        Ok(())
    }

    /// Retrieves a `T` beginning at the specified offset
    ///
    /// # Errors
    ///
    /// - The offset is not within bounds
    /// - The offset + size of `T` is not within bounds
    #[inline]
    pub fn item_at_offset<T: Pod>(&self, offset: usize) -> Result<&T, PacketError> {
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

        Ok(unsafe { &*(self.data.as_ptr().byte_offset(start as _).cast()) })
    }

    /// Retrieves a mutable `T` beginning at the specified offset
    ///
    /// # Errors
    ///
    /// - The offset is not within bounds
    /// - The offset + size of `T` is not within bounds
    #[inline]
    pub fn item_at_offset_mut<T: Pod>(&mut self, offset: usize) -> Result<&mut T, PacketError> {
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

        Ok(unsafe {
            &mut *(self
                .data
                .as_mut_ptr()
                .byte_offset((self.head + offset) as _)
                .cast())
        })
    }

    /// Retrieves a slice of bytes beginning at the specified offset
    ///
    /// # Errors
    ///
    /// - The offset is not within bounds
    /// - The offset + len is not within bounds
    #[inline]
    pub fn slice_at_offset(&self, offset: usize, len: usize) -> Result<&[u8], PacketError> {
        let start = self.head + offset;
        if start > self.tail {
            return Err(PacketError::InvalidOffset {
                offset,
                length: self.tail - self.head,
            });
        }

        if start + len > self.tail {
            return Err(PacketError::InsufficientData {
                offset,
                size: len,
                length: self.tail - offset,
            });
        }

        Ok(&self.data[start..start + len])
    }

    /// Retrieves a mutable slice of bytes beginning at the specified offset
    ///
    /// # Errors
    ///
    /// - The offset is not within bounds
    /// - The offset + len is not within bounds
    #[inline]
    pub fn slice_at_offset_mut(
        &mut self,
        offset: usize,
        len: usize,
    ) -> Result<&mut [u8], PacketError> {
        let start = self.head + offset;
        if start + len > self.tail {
            return Err(PacketError::InsufficientData {
                offset,
                size: len,
                length: self.tail - offset,
            });
        }

        Ok(&mut self.data[start..start + len])
    }

    /// Retrieves a fixed size array of bytes beginning at the specified offset
    ///
    /// # Errors
    ///
    /// - The offset is not within bounds
    /// - The offset + `N` is not within bounds
    #[inline]
    pub fn array_at_offset<const N: usize>(&self, offset: usize) -> Result<[u8; N], PacketError> {
        let start = self.head + offset;
        if start + N > self.tail {
            return Err(PacketError::InsufficientData {
                offset,
                size: N,
                length: self.tail - offset,
            });
        }

        let mut data = [0u8; N];
        data.copy_from_slice(&self.data[start..start + N]);
        Ok(data)
    }

    /// Inserts a slice at the specified offset, shifting any bytes above offset
    /// by `slice.len()`
    ///
    /// # Errors
    ///
    /// - The offset is not within bounds
    /// - The offset + `slice.len()` would exceed the capacity
    #[inline]
    pub fn insert(&mut self, offset: usize, slice: &[u8]) -> Result<(), PacketError> {
        if self.tail + slice.len() > self.data.len() {
            return Err(PacketError::InvalidPacketLength {});
        }

        let adjusted_offset = self.head + offset;
        let shift = self.tail + self.head - adjusted_offset;
        if shift > 0 {
            unsafe {
                std::ptr::copy(
                    self.data.as_ptr().byte_offset(adjusted_offset as isize),
                    self.data
                        .as_mut_ptr()
                        .byte_offset((adjusted_offset + slice.len()) as isize),
                    shift,
                );
            }
        }

        self.data[adjusted_offset..adjusted_offset + slice.len()].copy_from_slice(slice);
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

        // This would mean the user is requesting to set tx metadata...but not actually do anything
        debug_assert!(request_timestamp || matches!(csum, CsumOffload::Request { .. }));

        self.adjust_head(tx_metadata_diff())?;
        {
            let tx_meta = self.item_at_offset_mut::<xdp::xsk_tx_metadata>(0)?;
            tx_meta.flags = 0;
            tx_meta.offload.completion = 0;

            if let CsumOffload::Request(csum_req) = csum {
                tx_meta.flags |= xdp::XdpTxFlags::XDP_TXMD_FLAGS_CHECKSUM;
                tx_meta.offload.request = csum_req;
            }

            if request_timestamp {
                tx_meta.flags |= xdp::XdpTxFlags::XDP_TXMD_FLAGS_TIMESTAMP;
            }
        }
        self.adjust_head(-tx_metadata_diff())?;
        self.options |= xdp::XdpPktOptions::XDP_TX_METADATA;

        Ok(())
    }
}

impl std::ops::Deref for Packet {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.data[self.head..self.tail]
    }
}

impl From<Packet> for libc::xdp::xdp_desc {
    fn from(packet: Packet) -> Self {
        libc::xdp::xdp_desc {
            addr: unsafe {
                packet
                    .data
                    .as_ptr()
                    .byte_offset(packet.head as _)
                    .offset_from(packet.base) as _
            },
            len: (packet.tail - packet.head) as _,
            options: packet.options & !(libc::InternalXdpFlags::Mask as u32),
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
