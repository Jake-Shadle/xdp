#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod csum;
pub mod net_types;

use crate::bindings;
use std::fmt;

#[derive(Debug)]
pub enum FrameError {
    InsufficientHeadroom {
        diff: usize,
        head: usize,
    },
    InvalidPacketLength {},
    InvalidOffset {
        offset: usize,
        length: usize,
    },
    InsufficientData {
        offset: usize,
        size: usize,
        length: usize,
    },
}

impl std::error::Error for FrameError {}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Marker trait used to indicate the type is a POD and can be safely converted
/// to and from raw bytes
pub unsafe trait Pod: Sized {
    #[inline]
    fn size() -> usize {
        std::mem::size_of::<Self>()
    }

    #[inline]
    fn zeroed() -> Self {
        unsafe { std::mem::zeroed() }
    }

    #[inline]
    fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self as *const Self as *const u8,
                std::mem::size_of::<Self>(),
            )
        }
    }
}

const fn tx_metadata_diff() -> i32 {
    -(std::mem::size_of::<bindings::xsk_tx_metadata>() as i32)
}

pub enum CsumOffload {
    Request(bindings::xsk_tx_request),
    None,
}

/// A frame of data which can be received by the kernel or sent by userspace
///
/// ```text
/// ┌───────────────┌─────────────────────────────────────────────┌─────────────┐
/// │headroom       │packet                                       │remainder    │
/// └───────────────└─────────────────────────────────────────────└─────────────┘
///                 ▲                                             ▲              
///                 │                                             │              
///                 │                                             │              
///                 head                                          tail           
/// ```
///
/// The packet portion of the frame is then composed of the various layers/data,
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
pub struct Frame {
    /// The entire frame buffer, including headroom, initialized packet contents,
    /// and uninitialized/empty remainder
    pub(crate) data: &'static mut [u8],
    /// The offset in data where the packet starts
    pub(crate) head: usize,
    /// The offset in data where the packet ends
    pub(crate) tail: usize,
    pub(crate) base: *const u8,
    pub(crate) options: u32,
}

impl Frame {
    /// Only used for testing
    pub fn testing_new(buf: &mut [u8]) -> Self {
        assert_eq!(buf.len(), 2 * 1024);
        unsafe {
            Self {
                data: std::mem::transmute(buf),
                head: bindings::XDP_PACKET_HEADROOM as _,
                tail: bindings::XDP_PACKET_HEADROOM as _,
                base: std::ptr::null(),
                options: 0,
            }
        }
    }

    /// The number of initialized/valid bytes in the frame
    #[inline]
    pub fn len(&self) -> usize {
        self.tail - self.head
    }

    /// The total capacity of the frame.
    ///
    /// Note that this never includes the [`crate::bindings::XDP_PACKET_HEADROOM`]
    /// part of every frame
    #[inline]
    pub fn capacity(&self) -> usize {
        self.data.len()
    }

    /// If true, this frame is partial, and the next frame in the RX continues
    /// this frame, until this returns fals
    #[inline]
    pub fn is_continued(&self) -> bool {
        (self.options & bindings::XdpFlags::XDP_PKT_CONTD as u32) != 0
    }

    /// Checks if the NIC this frame is being sent on supports tx checksum offload
    ///
    /// TODO: Create a different type to indicate checksum since it's not going
    /// to change so the user can choose at init time whether they want checksum
    /// offload or not
    #[inline]
    pub fn can_offload_checksum(&self) -> bool {
        (self.options & bindings::InternalXdpFlags::SupportsChecksumOffload as u32) != 0
    }

    /// Adjust the head of the packet up or down by `diff` bytes
    ///
    /// This method is the equivalent of [`bpf_xdp_adjust_head`](https://docs.ebpf.io/linux/helper-function/bpf_xdp_adjust_head/),
    /// allowing modification of layers (eg. layer 3 IPv4 <-> IPv6) without needing
    /// to copy the entirety of the packet data up or down.
    ///
    /// Adjusting the head down requires that headroom was configured for the [`Umem`]
    #[inline]
    pub fn adjust_head(&mut self, diff: i32) -> Result<(), FrameError> {
        if diff < 0 {
            let diff = diff.unsigned_abs() as usize;
            if diff > self.head {
                return Err(FrameError::InsufficientHeadroom {
                    diff,
                    head: self.head,
                });
            }

            self.head -= diff;
        } else {
            let diff = diff as usize;
            if self.head + diff > self.tail {
                return Err(FrameError::InvalidPacketLength {});
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
    pub fn adjust_tail(&mut self, diff: i32) -> Result<(), FrameError> {
        if diff < 0 {
            let diff = diff.unsigned_abs() as usize;
            if diff > self.tail || self.tail - diff < self.head {
                return Err(FrameError::InsufficientHeadroom {
                    diff,
                    head: self.head,
                });
            }

            self.tail -= diff;
        } else {
            let diff = diff as usize;
            if self.tail + diff > self.data.len() {
                return Err(FrameError::InvalidPacketLength {});
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
    pub fn item_at_offset<T: Pod>(&self, offset: usize) -> Result<&T, FrameError> {
        let start = self.head + offset;
        if start > self.tail {
            return Err(FrameError::InvalidOffset {
                offset,
                length: self.tail - self.head,
            });
        }

        let size = std::mem::size_of::<T>();
        if start + size > self.tail {
            return Err(FrameError::InsufficientData {
                offset,
                size,
                length: self.tail - offset,
            });
        }

        Ok(unsafe { &*(self.data.as_ptr().byte_offset((self.head + offset) as _) as *const T) })
    }

    /// Retrieves a mutable `T` beginning at the specified offset
    ///
    /// # Errors
    ///
    /// - The offset is not within bounds
    /// - The offset + size of `T` is not within bounds
    #[inline]
    pub fn item_at_offset_mut<T: Pod>(&mut self, offset: usize) -> Result<&mut T, FrameError> {
        let start = self.head + offset;
        if start > self.tail {
            return Err(FrameError::InvalidOffset {
                offset,
                length: self.tail - self.head,
            });
        }

        let size = std::mem::size_of::<T>();
        if start + size > self.tail {
            return Err(FrameError::InsufficientData {
                offset,
                size,
                length: self.tail - offset,
            });
        }

        Ok(unsafe {
            &mut *(self
                .data
                .as_mut_ptr()
                .byte_offset((self.head + offset) as _) as *mut T)
        })
    }

    /// Retrieves a slice of bytes beginning at the specified offset
    ///
    /// # Errors
    ///
    /// - The offset is not within bounds
    /// - The offset + len is not within bounds
    #[inline]
    pub fn slice_at_offset(&self, offset: usize, len: usize) -> Result<&[u8], FrameError> {
        let start = self.head + offset;
        if start > self.tail {
            return Err(FrameError::InvalidOffset {
                offset,
                length: self.tail - self.head,
            });
        }

        if start + len > self.tail {
            return Err(FrameError::InsufficientData {
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
    ) -> Result<&mut [u8], FrameError> {
        let start = self.head + offset;
        if start + len > self.tail {
            return Err(FrameError::InsufficientData {
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
    pub fn array_at_offset<const N: usize>(&self, offset: usize) -> Result<[u8; N], FrameError> {
        let start = self.head + offset;
        if start + N > self.tail {
            return Err(FrameError::InsufficientData {
                offset,
                size: N,
                length: self.tail - offset,
            });
        }

        let mut data = [0u8; N];
        data.copy_from_slice(&self.data[start..start + N]);
        Ok(data)
    }

    /// Pushes a slice of bytes to the frame, extending the tail
    ///
    /// # Errors
    ///
    /// The slice would extend the tail beyond the frame's capacity
    #[inline]
    pub fn push_slice(&mut self, slice: &[u8]) -> Result<(), FrameError> {
        if self.tail + slice.len() > self.data.len() {
            return Err(FrameError::InvalidPacketLength {});
        }

        self.data[self.tail..self.tail + slice.len()].copy_from_slice(slice);
        self.tail += slice.len();
        Ok(())
    }

    /// Sets the specified [TX metadata](https://github.com/torvalds/linux/blob/ae90f6a6170d7a7a1aa4fddf664fbd093e3023bc/Documentation/networking/xsk-tx-metadata.rst)
    ///
    /// Calling this function requires that the [`UmemCfgBuilder::tx_metadata`]
    /// was true.
    ///
    /// - If `csum` is `CsumOffload::Request`, this will request that the Layer 4
    /// checksum computation be offload to the NIC before transmission. Note that
    /// this requires that the IP pseudo header checksum be calculated and stored
    /// in the same location.
    /// - If `request_timestamp` is true, requests that the NIC write the timestamp
    /// the frame was transmitted. This can be retrieved using [`crate::CompletionRing::dequeue_with_timestamps`]
    #[inline]
    pub fn set_tx_metadata(
        &mut self,
        csum: CsumOffload,
        request_timestamp: bool,
    ) -> Result<(), FrameError> {
        // This would mean the user is requesting to set tx metadata...but not actually do anything
        debug_assert!(request_timestamp || matches!(csum, CsumOffload::Request { .. }));

        self.adjust_head(tx_metadata_diff())?;
        {
            let tx_meta = self.item_at_offset_mut::<bindings::xsk_tx_metadata>(0)?;
            tx_meta.flags = 0;
            tx_meta.offload.completion = 0;

            if let CsumOffload::Request(csum_req) = csum {
                tx_meta.flags |= bindings::XDP_TXMD_FLAGS_CHECKSUM;
                tx_meta.offload.request = csum_req;
            }

            if request_timestamp {
                tx_meta.flags |= bindings::XDP_TXMD_FLAGS_TIMESTAMP;
            }
        }
        self.adjust_head(-tx_metadata_diff())?;

        self.options |= bindings::XdpFlags::XDP_TX_METADATA as u32;

        Ok(())
    }
}

use crate::bindings::xdp_desc;

impl From<Frame> for xdp_desc {
    fn from(frame: Frame) -> Self {
        if (frame.options & bindings::XdpFlags::XDP_TX_METADATA as u32) == 0 {
            xdp_desc {
                // SAFETY:
                addr: unsafe {
                    frame
                        .data
                        .as_ptr()
                        .byte_offset(frame.head as _)
                        .offset_from(frame.base) as _
                },
                len: (frame.tail - frame.head) as _,
                options: frame.options & !(bindings::InternalXdpFlags::Mask as u32),
            }
        } else {
            xdp_desc {
                addr: unsafe {
                    frame
                        .data
                        .as_ptr()
                        .byte_offset(
                            (frame.head + std::mem::size_of::<bindings::xsk_tx_metadata>()) as _,
                        )
                        .offset_from(frame.base) as _
                },
                len: (frame.tail - frame.head - std::mem::size_of::<bindings::xsk_tx_metadata>())
                    as _,
                options: frame.options & !(bindings::InternalXdpFlags::Mask as u32),
            }
        }
    }
}
