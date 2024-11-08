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

/// Request transmit timestamp. Upon completion, put it into tx_timestamp
/// field of union xsk_tx_metadata.
const XDP_TXMD_FLAGS_TIMESTAMP: u64 = 1 << 0;

/// Request transmit checksum offload. Checksum start position and offset
/// are communicated via csum_start and csum_offset fields of union
/// xsk_tx_metadata.
const XDP_TXMD_FLAGS_CHECKSUM: u64 = 1 << 1;

/// xdp_desc contains tx_metadata
const XDP_TX_METADATA: u32 = 1 << 1;

const fn tx_metadata_diff() -> i32 {
    -(std::mem::size_of::<XskTxMetadata>() as i32)
}

pub enum CsumOffload {
    Request(Csum),
    None,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Csum {
    pub start: u16,
    pub offset: u16,
}

#[repr(C)]
pub(crate) union TxMetadataInner {
    pub(crate) csum: Csum,
    pub(crate) timestamp: u64,
}

#[repr(C)]
pub(crate) struct XskTxMetadata {
    flags: u64,
    pub(crate) which: TxMetadataInner,
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
pub struct Frame<'umem> {
    /// The entire frame buffer, including headroom, initialized packet contents,
    /// and uninitialized/empty remainder
    pub(crate) data: &'umem mut [u8],
    /// The offset in data where the packet starts
    pub(crate) head: usize,
    /// The offset in data where the packet ends
    pub(crate) tail: usize,
    pub(crate) base: *const u8,
    pub has_tx_metadata: bool,
}

impl<'umem> Frame<'umem> {
    #[inline]
    pub fn len(&self) -> usize {
        self.tail - self.head
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.data.len()
    }

    /// Adjust the head of the packet up or down by `diff` bytes
    ///
    /// This method is the equivalent of [`bpf_xdp_adjust_head`](https://docs.ebpf.io/linux/helper-function/bpf_xdp_adjust_head/),
    /// allowing modification of layers (eg. layer 3 IPv4 <-> IPv6) without needing
    /// to copy the entirety of the packet data up or down.
    ///
    /// Adjusting the head down requires that headroom was configured for the umem
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

    #[inline]
    pub fn item_at_offset<T: Sized>(&self, offset: usize) -> Result<&T, FrameError> {
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

    #[inline]
    pub fn item_at_offset_mut<T: Sized>(&mut self, offset: usize) -> Result<&mut T, FrameError> {
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

    #[inline]
    pub fn slice_at_offset(&self, offset: usize, len: usize) -> Result<&[u8], FrameError> {
        let start = self.head + offset;
        if start + len > self.tail {
            return Err(FrameError::InsufficientData {
                offset,
                size: len,
                length: self.tail - offset,
            });
        }

        Ok(&self.data[start..start + len])
    }

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
    /// - If `csum` is Some(), this will request that the Layer 4 checksum computation
    /// be offload to the NIC before transmission
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
        let tx_meta = self.item_at_offset_mut::<XskTxMetadata>(0)?;
        tx_meta.flags = 0;
        tx_meta.which.timestamp = 0;

        if let CsumOffload::Request(csum_req) = csum {
            tx_meta.flags |= XDP_TXMD_FLAGS_CHECKSUM;
            tx_meta.which.csum = csum_req;
        }

        if request_timestamp {
            tx_meta.flags |= XDP_TXMD_FLAGS_TIMESTAMP;
        }

        Ok(())
    }
}

impl<'umem> From<Frame<'umem>> for libc::xdp_desc {
    fn from(frame: Frame<'umem>) -> Self {
        if !frame.has_tx_metadata {
            libc::xdp_desc {
                // SAFETY:
                addr: unsafe {
                    frame
                        .data
                        .as_ptr()
                        .byte_offset(frame.head as _)
                        .offset_from(frame.base) as _
                },
                len: (frame.tail - frame.head) as _,
                options: 0,
            }
        } else {
            libc::xdp_desc {
                addr: unsafe {
                    frame
                        .data
                        .as_ptr()
                        .byte_offset((frame.head + std::mem::size_of::<XskTxMetadata>()) as _)
                        .offset_from(frame.base) as _
                },
                len: (frame.tail - frame.head - std::mem::size_of::<XskTxMetadata>()) as _,
                options: XDP_TX_METADATA,
            }
        }
    }
}
