//! Simple inline definitions of various types and constants so that we can
//! properly comment them, as well as add a few missing ones.
//!
//! Note that while [`rustix`](https://github.com/bytecodealliance/rustix) does
//! include most/all what we need, and includes comments from the kernel, it also
//! has dependencies (unlike libc) and just generally includes a bunch of stuff
//! we don't need, same as libc

#![allow(non_camel_case_types)]

/// The size in bytes of the [headroom](https://github.com/torvalds/linux/blob/ae90f6a6170d7a7a1aa4fddf664fbd093e3023bc/include/uapi/linux/bpf.h#L6432) reserved by the kernel for each xdp packet
pub const XDP_PACKET_HEADROOM: u64 = 256;
/// The default packet size used by [libxdp](https://github.com/xdp-project/xdp-tools/blob/3b199c0c185d4603406e6324ca5783b157c0e492/headers/xdp/xsk.h#L194)
pub const XSK_UMEM_DEFAULT_FRAME_SIZE: u32 = 4096;

/// Flags that can be present in [`xdp_desc::options`]
#[derive(Copy, Clone)]
#[repr(u32)]
pub enum XdpFlags {
    /// Flag indicating that the packet continues with the buffer pointed out by the
    /// next packet in the ring.
    ///
    /// The end of the packet is signalled by setting this bit to zero. For single
    /// buffer packets, every descriptor has 'options' set to 0 and this maintains
    /// backward compatibility.
    XDP_PKT_CONTD = 1 << 0,
    /// TX packet carries valid metadata.
    XDP_TX_METADATA = 1 << 1,
}

#[derive(Copy, Clone)]
#[repr(u32)]
pub enum InternalXdpFlags {
    SupportsChecksumOffload = 1 << 31,
    Mask = 0xf0000000,
}

/// An RX/TX packet descriptor describing an area of a [`Umem`](crate::umem::Umem)
///
/// For RX, this is filled by the kernel, for TX it is filled by userspace
#[repr(C)]
#[derive(Copy, Clone)]
pub struct xdp_desc {
    /// The offset from the beginning of the [`Umem`](crate::umem::Umem) where
    /// a packet's data starts.
    ///
    /// Note that this offset is always >= the [`XDP_PACKET_HEADROOM`] from the
    /// _actual_ start of the packet, eg. packet 0 of the umem would have an addr
    /// of [`XDP_PACKET_HEADROOM`]
    pub addr: u64,
    /// The length of the packet in bytes
    pub len: u32,
    /// The options for the packet
    ///
    /// For frames being received, this will either be 0 or [`XdpFlags::XDP_PKT_CONTD`]
    ///
    /// For frames being sent, this can additionally be [`XdpFlags::XDP_TX_METADATA`] to
    /// indicate that an [`xsk_tx_metadata`] has been filled for the packet
    pub options: u32,
}

/// Request transmit timestamp.
///
/// Upon completion, fills [`xsk_tx_offload::Completion::tx_timestamp`]
pub const XDP_TXMD_FLAGS_TIMESTAMP: u64 = 1;

/// Request transmit checksum offload.
pub const XDP_TXMD_FLAGS_CHECKSUM: u64 = 2;

/// Checksum offload data that must be filled by userspace when requesting [`XDP_TXMD_FLAGS_CHECKSUM`]
#[repr(C)]
#[derive(Copy, Clone)]
pub struct xsk_tx_request {
    /// Offset from [`xdp_desc::addr`] where checksumming should start.
    pub csum_start: u16,
    /// Offset from [`Self::Request::csum_start`] where checksum should be stored.
    pub csum_offset: u16,
}

/// The block of data filled by userspace when using [`XDP_TXMD_FLAGS_CHECKSUM`]
/// and filled by the kernel when using [`XDP_TXMD_FLAGS_TIMESTAMP`]
#[repr(C)]
pub union xsk_tx_offload {
    /// The checksum offload request
    pub request: xsk_tx_request,
    /// The timestamp the TX request was emitted
    pub completion: u64,
}

/// `AF_XDP` TX offloads request.
pub struct xsk_tx_metadata {
    /// [`XDP_TXMD_FLAGS_TIMESTAMP`] and/or [`XDP_TXMD_FLAGS_CHECKSUM`]
    pub flags: u64,
    /// When using [`XDP_TXMD_FLAGS_TIMESTAMP`] the [`xsk_tx_offload::request`]
    /// field must be set.
    ///
    /// When using [`XDP_TXMD_FLAGS_CHECKSUM`], the [`xsk_tx_offload::completion`]
    /// field will be set when the kernel gives back the packet in the completion ring
    pub offload: xsk_tx_offload,
}

unsafe impl crate::packet::Pod for xsk_tx_metadata {}

/// The bindings specific to the various rings used by `AF_XDP` sockets.
///
/// These are public just in case, but are really only used internally
pub mod rings {
    /// The mmap offsets for each ring
    ///
    /// [Source](https://github.com/torvalds/linux/blob/7af08b57bcb9ebf78675c50069c54125c0a8b795/include/uapi/linux/if_xdp.h#L109-L112)
    #[repr(u64)]
    pub enum RingPageOffsets {
        Rx = 0,
        Tx = 0x80000000,
        Fill = 0x100000000,
        Completion = 0x180000000,
    }

    /// The
    ///
    /// [Source](https://github.com/torvalds/linux/blob/7af08b57bcb9ebf78675c50069c54125c0a8b795/include/uapi/linux/if_xdp.h#L59-L64)
    #[repr(C)]
    pub struct xdp_ring_offset {
        pub producer: u64,
        pub consumer: u64,
        pub desc: u64,
        pub flags: u64,
    }

    ///
    ///
    /// [Source](https://github.com/torvalds/linux/blob/7af08b57bcb9ebf78675c50069c54125c0a8b795/include/uapi/linux/if_xdp.h#L66-L71)
    #[repr(C)]
    pub struct xdp_mmap_offsets {
        pub rx: xdp_ring_offset,
        pub tx: xdp_ring_offset,
        pub fill: xdp_ring_offset,
        pub completion: xdp_ring_offset,
    }
}
