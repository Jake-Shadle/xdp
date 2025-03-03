//! Simple inline definitions of various types and constants so that we can
//! properly comment them, as well as add a few missing ones.
//!
//! Note that while [`rustix`](https://github.com/bytecodealliance/rustix) does
//! include most/all what we need, and includes comments from the kernel, it also
//! has dependencies (unlike libc) and just generally includes a bunch of stuff
//! we don't need, same as libc

#![allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    clippy::upper_case_acronyms
)]

use std::{ffi::c_void, os::fd::RawFd};

/// Internal flags to enable TX offload features if they were enabled at
/// socket creation
#[derive(Copy, Clone)]
#[repr(u32)]
pub enum InternalXdpFlags {
    /// TX checksum offload is enabled
    SupportsChecksumOffload = 1 << 31,
    /// TX checksum offload is enabled in software
    SoftwareOffload = (1 << 30) | (1 << 31),
    /// TX completion timestamp is supported
    CompletionTimestamp = 1 << 29,
    /// Mask of valid flags
    Mask = 0xf0000000,
}

/// The bindings specific to the various rings used by `AF_XDP` sockets.
///
/// These are public just in case, but are really only used internally
pub mod rings {
    /// The mmap offsets for each ring
    ///
    /// [Source](https://github.com/torvalds/linux/blob/7af08b57bcb9ebf78675c50069c54125c0a8b795/include/uapi/linux/if_xdp.h#L109-L112)
    #[repr(u64)]
    pub enum RingPageOffsets {
        /// Offset for the RX ring
        Rx = 0,
        /// Offset for the TX ring
        Tx = 0x80000000,
        /// Offset for the Fill ring
        Fill = 0x100000000,
        /// Offset for the Completion ring
        Completion = 0x180000000,
    }

    /// The mapping offsets for a single ring
    ///
    /// [Source](https://github.com/torvalds/linux/blob/7af08b57bcb9ebf78675c50069c54125c0a8b795/include/uapi/linux/if_xdp.h#L59-L64)
    #[repr(C)]
    pub struct xdp_ring_offset {
        /// The offset in the mmap where the producer u32 atomic resides
        pub producer: u64,
        /// The offset in the mmap where the consumer u32 atomic resides
        pub consumer: u64,
        /// The offset in the mmap where the ring will actually store data
        pub desc: u64,
        /// Currently unused
        pub flags: u64,
    }

    /// The ring offsets for each of the 4 rings
    ///
    /// [Source](https://github.com/torvalds/linux/blob/7af08b57bcb9ebf78675c50069c54125c0a8b795/include/uapi/linux/if_xdp.h#L66-L71)
    #[repr(C)]
    pub struct xdp_mmap_offsets {
        /// RX ring
        pub rx: xdp_ring_offset,
        /// TX ring
        pub tx: xdp_ring_offset,
        /// Fill ring
        pub fill: xdp_ring_offset,
        /// Completion ring
        pub completion: xdp_ring_offset,
    }
}

/// xdp specific bindings
pub mod xdp {
    /// The size in bytes of the [headroom](https://github.com/torvalds/linux/blob/ae90f6a6170d7a7a1aa4fddf664fbd093e3023bc/include/uapi/linux/bpf.h#L6432) reserved by the kernel for each xdp packet
    pub const XDP_PACKET_HEADROOM: u64 = 256;
    /// The default packet size used by [libxdp](https://github.com/xdp-project/xdp-tools/blob/3b199c0c185d4603406e6324ca5783b157c0e492/headers/xdp/xsk.h#L194)
    pub const XSK_UMEM_DEFAULT_FRAME_SIZE: u32 = 4096;

    /// The various `SOL_XDP` socket options.
    ///
    /// Defined in `<include/uapi/linux/if_xdp.h>`
    pub(crate) mod SockOpts {
        pub type Enum = i32;

        pub const XDP_MMAP_OFFSETS: Enum = 1;
        pub const XDP_RX_RING: Enum = 2;
        pub const XDP_TX_RING: Enum = 3;
        pub const XDP_UMEM_REG: Enum = 4;
        pub const XDP_UMEM_FILL_RING: Enum = 5;
        pub const XDP_UMEM_COMPLETION_RING: Enum = 6;
        //pub const XDP_STATISTICS: Enum = 7;
        //pub const XDP_OPTIONS: Enum = 8;
    }

    /// The various `AF_XDP` bind flags.
    ///
    /// Defined in `<include/uapi/linux/if_xdp.h>`
    pub mod BindFlags {
        /// Integer type for the flags
        pub type Enum = u16;

        /// Umem is shared between multiple processes/threads
        pub const XDP_SHARED_UMEM: Enum = 1 << 0;
        /// Force copy mode, even if zero-copy is supported.
        ///
        /// By default if neither copy nor zero-copy is specified, zero-copy will
        /// be used if supported, falling back to copy which is always supported
        pub const XDP_COPY: Enum = 1 << 1;
        /// Force zero-copy mode.
        ///
        /// The socket will fail to bind if zero-copy mode is not supported.
        pub const XDP_ZEROCOPY: Enum = 1 << 2;
        /// If this option is set, the driver might go sleep and in that case
        /// the `XDP_RING_NEED_WAKEUP` flag in the fill and/or Tx rings will be
        /// set.
        ///
        /// If it is set, the application need to explicitly wake up the
        /// driver with a [`poll`](https://man7.org/linux/man-pages/man2/poll.2.html)
        /// (Rx and Tx) or [`sendto`](https://man7.org/linux/man-pages/man3/sendto.3p.html) (Tx only).
        ///
        /// If you are running the driver and the application on the same core,
        /// you should use this option so that the kernel will yield to the user
        /// space application.
        pub const XDP_USE_NEED_WAKEUP: Enum = 1 << 3;
        /// By setting this option, userspace application indicates that it can
        /// handle multiple descriptors per packet.
        ///
        /// This enables `AF_XDP` to split multi-buffer XDP frames into multiple
        /// Rx descriptors. Without this set such frames will be dropped.
        pub const XDP_USE_SG: Enum = 1 << 4;
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
        /// For frames being received, this will either be 0 or [`XdpPktOptions::XDP_PKT_CONTD`]
        ///
        /// For frames being sent, this can additionally be [`XdpPktOptions::XDP_TX_METADATA`] to
        /// indicate that an [`xsk_tx_metadata`] has been filled for the packet
        pub options: XdpPktOptions::Enum,
    }

    /// Flags that can be present in [`xdp_desc::options`]
    pub mod XdpPktOptions {
        /// The type of the flags
        pub type Enum = u32;

        /// Flag indicating that the packet continues with the buffer pointed out by the
        /// next packet in the ring.
        ///
        /// The end of the packet is signalled by setting this bit to zero. For
        /// single buffer packets, every descriptor has [`super::xdp_desc::options`] set
        /// to `0` and this maintains backward compatibility.
        pub const XDP_PKT_CONTD: Enum = 1 << 0;
        /// TX packet carries valid metadata.
        pub const XDP_TX_METADATA: Enum = 1 << 1;
    }

    /// Flags that can be present in [`xsk_tx_metadata::flags`]
    pub mod XdpTxFlags {
        /// The type of the flags
        pub type Enum = u64;

        /// Request transmit timestamp.
        ///
        /// Upon completion, fills [`super::xsk_tx_offload::completion`] with
        /// the timestamp when transmission occurred
        pub const XDP_TXMD_FLAGS_TIMESTAMP: Enum = 0x1;

        /// Request transmit checksum offload.
        pub const XDP_TXMD_FLAGS_CHECKSUM: Enum = 0x2;
    }

    /// Checksum offload data that must be filled by userspace when requesting [`XdpTxFlags::XDP_TXMD_FLAGS_CHECKSUM`]
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct xsk_tx_request {
        /// Offset from [`xdp_desc::addr`] where checksumming should start.
        pub csum_start: u16,
        /// Offset from [`Self::csum_start`] where checksum should be stored.
        pub csum_offset: u16,
    }

    /// The block of data filled by userspace when using [`XdpTxFlags::XDP_TXMD_FLAGS_CHECKSUM`]
    /// and filled by the kernel when using [`XdpTxFlags::XDP_TXMD_FLAGS_TIMESTAMP`]
    #[repr(C)]
    pub union xsk_tx_offload {
        /// The checksum offload request
        pub request: xsk_tx_request,
        /// The timestamp the TX request was emitted
        pub completion: u64,
    }

    /// `AF_XDP` TX offloads request.
    #[repr(C)]
    pub struct xsk_tx_metadata {
        /// [`XdpTxFlags::XDP_TXMD_FLAGS_TIMESTAMP`] and/or [`XdpTxFlags::XDP_TXMD_FLAGS_CHECKSUM`]
        pub flags: XdpTxFlags::Enum,
        /// When using [`XdpTxFlags::XDP_TXMD_FLAGS_TIMESTAMP`] the [`xsk_tx_offload::request`]
        /// field must be set.
        ///
        /// When using [`XdpTxFlags::XDP_TXMD_FLAGS_CHECKSUM`], the [`xsk_tx_offload::completion`]
        /// field will be set when the kernel gives back the packet in the completion ring
        pub offload: xsk_tx_offload,
    }

    // SAFETY: POD
    unsafe impl crate::packet::Pod for xsk_tx_metadata {}

    /// Flags available when registering a [`crate::Umem`] with a socket
    pub mod UmemFlags {
        /// The type of the flags
        pub type Enum = u32;

        /// Umem chunks are not power of 2 (ie, 2k or 4k)
        pub const XDP_UMEM_UNALIGNED_CHUNK_FLAG: Enum = 1 << 0;
        /// Force checksum calculation in software. Can be used for testing or
        /// working around potential HW issues.
        ///
        /// This option causes performance degradation and only works in
        /// `XDP_COPY` mode.
        pub const XDP_UMEM_TX_SW_CSUM: Enum = 1 << 1;
        /// Request to reserve `tx_metadata_len` bytes of per-chunk metadata.
        pub const XDP_UMEM_TX_METADATA_LEN: Enum = 1 << 2;
    }

    #[repr(C)]
    pub(crate) struct XdpUmemReg {
        /// Base pointer of the packet mmap
        pub addr: u64,
        /// Length of the packet mmap in bytes
        pub len: u64,
        /// Size of each individual chunk/packet/packet
        pub chunk_size: u32,
        /// Size of the headroom the packet is offset from the beginning.
        ///
        /// Note this does not include the headroom that is already reserved by
        /// the kernel
        pub headroom: u32,
        /// Umem flags
        pub flags: UmemFlags::Enum,
        /// Length of the TX metadata, if any.
        pub tx_metadata_len: u32,
    }

    #[repr(C)]
    pub(crate) struct sockaddr_xdp {
        pub sxdp_family: u16,
        pub sxdp_flags: u16,
        pub sxdp_ifindex: u32,
        pub sxdp_queue_id: u32,
        pub sxdp_shared_umem_fd: u32,
    }
}

pub(crate) mod socket {
    use super::{RawFd, c_void};

    pub mod AddressFamily {
        pub type Enum = i32;

        pub const AF_LOCAL: Enum = 1;
        pub const AF_INET: Enum = 2;
        pub const AF_INET6: Enum = 10;
        pub const AF_NETLINK: Enum = 16;
        pub const AF_XDP: Enum = 44;
    }

    /// The different socket kinds
    ///
    /// Defined in <include/linux/net.h>
    pub mod Kind {
        pub type Enum = i32;

        pub const SOCK_DGRAM: Enum = 2;
        pub const SOCK_RAW: Enum = 3;

        pub const SOCK_CLOEXEC: Enum = 0o02000000;
    }

    pub mod Protocol {
        pub type Enum = i32;

        pub const NONE: Enum = 0;
        pub const NETLINK_GENERIC: Enum = 16;
    }

    pub mod Level {
        pub type Enum = i32;

        pub const SOL_NETLINK: Enum = 270;
        pub const SOL_XDP: Enum = 283;
    }

    pub mod MsgFlags {
        pub type Enum = i32;

        pub const NONE: Enum = 0;
        pub const DONTWAIT: Enum = 0x40;
    }

    #[repr(C)]
    pub struct sockaddr {
        pub sa_family: u16,
        pub sa_data: [u8; 14],
    }

    #[repr(C)]
    pub struct sockaddr_in {
        pub sin_family: u16,
        pub sin_port: u16,
        pub sin_addr: u32,
        pub sin_zero: [u8; 8],
    }

    #[repr(C)]
    pub struct sockaddr_in6 {
        pub sin6_family: u16,
        pub sin6_port: u16,
        pub sin6_flowinfo: u32,
        pub sin6_addr: [u8; 16],
        pub sin6_scope_id: u32,
    }

    #[repr(C)]
    pub struct pollfd {
        pub fd: RawFd,
        pub events: PollEvents::Enum,
        pub revents: PollEvents::Enum,
    }

    pub mod PollEvents {
        pub type Enum = i16;

        pub const POLLIN: Enum = 0x1;
        pub const POLLOUT: Enum = 0x4;
    }

    #[link(name = "c")]
    unsafe extern "C" {
        /// <https://www.man7.org/linux/man-pages/man2/socket.2.html>
        ///
        /// This is marked as safe as we have no invariants to uphold, and invalid
        /// arguments or other runtime errors will result in errno being set
        pub safe fn socket(
            family: AddressFamily::Enum,
            kind: Kind::Enum,
            protocol: Protocol::Enum,
        ) -> RawFd;

        /// <https://man7.org/linux/man-pages/man2/bind.2.html>
        pub fn bind(socket: RawFd, address: *const sockaddr, address_len: u32) -> i32;

        /// <https://man7.org/linux/man-pages/man2/setsockopt.2.html>
        pub fn getsockopt(
            sockfd: RawFd,
            level: Level::Enum,
            optname: i32,
            optval: *mut c_void,
            optlen: *mut u32,
        ) -> i32;

        /// <https://man7.org/linux/man-pages/man2/setsockopt.2.html>
        pub fn setsockopt(
            sockfd: RawFd,
            level: Level::Enum,
            optname: i32,
            optval: *const c_void,
            optlen: u32,
        ) -> i32;

        /// <https://man7.org/linux/man-pages/man3/sendto.3p.html>
        pub fn sendto(
            socket: RawFd,
            buf: *const c_void,
            len: usize,
            flags: MsgFlags::Enum,
            addr: *const sockaddr,
            addrlen: u32,
        ) -> isize;

        /// <https://man7.org/linux/man-pages/man3/recvfrom.3p.html>
        pub fn recvfrom(
            socket: RawFd,
            buf: *mut c_void,
            len: usize,
            flags: MsgFlags::Enum,
            addr: *mut sockaddr,
            addrlen: *mut u32,
        ) -> isize;

        /// <https://man7.org/linux/man-pages/man2/poll.2.html>
        pub fn poll(fds: *mut pollfd, nfds: u64, timeout: i32) -> i32;

        /// <https://man7.org/linux/man-pages/man3/send.3p.html>
        pub fn send(socket: RawFd, buf: *const c_void, len: usize, flags: MsgFlags::Enum) -> isize;

        /// <https://man7.org/linux/man-pages/man3/recv.3p.html>
        pub fn recv(socket: RawFd, buf: *mut c_void, len: usize, flags: MsgFlags::Enum) -> isize;
    }
}

pub(crate) mod iface {
    use super::{RawFd, c_void, socket::sockaddr};
    use std::ffi::c_char;

    /// Maximum length, including NULL, of an interface name
    pub const IF_NAMESIZE: usize = 16;

    /// No interface found with given name.
    pub const ENODEV: i32 = 19;

    /// Directory entry type for a directory
    pub const DT_DIR: u8 = 4;

    pub const SIOCETHTOOL: u64 = 0x00008946;

    pub const RTF_UP: u16 = 0x0001;
    pub const RTF_GATEWAY: u16 = 0x0002;

    #[repr(C)]
    pub struct ifaddrs {
        pub ifa_next: *mut ifaddrs,
        pub ifa_name: *mut u8,
        pub ifa_flags: u32,
        pub ifa_addr: *mut sockaddr,
        pub ifa_netmask: *mut sockaddr,
        pub ifa_ifu: *mut sockaddr,
        pub ifa_data: *mut c_void,
    }

    #[repr(C)]
    pub struct dirent {
        pub d_ino: u64,
        pub d_off: i64,
        pub d_reclen: u16,
        pub d_type: u8,
        pub d_name: [u8; 256],
    }

    #[repr(C)]
    pub union ifr_ifru {
        pub ifru_data: *mut c_char,
    }

    #[repr(C)]
    pub struct ifreq {
        pub ifr_name: [u8; 16],
        pub ifr_ifru: ifr_ifru,
    }

    pub enum DIR {}

    #[link(name = "c")]
    unsafe extern "C" {
        /// <https://man7.org/linux/man-pages/man3/getifaddrs.3.html>
        pub fn getifaddrs(ifap: *mut *mut ifaddrs) -> i32;
        /// <https://man7.org/linux/man-pages/man3/getifaddrs.3.html>
        pub fn freeifaddrs(ifap: *mut ifaddrs) -> i32;

        /// <https://man7.org/linux/man-pages/man3/if_nametoindex.3.html>
        pub fn if_indextoname(ifindex: u32, ifname: *mut u8) -> *mut u8;
        /// <https://man7.org/linux/man-pages/man3/if_nametoindex.3.html>
        pub fn if_nametoindex(ifname: *const u8) -> u32;

        /// <https://man7.org/linux/man-pages/man2/ioctl.2.html>
        pub fn ioctl(fd: RawFd, request: u64, ...) -> i32;

        /// <https://man7.org/linux/man-pages/man3/opendir.3.html>
        pub fn opendir(dirname: *const u8) -> *mut DIR;
        /// <https://man7.org/linux/man-pages/man3/closedir.3.html>
        pub fn closedir(dirp: *mut DIR) -> i32;
        /// <https://man7.org/linux/man-pages/man3/readdir.3.html>
        pub fn readdir(dirp: *mut DIR) -> *mut dirent;

        pub fn strncmp(cs: *const u8, ct: *const u8, n: usize) -> i32;
    }
}

pub(crate) mod mmap {
    use super::c_void;

    pub const _SC_PAGESIZE: i32 = 30;

    pub const MAP_FAILED: *mut c_void = !0 as *mut c_void;

    // Don't feel like supporting non-64 bit platforms, but would be possible
    // if someone actually wanted it
    #[cfg(not(target_pointer_width = "64"))]
    compile_error!("non-64 bit platforms are not supported");

    pub mod Flags {
        pub type Enum = i32;

        pub const MAP_SHARED: Enum = 0x0001;
        pub const MAP_PRIVATE: Enum = 0x0002;
        pub const MAP_ANONYMOUS: Enum = 0x0020;
        pub const MAP_POPULATE: Enum = 0x08000;
    }

    pub mod Prot {
        pub type Enum = i32;

        pub const PROT_READ: Enum = 1;
        pub const PROT_WRITE: Enum = 2;
    }

    #[link(name = "c")]
    unsafe extern "C" {
        /// <https://man7.org/linux/man-pages/man3/sysconf.3.html>
        pub safe fn sysconf(name: i32) -> i64;
        /// <https://man7.org/linux/man-pages/man2/mmap.2.html>
        #[cfg_attr(
            any(
                target_os = "android",
                all(target_os = "linux", not(target_env = "musl"))
            ),
            link_name = "mmap64"
        )]
        pub fn mmap(
            addr: *mut c_void,
            len: usize,
            prot: Prot::Enum,
            flags: Flags::Enum,
            fd: i32,
            offset: i64,
        ) -> *mut c_void;
        /// <https://man7.org/linux/man-pages/man2/mmap.2.html>
        pub fn munmap(addr: *mut c_void, len: usize) -> i32;
    }
}
