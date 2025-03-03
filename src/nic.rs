//! Utilities for querying NIC capabilities

use crate::libc::{iface, socket};
mod netlink;

macro_rules! flag_strings {
    ($table:expr, $v:expr, $f:expr) => {{
        let mut count = 0;

        for (flag, s) in $table {
            if (flag as u64 & $v) == 0 {
                continue;
            }

            if count > 0 {
                $f.write_str(" | ")?;
            }

            count += 1;
            $f.write_str(s)?;
        }

        if count == 0 {
            $f.write_str("-")?;
        }

        Ok(())
    }};
}

/// The XDP modes supported by a device (+driver)
#[derive(Copy, Clone)]
pub enum XdpModes {
    /// Socket buffer mode
    ///
    /// This doesn't require driver support, but means many XDP advantages are
    /// lost due to some of the higher level network stack being involved, most
    /// crucially copies into user space memory over
    Skb = 1 << 1,
    /// Driver mode
    ///
    /// The driver supports XDP, allowing bypass of the higher level network
    /// stack, and potentially zero copies, if the packet is redirected,
    /// dropped, or retransmitted
    Drv = 1 << 2,
    /// Hardware mode
    ///
    /// Allows offload of the eBPF program from the kernel to the device itself
    /// for maximum performance. Extremely few devices support this.
    Hardware = 1 << 3,
}

/// The support for [`XDP_ZEROCOPY`](https://www.kernel.org/doc/html/latest/networking/af_xdp.html#xdp-copy-and-xdp-zerocopy-bind-flags)
///
/// Zero copy gives the NIC the XDP socket(s) is bound to [direct memory access](https://en.wikipedia.org/wiki/Direct_memory_access)
/// to the [`crate::Umem`] buffers provided by userspace to receive or send packets
#[derive(Copy, Clone, Debug)]
pub enum XdpZeroCopy {
    /// Zero copy is not available for the device
    Unavailable,
    /// Zero copy is available
    Available,
    /// Zero copy is available, including [multi-buffer](https://www.kernel.org/doc/html/latest/networking/af_xdp.html#multi-buffer-support).
    /// This is conceptually similar to [`iovec`](https://www.man7.org/linux/man-pages/man3/iovec.3type.html)
    MultiBuffer(u32),
}

impl XdpZeroCopy {
    /// True if the zero copy feature is available
    #[inline]
    pub fn is_available(&self) -> bool {
        !matches!(self, Self::Unavailable)
    }
}

/// XDP features that can be supported by a driver/NIC
#[derive(Copy, Clone)]
pub enum XdpAct {
    /// XDP features supported by all drivers
    ///
    /// - `XDP_ABORTED` - Drop packet with tracepoint exception
    /// - `XDP_DROP` - Silently drop packet
    /// - `XDP_PASS` - Let packet continue through the normal network stack
    /// - `XDP_TX` - Bounce packet back to the NIC it arrived on
    Basic = 1 << 0,
    /// `XDP_REDIRECT` is supported
    ///
    /// Packets can be redirected to another NIC or to an `AF_XDP` socket.
    Redirect = 1 << 1,
    /// The driver implements the [`ndo_xdp_xmit`](https://github.com/xdp-project/xdp-project/blob/master/areas/core/redesign01_ndo_xdp_xmit.org)
    /// callback
    NdoXmit = 1 << 2,
    /// `XDP_ZEROCOPY` is supported.
    XskZeroCopy = 1 << 3,
    /// Hardware offloading is supported
    HwOffload = 1 << 4,
    /// The NIC supports non-linear buffers in the driver napi callback
    RxSg = 1 << 5,
    /// The NIC supports non-linear buffers in the [`ndo_xdp_xmit`](https://github.com/xdp-project/xdp-project/blob/master/areas/core/redesign01_ndo_xdp_xmit.org)
    /// callback
    NdoXmitSg = 1 << 6,

    /// Mask for the valid bits
    Mask = (1 << 7) - 1,
}

/// The XDP features that can be supported by a network interface
#[derive(Copy, Clone)]
pub struct XdpFeatures(pub u64);

impl fmt::Debug for XdpFeatures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        flag_strings!(
            [
                (XdpAct::Basic, "NETDEV_XDP_ACT_BASIC"),
                (XdpAct::Redirect, "NETDEV_XDP_ACT_REDIRECT"),
                (XdpAct::NdoXmit, "NETDEV_XDP_ACT_NDO_XMIT"),
                (XdpAct::XskZeroCopy, "NETDEV_XDP_ACT_XSK_ZEROCOPY"),
                (XdpAct::HwOffload, "NETDEV_XDP_ACT_HW_OFFLOAD"),
                (XdpAct::RxSg, "NETDEV_XDP_ACT_RX_SG"),
                (XdpAct::NdoXmitSg, "NETDEV_XDP_ACT_NDO_XMIT_SG"),
            ],
            self.0,
            f
        )
    }
}

impl XdpFeatures {
    /// XDP features supported by all drivers
    ///
    /// - `XDP_ABORTED` - Drop packet with tracepoint exception
    /// - `XDP_DROP` - Silently drop packet
    /// - `XDP_PASS` - Let packet continue through the normal network stack
    /// - `XDP_TX` - Bounce packet back to the NIC it arrived on
    #[inline]
    pub fn basic(self) -> bool {
        (self.0 & XdpAct::Basic as u64) != 0
    }

    /// `XDP_REDIRECT` is supported
    ///
    /// Packets can be redirected to another NIC or to an `AF_XDP` socket.
    #[inline]
    pub fn redirect(self) -> bool {
        (self.0 & XdpAct::Redirect as u64) != 0
    }

    /// `XDP_ZEROCOPY` is supported.
    #[inline]
    pub fn zero_copy(self) -> bool {
        (self.0 & XdpAct::XskZeroCopy as u64) != 0
    }
}

/// The [RX metadata](https://docs.kernel.org/networking/xdp-rx-metadata.html)
/// that can be provided by a network interface
#[repr(u64)]
pub enum RxMetadataFlags {
    /// Device is capable of exposing receive HW timestamp via [`bpf_xdp_metadata_rx_timestamp`](https://docs.ebpf.io/linux/kfuncs/bpf_xdp_metadata_rx_timestamp/)
    Timestamp = 1 << 0,
    /// Device is capable of exposing receive packet hash via [`bpf_xdp_metadata_rx_hash`](https://docs.ebpf.io/linux/kfuncs/bpf_xdp_metadata_rx_hash/)
    Hash = 1 << 1,
    /// Device is capable of exposing receive packet VLAN tag via [`bpf_xdp_metadata_rx_vlan_tag`](https://docs.ebpf.io/linux/kfuncs/bpf_xdp_metadata_rx_vlan_tag/)
    VlanTag = 1 << 2,
}

/// The [RX metadata](https://docs.kernel.org/networking/xdp-rx-metadata.html) supported by a NIC
#[derive(Copy, Clone)]
pub struct XdpRxMetadata(pub u64);

impl fmt::Debug for XdpRxMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        flag_strings!(
            [
                (
                    RxMetadataFlags::Timestamp,
                    "NETDEV_XDP_RX_METADATA_TIMESTAMP"
                ),
                (RxMetadataFlags::Hash, "NETDEV_XDP_RX_METADATA_HASH"),
                (RxMetadataFlags::VlanTag, "NETDEV_XDP_RX_METADATA_VLAN_TAG"),
            ],
            self.0,
            f
        )
    }
}

impl XdpRxMetadata {
    /// Device is capable of exposing receive HW timestamp via [`bpf_xdp_metadata_rx_timestamp`](https://docs.ebpf.io/linux/kfuncs/bpf_xdp_metadata_rx_timestamp/)
    #[inline]
    pub fn timestamp(self) -> bool {
        (self.0 & RxMetadataFlags::Timestamp as u64) != 0
    }

    /// Device is capable of exposing receive packet hash via [`bpf_xdp_metadata_rx_hash`](https://docs.ebpf.io/linux/kfuncs/bpf_xdp_metadata_rx_hash/)
    #[inline]
    pub fn hash(self) -> bool {
        (self.0 & RxMetadataFlags::Hash as u64) != 0
    }

    /// Device is capable of exposing receive packet VLAN tag via [`bpf_xdp_metadata_rx_vlan_tag`](https://docs.ebpf.io/linux/kfuncs/bpf_xdp_metadata_rx_vlan_tag/)
    #[inline]
    pub fn vlan_tag(self) -> bool {
        (self.0 & RxMetadataFlags::VlanTag as u64) != 0
    }
}

/// The [TX metadata](https://docs.kernel.org/networking/xsk-tx-metadata.html)
/// that can be provided by a network interface
#[repr(u64)]
pub enum TxMetadataFlags {
    /// HW timestamping egress packets is supported by the driver.
    Timestamp = 1 << 0,
    /// L4 checksum HW offload is supported by the driver.
    Checksum = 1 << 1,
}

/// The [`TxMetadataFlags`] supported by a NIC
#[derive(Copy, Clone)]
pub struct XdpTxMetadata(pub u64);

impl fmt::Debug for XdpTxMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        flag_strings!(
            [
                (TxMetadataFlags::Timestamp, "NETDEV_XSK_FLAGS_TX_TIMESTAMP"),
                (TxMetadataFlags::Checksum, "NETDEV_XSK_FLAGS_TX_CHECKSUM"),
            ],
            self.0,
            f
        )
    }
}

impl XdpTxMetadata {
    /// HW timestamping egress packets is supported by the driver.
    #[inline]
    pub fn timestamp(self) -> bool {
        (self.0 & TxMetadataFlags::Timestamp as u64) != 0
    }

    /// L4 checksum HW offload is supported by the driver.
    #[inline]
    pub fn checksum(self) -> bool {
        (self.0 & TxMetadataFlags::Checksum as u64) != 0
    }
}

/// The capabilities available for a network device
#[derive(Debug)]
pub struct NetdevCapabilities {
    // The [XDP modes](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_XDP/)
    // supported by the driver/device
    //pub modes: XdpModes,
    /// The number of hardware queues supported by the NIC
    pub queue_count: u32,
    /// The XDP features available
    pub xdp_features: XdpFeatures,
    /// The zero copy features available
    pub zero_copy: XdpZeroCopy,
    /// The RX metadata features available
    pub rx_metadata: XdpRxMetadata,
    /// The TX metadata features available
    pub tx_metadata: XdpTxMetadata,
}

/// The number of queues available for the interface
///
/// Generally speaking, the number of RX and TX queues will be the same, and the
/// current for each will be the minimum of the number of queues actually supported
/// by the NIC hardware device, and number of logical CPUs on the machine
#[derive(Copy, Clone)]
pub struct Queues {
    /// The maximum number of RX queues
    pub rx_max: u32,
    /// The current number of RX queues
    pub rx_current: u32,
    /// The maximum number of TX queues
    pub tx_max: u32,
    /// The current number of TX queues
    pub tx_current: u32,
}

/// A network interface
#[derive(Copy, Clone)]
pub struct NicIndex(pub u32);

impl NicIndex {
    /// Creates a new [`Self`], but using it will fail various syscalls if the
    /// index is not actually valid
    #[inline]
    pub fn new(index: u32) -> Self {
        Self(index)
    }

    /// Attempts to look up the NIC by name
    ///
    /// # Returns
    ///
    /// `None` if the interface cannot be found
    #[inline]
    pub fn lookup_by_name(ifname: &std::ffi::CStr) -> std::io::Result<Option<Self>> {
        // SAFETY: syscall, we give it a valid pointer
        let res = unsafe { iface::if_nametoindex(ifname.as_ptr().cast()) };

        if res == 0 {
            let err = std::io::Error::last_os_error();

            if err.raw_os_error() == Some(iface::ENODEV) {
                Ok(None)
            } else {
                Err(err)
            }
        } else {
            Ok(Some(Self(res)))
        }
    }

    /// Retrieves the interface's name
    #[inline]
    pub fn name(&self) -> std::io::Result<NicName> {
        let mut name = [0; iface::IF_NAMESIZE];
        // SAFETY: syscall, we give it a valid pointer
        if unsafe { !iface::if_indextoname(self.0, name.as_mut_ptr()).is_null() } {
            let len = name
                .iter()
                .position(|n| *n == 0)
                .unwrap_or(iface::IF_NAMESIZE);
            Ok(NicName { arr: name, len })
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    /// Retrieves the [`std::net::Ipv4Addr`] and/or [`std::net::Ipv6Addr`] associated
    /// with this network interface
    pub fn addresses(
        &self,
    ) -> std::io::Result<(Option<std::net::Ipv4Addr>, Option<std::net::Ipv6Addr>)> {
        // SAFETY: syscalls
        unsafe {
            let mut ifaddrs = std::mem::MaybeUninit::<*mut iface::ifaddrs>::uninit();
            if iface::getifaddrs(ifaddrs.as_mut_ptr()) != 0 {
                return Err(std::io::Error::last_os_error());
            }

            let ifaddrs = ifaddrs.assume_init();
            let mut cur = ifaddrs.as_ref();

            struct Ifaddrs(*mut iface::ifaddrs);
            impl Drop for Ifaddrs {
                fn drop(&mut self) {
                    // SAFETY: syscall, we validate the pointer before allowing it to be freed
                    unsafe { iface::freeifaddrs(self.0) };
                }
            }

            let _ifa = Ifaddrs(ifaddrs);
            let name = self.name()?;

            let mut ipv4 = None;
            let mut ipv6 = None;

            while let Some(ifaddr) = cur {
                cur = ifaddr.ifa_next.as_ref();

                if iface::strncmp(name.arr.as_ptr(), ifaddr.ifa_name, name.len) != 0 {
                    continue;
                }

                let Some(addr) = ifaddr.ifa_addr.as_ref() else {
                    continue;
                };

                match addr.sa_family as socket::AddressFamily::Enum {
                    socket::AddressFamily::AF_INET => {
                        let addr = &*ifaddr.ifa_addr.cast::<socket::sockaddr_in>();
                        ipv4 = Some(std::net::Ipv4Addr::from_bits(u32::from_be(addr.sin_addr)));
                    }
                    socket::AddressFamily::AF_INET6 => {
                        let addr = &*ifaddr.ifa_addr.cast::<socket::sockaddr_in6>();
                        ipv6 = Some(addr.sin6_addr.into());
                    }
                    _ => continue,
                }
            }

            Ok((ipv4, ipv6))
        }
    }

    /// Attempts to determine the queue count of this NIC
    ///
    /// For normal consumer NICs this will usually be 1, but server NICs will
    /// generally have more. Typically, one will want to bind an `AF_XDP` to each
    /// queue, spreading RX/TX across multiple CPUs.
    ///
    /// # Returns
    ///
    /// The first number is the maximum queue count supported by the NIC, the
    /// second is the current queue count. It will often be the case that the
    /// current queue count will be the lowest value of the max queue count and
    /// the number of CPUs.
    ///
    /// # Notes
    ///
    /// This function is a reimplementation of [`xsk_get_max_queues`](https://github.com/xdp-project/xdp-tools/blob/3b199c0c185d4603406e6324ca5783b157c0e492/lib/libxdp/xsk.c#L457-L523)
    pub fn queue_count(&self) -> std::io::Result<Queues> {
        use std::os::fd::{AsRawFd, FromRawFd};

        // SAFETY: syscall
        let socket = unsafe {
            let fd = socket::socket(socket::AddressFamily::AF_LOCAL, socket::Kind::SOCK_DGRAM, 0);
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }

            std::os::fd::OwnedFd::from_raw_fd(fd)
        };

        // https://github.com/torvalds/linux/blob/cdd30ebb1b9f36159d66f088b61aee264e649d7a/include/uapi/linux/ethtool.h#L536-L562
        #[repr(C)]
        struct Channels {
            cmd: u32,
            max_rx: u32,
            max_tx: u32,
            max_other: u32,
            max_combined: u32,
            rx_count: u32,
            tx_count: u32,
            other_count: u32,
            combined_count: u32,
        }

        // https://github.com/torvalds/linux/blob/cdd30ebb1b9f36159d66f088b61aee264e649d7a/include/uapi/linux/ethtool.h#L1915
        const ETHTOOL_GCHANNELS: u32 = 0x0000003c;

        // SAFETY: POD
        let mut channels: Channels = unsafe { std::mem::zeroed() };
        channels.cmd = ETHTOOL_GCHANNELS;

        // SAFETY: POD
        let mut ifr: iface::ifreq = unsafe { std::mem::zeroed() };
        ifr.ifr_ifru.ifru_data = (&mut channels as *mut Channels).cast();

        let name = self.name()?;
        ifr.ifr_name[..name.len].copy_from_slice(&name.arr[..name.len]);

        // SAFETY: The inputs are valid, so this should be fine
        if unsafe {
            iface::ioctl(
                socket.as_raw_fd(),
                iface::SIOCETHTOOL,
                &mut ifr as *mut iface::ifreq,
            )
        } != 0
        {
            // We failed to use the ioctl, so fallback to the filesystem, which
            // might be less accurate, but better than nothing

            const PREFIX: &[u8] = b"/sys/class/net/";
            const SUFFIX: &[u8] = b"/queues/";

            const MAX: usize = PREFIX.len() + iface::IF_NAMESIZE + SUFFIX.len() + 1;

            // This directory will contain directory named rx-{id} and tx-{id}
            // Note we use libc to read the directory because std::fs::read_dir
            // forces us to do a heap allocation to get the name of each entry
            // which is...extremely wasteful
            // SAFETY: syscalls
            unsafe {
                let mut dir_path = [0; MAX];
                let mut start = 0;
                dir_path[start..start + PREFIX.len()].copy_from_slice(std::slice::from_raw_parts(
                    PREFIX.as_ptr().cast(),
                    PREFIX.len(),
                ));
                start += PREFIX.len();
                dir_path[start..start + name.len].copy_from_slice(&name.arr[..name.len]);
                start += name.len;
                dir_path[start..start + SUFFIX.len()].copy_from_slice(std::slice::from_raw_parts(
                    SUFFIX.as_ptr().cast(),
                    SUFFIX.len(),
                ));

                let dir = iface::opendir(dir_path.as_ptr());
                if dir.is_null() {
                    return Err(std::io::Error::last_os_error());
                }

                struct Dir(*mut iface::DIR);
                impl Drop for Dir {
                    fn drop(&mut self) {
                        // SAFETY: we only construct with a valid DIR
                        unsafe {
                            iface::closedir(self.0);
                        }
                    }
                }

                let dir = Dir(dir);

                // These _should_ be zero if the ioctl fails, but just in case
                channels = std::mem::zeroed();

                while let Some(entry) = iface::readdir(dir.0).as_ref() {
                    if entry.d_type != iface::DT_DIR {
                        continue;
                    }

                    if entry.d_name[..2] == [b'r', b'x'] {
                        channels.max_rx += 1;
                        channels.rx_count += 1;
                    } else if entry.d_name[..2] == [b't', b'x'] {
                        channels.max_tx += 1;
                        channels.tx_count += 1;
                    }
                }
            }
        }

        Ok(Queues {
            rx_max: channels.max_rx.max(channels.max_combined),
            rx_current: channels.rx_count.max(channels.combined_count),
            tx_max: channels.max_tx.max(channels.max_combined),
            tx_current: channels.tx_count.max(channels.combined_count),
        })
    }

    /// Queries the network device's available features
    pub fn query_capabilities(&self) -> std::io::Result<NetdevCapabilities> {
        std::thread::scope(|s| -> std::io::Result<NetdevCapabilities> {
            let qc = s.spawn(|| self.queue_count().map_or(1, |queues| queues.rx_current));

            let ndc = s.spawn(|| -> std::io::Result<NetdevCapabilities> { self.netdev_caps() });

            let queue_count = qc.join().map_err(|_e| {
                std::io::Error::new(
                    std::io::ErrorKind::Deadlock,
                    "panic occurred querying queue count",
                )
            })?;
            let mut ndc = ndc.join().map_err(|_e| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "panic occurred query device caps",
                )
            })??;
            ndc.queue_count = queue_count;
            Ok(ndc)
        })
    }
}

impl From<NicIndex> for u32 {
    fn from(value: NicIndex) -> Self {
        value.0
    }
}

use std::fmt;

impl fmt::Debug for NicIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // attempt to retrieve the name via the index
        if let Ok(name) = self.name() {
            write!(f, "{} \"{}\"", self.0, name.as_str().unwrap_or("unknown"))
        } else {
            write!(f, "{} \"unknown\"", self.0)
        }
    }
}

impl PartialEq<u32> for NicIndex {
    fn eq(&self, other: &u32) -> bool {
        self.0 == *other
    }
}

impl PartialEq<NicIndex> for NicIndex {
    fn eq(&self, other: &NicIndex) -> bool {
        self.0 == other.0
    }
}

/// The human-readable name assigned to a network device
#[derive(Copy, Clone)]
pub struct NicName {
    arr: [u8; iface::IF_NAMESIZE],
    len: usize,
}

impl NicName {
    /// Attempts to get the utf-8 interface name, will return `None` in the
    /// unlikely case the interface name is not utf-8
    #[inline]
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.arr[..self.len]).ok()
    }
}

impl fmt::Debug for NicName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(s) = self.as_str() {
            f.write_str(s)
        } else {
            f.write_str("non utf-8")
        }
    }
}

impl fmt::Display for NicName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(s) = self.as_str() {
            f.write_str(s)
        } else {
            f.write_str("non utf-8")
        }
    }
}

/// Iterator over interfaces that are currently `UP`
///
/// Note that the same interface can be returned multiple times if it has multiple
/// routes
pub struct InterfaceIter {
    routes: String,
    pos: usize,
}

impl InterfaceIter {
    /// Attempts to create the iterator
    #[inline]
    pub fn new() -> std::io::Result<Self> {
        let routes = std::fs::read_to_string("/proc/net/route")?;

        // Skip the header line
        let pos = routes.find('\n').ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "route table didn't have a newline",
        ))? + 1;

        Ok(Self { routes, pos })
    }
}

impl Iterator for InterfaceIter {
    type Item = NicIndex;

    fn next(&mut self) -> Option<Self::Item> {
        const IS_UP: u16 = iface::RTF_UP | iface::RTF_GATEWAY;

        loop {
            let end = self.routes[self.pos..].find('\n')?;
            let line = &self.routes[self.pos..self.pos + end];
            self.pos = self.pos + end + 1;

            let mut iter = line.split(char::is_whitespace).filter_map(|s| {
                let s = s.trim();
                (!s.is_empty()).then_some(s)
            });

            let Some(name) = iter.next() else {
                continue;
            };
            let Some(flags) = iter.nth(2).and_then(|f| u16::from_str_radix(f, 16).ok()) else {
                continue;
            };

            if flags & IS_UP != IS_UP {
                continue;
            }

            let mut ifname = [0u8; iface::IF_NAMESIZE];
            ifname[..name.len()].copy_from_slice(name.as_bytes());
            ifname[name.len()] = 0;

            let Ok(Some(iface)) = NicIndex::lookup_by_name(
                // SAFETY: we ensure there is a null byte at the end
                unsafe { std::ffi::CStr::from_bytes_with_nul_unchecked(&ifname) },
            ) else {
                continue;
            };

            return Some(iface);
        }
    }
}

#[cfg(test)]
mod test {
    #[test]
    #[cfg_attr(miri, ignore)]
    fn gets_features() {
        let nic = super::InterfaceIter::new().unwrap().next().unwrap();
        nic.query_capabilities().unwrap();
    }
}
