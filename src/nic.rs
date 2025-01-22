//! Utilities for querying NIC capabilities

#[cfg(test)]
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

#[derive(Copy, Clone)]
pub struct NicName {
    arr: [i8; libc::IF_NAMESIZE],
    len: usize,
}

impl NicName {
    #[inline]
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(unsafe {
            std::slice::from_raw_parts(self.arr.as_ptr().cast(), self.len)
        })
        .ok()
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

#[derive(Copy, Clone)]
pub enum XdpModes {
    /// Socket buffer mode, doesn't require driver support, but means all XDP
    /// advantages are lost due to the higher level network stack being involved
    /// and copies into user space memory
    Skb = 1 << 1,
    /// Driver mode, the driver supports XDP allowing bypass of the higher level
    /// network stack, and potentially zero copies, if the packet is redirected,
    /// dropped, or retransmitted
    Drv = 1 << 2,
    /// Hardware mode, allows offload of the eBPF program from the kernel to
    /// the device itself for maximum performance. Extremely few devices support
    /// this.
    Hardware = 1 << 3,
}

#[derive(Copy, Clone)]
#[cfg_attr(test, derive(Debug))]
pub enum XdpZeroCopy {
    Unavailable,
    Available,
    MultiBuffer(u32),
}

impl XdpZeroCopy {
    /// True if the zero copy feature is available
    #[inline]
    pub fn is_available(&self) -> bool {
        !matches!(self, Self::Unavailable)
    }
}

#[derive(Copy, Clone)]
pub struct XdpFeatures(u64);

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

    Mask = (1 << 7) - 1,
}

#[cfg(test)]
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

#[derive(Copy, Clone)]
pub struct XdpRxMetadata(u64);

#[cfg(test)]
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

#[repr(u64)]
pub enum RxMetadataFlags {
    /// Device is capable of exposing receive HW timestamp via [`bpf_xdp_metadata_rx_timestamp`](https://docs.ebpf.io/linux/kfuncs/bpf_xdp_metadata_rx_timestamp/)
    Timestamp = 1 << 0,
    /// Device is capable of exposing receive packet hash via [`bpf_xdp_metadata_rx_hash`](https://docs.ebpf.io/linux/kfuncs/bpf_xdp_metadata_rx_hash/)
    Hash = 1 << 1,
    /// Device is capable of exposing receive packet VLAN tag via [`bpf_xdp_metadata_rx_vlan_tag`](https://docs.ebpf.io/linux/kfuncs/bpf_xdp_metadata_rx_vlan_tag/)
    VlanTag = 1 << 2,
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

#[derive(Copy, Clone)]
pub struct XdpTxMetadata(u64);

#[cfg(test)]
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

#[repr(u64)]
pub enum TxMetadataFlags {
    /// HW timestamping egress packets is supported by the driver.
    Timestamp = 1 << 0,
    /// L4 checksum HW offload is supported by the driver.
    Checksum = 1 << 1,
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

#[cfg_attr(test, derive(Debug))]
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

#[derive(Copy, Clone)]
pub struct NicIndex(pub(crate) u32);

impl NicIndex {
    pub fn new(index: u32) -> Self {
        Self(index)
    }

    /// Attempts to look up the NIC by name
    ///
    /// # Returns
    ///
    /// `None` if the interface cannot be found
    #[inline]
    pub fn lookup_by_name(s: &str) -> std::io::Result<Option<Self>> {
        unsafe {
            let ifname = std::ffi::CString::new(s)?;
            let res = libc::if_nametoindex(ifname.as_ptr());
            if res == 0 {
                let err = std::io::Error::last_os_error();

                if err.raw_os_error() == Some(libc::ENODEV) {
                    Ok(None)
                } else {
                    Err(err)
                }
            } else {
                Ok(Some(Self(res)))
            }
        }
    }

    /// Retrieves the interface's name
    #[inline]
    pub fn name(&self) -> std::io::Result<NicName> {
        let mut name = [0; libc::IF_NAMESIZE];
        if unsafe { !libc::if_indextoname(self.0, name.as_mut_ptr()).is_null() } {
            let len = name
                .iter()
                .position(|n| *n == 0)
                .unwrap_or(libc::IF_NAMESIZE);
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
        unsafe {
            let mut ifaddrs = std::mem::MaybeUninit::<*mut libc::ifaddrs>::uninit();
            if libc::getifaddrs(ifaddrs.as_mut_ptr()) != 0 {
                return Err(std::io::Error::last_os_error());
            }

            let ifaddrs = ifaddrs.assume_init();
            let mut cur = ifaddrs.as_ref();

            struct Ifaddrs(*mut libc::ifaddrs);
            impl Drop for Ifaddrs {
                fn drop(&mut self) {
                    unsafe { libc::freeifaddrs(self.0) };
                }
            }

            let _ifa = Ifaddrs(ifaddrs);
            let name = self.name()?;

            let mut ipv4 = None;
            let mut ipv6 = None;

            while let Some(ifaddr) = cur {
                cur = ifaddr.ifa_next.as_ref();

                if libc::strncmp(name.arr.as_ptr(), ifaddr.ifa_name, name.len as _) != 0 {
                    continue;
                }

                let Some(addr) = ifaddr.ifa_addr.as_ref() else {
                    continue;
                };

                match addr.sa_family as libc::c_int {
                    libc::AF_INET => {
                        let addr = &*ifaddr.ifa_addr.cast::<libc::sockaddr_in>();
                        ipv4 = Some(std::net::Ipv4Addr::from_bits(u32::from_be(
                            addr.sin_addr.s_addr,
                        )));
                    }
                    libc::AF_INET6 => {
                        let addr = &*ifaddr.ifa_addr.cast::<libc::sockaddr_in6>();
                        ipv6 = Some(addr.sin6_addr.s6_addr.into());
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
    pub fn queue_count(&self) -> std::io::Result<(u32, u32)> {
        use std::os::fd::{AsRawFd, FromRawFd};

        // SAFETY: syscall
        let socket = unsafe {
            let fd = libc::socket(libc::AF_LOCAL, libc::SOCK_DGRAM, 0);
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
        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        ifr.ifr_ifru.ifru_data = (&mut channels as *mut Channels).cast();

        let name = self.name()?;
        ifr.ifr_name[..name.len].copy_from_slice(&name.arr[..name.len]);

        // SAFETY: The inputs are valid, so this should be fine
        if unsafe {
            libc::ioctl(
                socket.as_raw_fd(),
                libc::SIOCETHTOOL,
                &mut ifr as *mut libc::ifreq,
            )
        } != 0
        {
            // We failed to use the ioctl, so fallback to the filesystem, which
            // might be less accurate, but better than nothing

            const PREFIX: &[u8] = b"/sys/class/net/";
            const SUFFIX: &[u8] = b"/queues/";

            const MAX: usize = PREFIX.len() + libc::IF_NAMESIZE + SUFFIX.len() + 1;

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

                let dir = libc::opendir(dir_path.as_ptr());
                if dir.is_null() {
                    return Err(std::io::Error::last_os_error());
                }

                struct Dir(*mut libc::DIR);
                impl Drop for Dir {
                    fn drop(&mut self) {
                        // SAFETY: we only construct with a valid DIR
                        unsafe {
                            libc::closedir(self.0);
                        }
                    }
                }

                let dir = Dir(dir);

                // These _should_ be zero if the ioctl fails, but just in case
                channels = std::mem::zeroed();

                while let Some(entry) = libc::readdir(dir.0).as_ref() {
                    if entry.d_type != libc::DT_DIR {
                        continue;
                    }

                    if entry.d_name[..2] == [b'r' as i8, b'x' as i8] {
                        channels.max_rx += 1;
                        channels.rx_count += 1;
                    } else if entry.d_name[..2] == [b't' as i8, b'x' as i8] {
                        channels.max_tx += 1;
                        channels.tx_count += 1;
                    }
                }
            }
        }

        Ok((
            channels
                .max_rx
                .max(channels.max_tx)
                .max(channels.max_combined),
            channels
                .rx_count
                .max(channels.tx_count)
                .max(channels.combined_count),
        ))
    }

    /// Queries the network device's available features
    pub fn query_capabilities(&self) -> std::io::Result<NetdevCapabilities> {
        let mut queue_count = 0;
        let mut xdp_features = 0;
        let mut zero_copy_max_segs = 0u32;
        let mut rx_metadata_features = 0;
        let mut xsk_features = 0;

        std::thread::scope(|s| {
            s.spawn(|| {
                queue_count = self.queue_count().map_or(1, |(_max, count)| count);
            });

            s.spawn(|| -> Result<(), neli::err::SerError> {
                const GENL_VERSION: u8 = 2;

                let mut socket = neli::socket::NlSocketHandle::connect(
                    neli::consts::socket::NlFamily::Generic,
                    None,
                    &[],
                )?;

                let id = socket
                    .resolve_genl_family("netdev")
                    .map_err(|err| match err {
                        neli::err::NlError::Ser(ser) => ser,
                        neli::err::NlError::Msg(msg) => neli::err::SerError::Msg(msg),
                        neli::err::NlError::Wrapped(w) => neli::err::SerError::Wrapped(w),
                        other => neli::err::SerError::Msg(other.to_string()),
                    })?;

                #[derive(Copy, Clone, Debug, PartialEq)]
                #[repr(u16)]
                enum Netdev {
                    IfIndex = 1,
                    Pad,
                    XdpFeatures,
                    XdpZeroCopyMaxSegments,
                    XdpRxMetadataFeatures,
                    XskFeatures,
                    Unknown(u16),
                }

                impl neli::ToBytes for Netdev {
                    fn to_bytes(
                        &self,
                        buffer: &mut std::io::Cursor<Vec<u8>>,
                    ) -> Result<(), neli::err::SerError> {
                        u16::from(*self).to_bytes(buffer)
                    }
                }

                impl From<u16> for Netdev {
                    fn from(val: u16) -> Self {
                        match val {
                            1 => Self::IfIndex,
                            2 => Self::Pad,
                            3 => Self::XdpFeatures,
                            4 => Self::XdpZeroCopyMaxSegments,
                            5 => Self::XdpRxMetadataFeatures,
                            6 => Self::XskFeatures,
                            o => Self::Unknown(o),
                        }
                    }
                }

                impl From<Netdev> for u16 {
                    fn from(value: Netdev) -> Self {
                        match value {
                            Netdev::IfIndex => 1,
                            Netdev::Pad => 2,
                            Netdev::XdpFeatures => 3,
                            Netdev::XdpZeroCopyMaxSegments => 4,
                            Netdev::XdpRxMetadataFeatures => 5,
                            Netdev::XskFeatures => 6,
                            Netdev::Unknown(o) => o,
                        }
                    }
                }

                impl<'a> neli::FromBytes<'a> for Netdev {
                    fn from_bytes(
                        buffer: &mut std::io::Cursor<&'a [u8]>,
                    ) -> Result<Self, neli::err::DeError> {
                        let val = <u16 as neli::FromBytes>::from_bytes(buffer)?;
                        Ok(Self::from(val))
                    }
                }

                impl neli::Size for Netdev {
                    fn unpadded_size(&self) -> usize {
                        std::mem::size_of::<u16>()
                    }
                }

                impl neli::TypeSize for Netdev {
                    fn type_size() -> usize {
                        std::mem::size_of::<u16>()
                    }
                }

                impl neli::consts::genl::NlAttrType for Netdev {}

                let mut attrs = neli::types::GenlBuffer::<_, neli::types::Buffer>::new();
                attrs.push(neli::genl::Nlattr::new(
                    false,
                    false,
                    Netdev::IfIndex,
                    self.0,
                )?);

                const NETDEV_CMD_DEV_GET: u8 = 1;

                let genlhdr = neli::genl::Genlmsghdr::new(NETDEV_CMD_DEV_GET, GENL_VERSION, attrs);
                let nlhdr = neli::nl::Nlmsghdr::new(
                    None,
                    id,
                    neli::consts::nl::NlmFFlags::new(&[neli::consts::nl::NlmF::Request]),
                    None,
                    None,
                    neli::nl::NlPayload::Payload(genlhdr),
                );

                socket.send(nlhdr)?;

                let mut iter =
                    socket.iter::<neli::consts::nl::Nlmsg, neli::genl::Genlmsghdr<u8, _>>(false);

                fn get_attr<T: Copy + Clone>(
                    handle: &neli::attr::AttrHandle<
                        '_,
                        neli::types::GenlBuffer<Netdev, neli::types::Buffer>,
                        neli::genl::Nlattr<Netdev, neli::types::Buffer>,
                    >,
                    which: Netdev,
                ) -> Option<T> {
                    let attr = handle.get_attribute(which)?;
                    if attr.nla_payload.len() != std::mem::size_of::<T>() {
                        return None;
                    }

                    Some(unsafe { *attr.nla_payload.as_ref().as_ptr().cast::<T>() })
                }

                while let Some(Ok(msg)) = iter.next() {
                    let Some(payload) = msg.nl_payload.get_payload() else {
                        continue;
                    };

                    let attrs = payload.get_attr_handle();

                    let Some(if_index) = get_attr::<u32>(&attrs, Netdev::IfIndex) else {
                        continue;
                    };
                    if if_index != self.0 {
                        continue;
                    }
                    if let Some(xdp_attr) = get_attr::<u64>(&attrs, Netdev::XdpFeatures) {
                        xdp_features = xdp_attr;

                        zero_copy_max_segs =
                            get_attr::<u32>(&attrs, Netdev::XdpZeroCopyMaxSegments).unwrap_or(0);
                        rx_metadata_features =
                            get_attr::<u64>(&attrs, Netdev::XdpRxMetadataFeatures).unwrap_or(0);
                        xsk_features = get_attr::<u64>(&attrs, Netdev::XskFeatures).unwrap_or(0);
                    }
                }

                Ok(())
            });
        });

        Ok(NetdevCapabilities {
            queue_count,
            zero_copy: match zero_copy_max_segs {
                0 => XdpZeroCopy::Unavailable,
                1 => XdpZeroCopy::Available,
                o => XdpZeroCopy::MultiBuffer(o),
            },
            xdp_features: XdpFeatures(xdp_features),
            rx_metadata: XdpRxMetadata(rx_metadata_features),
            tx_metadata: XdpTxMetadata(xsk_features),
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

// #[cfg(test)]
// mod test {
//     #[test]
//     fn gets_features() {
//         let nic = super::NicIndex::lookup_by_name("enp117s0f1")
//             .unwrap()
//             .unwrap();
//         dbg!(nic.query_capabilities().unwrap());
//     }
// }
