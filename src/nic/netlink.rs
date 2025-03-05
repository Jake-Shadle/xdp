#![allow(non_camel_case_types)]

use crate::{libc::socket, packet::Pod};
use std::{
    io::{Error, ErrorKind, Result},
    mem,
    os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd},
};

/// Types for [`nlmsghdr::nlmsg_type`]
///
/// <include/uapi/linux/netlink.h>
mod msg_kind {
    pub type Enum = u16;

    //pub const NOOP: Enum = 1;
    pub const ERROR: Enum = 2;
    pub const DONE: Enum = 3;
    //pub const OVERRUN: Enum = 4;

    pub const GENL_ID_CTRL: Enum = 0x10;
}

/// Flags for [`nlmsghdr::nlmsg_flags`]
///
/// <include/uapi/linux/netlink.h>>
mod msg_flags {
    pub type Enum = u16;

    /// It is a request message
    pub const REQUEST: Enum = 0x01;
    // Multipart message, terminated by [`msg_kind::DONE`]
    pub const MULTI: Enum = 0x02;

    /// Extended ACK TVLs were included
    pub const ACK_TLVS: Enum = 0x200;

    pub const NESTED: Enum = 1 << 15;
    pub const NET_BYTEORDER: Enum = 1 << 14;

    pub const TYPE_MASK: Enum = !(NESTED | NET_BYTEORDER);
}

/// Generic netlink constants
///
/// <include/uapi/linux/genetlink.h>
mod generic {
    pub const CTRL_CMD_GETFAMILY: u8 = 3;

    pub const CTRL_ATTR_FAMILY_ID: u16 = 1;
    pub const CTRL_ATTR_FAMILY_NAME: u16 = 2;
}

/// netdev constants
///
/// <include/uapi/linux/netdev.h>
mod netdev {
    pub const NETDEV_CMD_DEV_GET: u8 = 1;

    pub const NETDEV_A_DEV_IFINDEX: u16 = 1;
    pub const NETDEV_A_DEV_XDP_FEATURES: u16 = 3;
    pub const NETDEV_A_DEV_XDP_ZC_MAX_SEGS: u16 = 4;
    pub const NETDEV_A_DEV_XDP_RX_METADATA_FEATURES: u16 = 5;
    pub const NETDEV_A_DEV_XSK_FEATURES: u16 = 6;
}

const GENL_VERSION: u8 = 2;
const NETLINK_EXT_ACK: i32 = 11;
const NLMSGERR_ATTR_MSG: u16 = 1;

macro_rules! len {
    ($record:ty) => {
        // SAFETY: internal only
        unsafe impl Pod for $record {}

        impl $record {
            /// The length in bytes of this type
            const LEN: usize = mem::size_of::<$record>();
        }
    };
}

#[repr(C)]
struct sockaddr_nl {
    nl_family: u16,
    nl_pad: u16,
    nl_pid: u32,
    nl_groups: u32,
}

/// Fixed format metadata header of Netlink messages
#[repr(C)]
struct nlmsghdr {
    /// Length of message including header
    nlmsg_len: u32,
    /// Message content type
    nlmsg_type: msg_kind::Enum,
    /// Additional flags
    nlmsg_flags: msg_flags::Enum,
    /// Sequence number
    nlmsg_seq: u32,
    /// Sending process port ID
    nlmsg_pid: u32,
}

len!(nlmsghdr);

/// netlink uses 4 byte alignment
#[inline]
const fn align(len: usize) -> usize {
    (len + 3) & !3
}

/// Generic netlink metadata header
#[repr(C)]
struct genlmsghdr {
    cmd: u8,
    version: u8,
    __reserved: u16,
}

len!(genlmsghdr);

#[repr(C)]
struct nlattr {
    nla_len: u16,
    nla_type: u16,
}

len!(nlattr);

#[repr(C)]
struct nlmsgerr {
    /// The error code, 0 for no error
    error: i32,
    /// The original request
    msg: nlmsghdr,
}

len!(nlmsgerr);

struct Buf<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> Buf<N> {
    #[inline]
    fn new() -> Self {
        Self {
            buf: [0u8; N],
            len: 0,
        }
    }

    #[inline]
    fn read<P: Pod>(&self, off: &mut usize) -> Result<P> {
        if *off > N || *off + P::size() > self.len {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "received incomplete netlink packet",
            ));
        }

        let p =
            // SAFETY: we've validated we'll only read within bounds
            unsafe { std::ptr::read_unaligned(self.buf.as_ptr().byte_offset(*off as _).cast()) };
        *off += P::size();
        Ok(p)
    }

    #[inline]
    fn write<P: Pod>(&mut self, off: &mut usize, item: P) -> Result<()> {
        assert!(
            *off < N && *off + P::size() <= self.len,
            "this indicates a bug in the netlink code, please file an issue"
        );

        // SAFETY: we've validated we'll only write within bounds
        unsafe {
            std::ptr::write_unaligned(self.buf.as_mut_ptr().byte_offset(*off as _).cast(), item);
        };
        *off += P::size();
        Ok(())
    }

    #[inline]
    fn push<P: Pod>(&mut self, data: P) -> Result<()> {
        if self.len + P::size() > N {
            return Err(Error::new(
                ErrorKind::OutOfMemory,
                "unable to append data to buffer, it would overflow",
            ));
        }

        self.buf[self.len..self.len + P::size()].copy_from_slice(data.as_bytes());
        self.len += P::size();
        Ok(())
    }

    #[inline]
    fn push_attribute(&mut self, kind: u16, data: &[u8]) -> Result<()> {
        let tail = align(self.len);
        if tail + align(nlattr::LEN + data.len()) > N {
            return Err(Error::new(
                ErrorKind::OutOfMemory,
                "unable to append attribute to buffer, it would overflow",
            ));
        }

        let attr_len = {
            let attr_len = nlattr::LEN + data.len();

            self.len = tail;
            self.push(nlattr {
                nla_type: kind,
                nla_len: attr_len as u16,
            })?;
            self.buf[self.len..self.len + data.len()].copy_from_slice(data);

            attr_len
        };

        self.len = tail + align(attr_len);
        Ok(())
    }
}

struct AttrIter<'b, const N: usize> {
    buf: &'b Buf<N>,
    off: &'b mut usize,
    len: usize,
}

impl<'b, const N: usize> AttrIter<'b, N> {
    fn generic(buf: &'b Buf<N>, msg_hdr: &nlmsghdr, off: &'b mut usize) -> Result<Self> {
        let _gen_hdr = buf.read::<genlmsghdr>(off)?;
        *off = align(*off);
        let len = msg_hdr.nlmsg_len as usize - align(genlmsghdr::LEN) - nlmsghdr::LEN;

        Ok(Self { buf, off, len })
    }

    fn error(buf: &'b Buf<N>, msg_hdr: &nlmsghdr, _err_msg: &nlmsgerr, off: &'b mut usize) -> Self {
        let len = msg_hdr.nlmsg_len as usize - align(nlmsgerr::LEN) - nlmsghdr::LEN;
        Self { buf, off, len }
    }
}

impl<'b, const N: usize> Iterator for AttrIter<'b, N> {
    type Item = (u16, &'b [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.len < nlattr::LEN {
            return None;
        }

        let mut off = *self.off;
        let attr = self.buf.read::<nlattr>(&mut off).ok()?;
        let kind = attr.nla_type & msg_flags::TYPE_MASK;
        let tot_len = align(attr.nla_len as usize);
        let data_len = attr.nla_len as usize - nlattr::LEN;

        if tot_len > self.len {
            return None;
        }

        let data = &self.buf.buf[off..off + data_len];

        self.len -= tot_len;
        *self.off += tot_len;

        Some((kind, data))
    }
}

impl<const N: usize> Drop for AttrIter<'_, N> {
    fn drop(&mut self) {
        *self.off += self.len;
    }
}

macro_rules! io_err {
    ($val:expr) => {{
        if $val < 0 {
            return Err(std::io::Error::last_os_error());
        }

        $val as _
    }};
}

struct NetlinkSocket {
    sock: OwnedFd,
    seq: u32,
}

impl NetlinkSocket {
    fn send_and_recv<const N: usize, T>(
        &mut self,
        msg: &mut Buf<N>,
        func: impl Fn(AttrIter<'_, N>) -> Result<Option<T>>,
    ) -> Result<Option<T>> {
        let seq = self.seq;
        self.seq += 1;

        // SAFETY: various syscalls and buffer manipulation
        unsafe {
            let mut off = 0;
            let len = msg.len;

            let mut hdr = msg.read::<nlmsghdr>(&mut off)?;
            off = 0;
            hdr.nlmsg_seq = seq;
            hdr.nlmsg_len = len as _;
            msg.write(&mut off, hdr)?;

            let sent: usize = io_err!(socket::send(
                self.sock.as_raw_fd(),
                msg.buf.as_ptr().cast(),
                msg.len,
                socket::MsgFlags::NONE
            ));

            if sent != msg.len {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::FileTooLarge,
                    "failed to send full nlmsg",
                ));
            }

            let mut is_multi_part = true;

            while is_multi_part {
                msg.len = io_err!(socket::recv(
                    self.sock.as_raw_fd(),
                    msg.buf.as_mut_ptr().cast(),
                    N,
                    socket::MsgFlags::NONE
                ));
                is_multi_part = false;

                let mut offset = 0;
                while offset < msg.len {
                    let msg_hdr = msg.read::<nlmsghdr>(&mut offset)?;
                    if msg_hdr.nlmsg_flags & msg_flags::MULTI != 0 {
                        is_multi_part = true;
                    }

                    if msg_hdr.nlmsg_seq != seq {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            "invalid sequence in netlink response",
                        ));
                    }

                    match msg_hdr.nlmsg_type {
                        msg_kind::ERROR => {
                            let err_hdr = msg.read::<nlmsgerr>(&mut offset)?;
                            if err_hdr.error != 0 {
                                // Query if the message has extended error information
                                let message = if msg_hdr.nlmsg_flags & msg_flags::ACK_TLVS != 0 {
                                    // We could also recover the offset of the failing attribute, but considering
                                    // we only do 2 requests and both have a single attribute..
                                    AttrIter::error(msg, &msg_hdr, &err_hdr, &mut offset).find_map(|(kind, data)| {
                                        (kind == NLMSGERR_ATTR_MSG).then_some(String::from_utf8_lossy(&data[..data.len() - 2]).into_owned())
                                    }).unwrap_or_else(|| format!("received netlink error code {}, and we failed to retrieve the additional information provided by the kernel", err_hdr.error))
                                } else {
                                    format!(
                                        "received netlink error code {}, and no additional error information was provided by the kernel",
                                        err_hdr.error
                                    )
                                };

                                return Err(Error::new(ErrorKind::ConnectionRefused, message));
                            } else {
                                offset = align(msg_hdr.nlmsg_len as usize);
                            }
                        }
                        msg_kind::DONE => {
                            return Ok(None);
                        }
                        _other => {
                            let res = func(AttrIter::generic(msg, &msg_hdr, &mut offset)?)?;
                            if res.is_some() {
                                return Ok(res);
                            }
                        }
                    }
                }
            }

            Ok(None)
        }
    }
}

macro_rules! read_attr {
    ($kind:ty, $attr:expr) => {{
        if $attr.len() != std::mem::size_of::<$kind>() {
            None
        } else {
            let mut bytes = [0u8; std::mem::size_of::<$kind>()];
            bytes.copy_from_slice($attr);
            Some(<$kind>::from_ne_bytes(bytes))
        }
    }};
}

impl super::NicIndex {
    pub(super) fn netdev_caps(&self) -> std::io::Result<super::NetdevCapabilities> {
        // SAFETY: We validate the socket descriptor
        let mut socket = unsafe {
            let fd = socket::socket(
                socket::AddressFamily::AF_NETLINK,
                socket::Kind::SOCK_RAW,
                socket::Protocol::NETLINK_GENERIC,
            );

            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }

            NetlinkSocket {
                sock: OwnedFd::from_raw_fd(fd),
                seq: 0xfeedfeed,
            }
        };

        // SAFETY: POD + we give a valid sockaddr to bind
        unsafe {
            // Enable extended ack, which can give use more detail error information
            let enable = 1;
            socket::setsockopt(
                socket.sock.as_raw_fd(),
                socket::Level::SOL_NETLINK,
                NETLINK_EXT_ACK,
                (&enable as *const i32).cast(),
                mem::size_of_val(&enable) as _,
            );

            let mut nladdr = mem::zeroed::<sockaddr_nl>();
            nladdr.nl_family = socket::AddressFamily::AF_NETLINK as _;

            if socket::bind(
                socket.sock.as_raw_fd(),
                (&nladdr as *const sockaddr_nl).cast(),
                mem::size_of::<sockaddr_nl>() as u32,
            ) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
        }

        // Just use the same buffer for sends and receives
        let mut buf = Buf::<{ 2 * 1024 }>::new();

        // Resolve the netdev family, this is mapping a friendly string to an integer id
        let netdev_id = {
            buf.push(nlmsghdr {
                nlmsg_len: 0,
                nlmsg_type: msg_kind::GENL_ID_CTRL,
                nlmsg_flags: msg_flags::REQUEST,
                nlmsg_seq: 0,
                nlmsg_pid: 0,
            })?;
            buf.push(genlmsghdr {
                cmd: generic::CTRL_CMD_GETFAMILY,
                version: GENL_VERSION,
                __reserved: 0,
            })?;

            // This is the attribute which informs netlink which family id we are querying
            buf.push_attribute(generic::CTRL_ATTR_FAMILY_NAME, b"netdev\0")?;

            socket
                .send_and_recv(&mut buf, |attrs| -> Result<Option<u16>> {
                    for (attr, data) in attrs {
                        if attr != generic::CTRL_ATTR_FAMILY_ID {
                            continue;
                        }

                        let Some(id) = read_attr!(u16, data) else {
                            return Err(Error::new(
                                ErrorKind::InvalidData,
                                "unexpected size for `netdev` CTRL_ATTR_FAMILY_ID",
                            ));
                        };

                        return Ok(Some(id));
                    }

                    Ok(None)
                })?
                .ok_or_else(|| {
                    Error::new(
                        ErrorKind::NotFound,
                        "failed to resolve the `netdev` family id",
                    )
                })?
        };

        // Now we can query the netdev to get the supported xdp features
        buf.len = 0;
        buf.push(nlmsghdr {
            nlmsg_len: 0,
            nlmsg_type: netdev_id,
            nlmsg_flags: msg_flags::REQUEST,
            nlmsg_seq: 0,
            nlmsg_pid: 0,
        })?;
        buf.push(genlmsghdr {
            cmd: netdev::NETDEV_CMD_DEV_GET,
            version: GENL_VERSION,
            __reserved: 0,
        })?;

        // This is the attribute used to tell netlink this is the interface index we wish to query
        buf.push_attribute(netdev::NETDEV_A_DEV_IFINDEX, &self.0.to_ne_bytes())?;

        let caps = socket.send_and_recv(&mut buf, |attrs| {
            let mut xdp_features = None;
            let mut zero_copy_max_segs = None;
            let mut rx_metadata_features = None;
            let mut xsk_features = None;

            for (attr, data) in attrs {
                match attr {
                    netdev::NETDEV_A_DEV_IFINDEX => {
                        let Some(ifindex) = read_attr!(u32, data) else {
                            return Ok(None);
                        };
                        if ifindex != self.0 {
                            return Ok(None);
                        }
                    }
                    netdev::NETDEV_A_DEV_XDP_FEATURES => {
                        let Some(xdp_feats) = read_attr!(u64, data) else {
                            return Ok(None);
                        };
                        xdp_features = Some(xdp_feats);
                    }
                    netdev::NETDEV_A_DEV_XSK_FEATURES => {
                        xsk_features = read_attr!(u64, data);
                    }
                    netdev::NETDEV_A_DEV_XDP_RX_METADATA_FEATURES => {
                        rx_metadata_features = read_attr!(u64, data);
                    }
                    netdev::NETDEV_A_DEV_XDP_ZC_MAX_SEGS => {
                        zero_copy_max_segs = read_attr!(u32, data);
                    }
                    _ => {}
                }
            }

            let Some(xdp_features) = xdp_features else {
                return Ok(None);
            };

            Ok(Some(super::NetdevCapabilities {
                queue_count: 0,
                zero_copy: match zero_copy_max_segs.unwrap_or(0) {
                    0 => super::XdpZeroCopy::Unavailable,
                    1 => super::XdpZeroCopy::Available,
                    o => super::XdpZeroCopy::MultiBuffer(o),
                },
                xdp_features: super::XdpFeatures(xdp_features),
                rx_metadata: super::XdpRxMetadata(rx_metadata_features.unwrap_or(0)),
                tx_metadata: super::XdpTxMetadata(xsk_features.unwrap_or(0)),
            }))
        })?;

        let Some(caps) = caps else {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "failed to query XDP features",
            ));
        };

        Ok(caps)
    }
}
