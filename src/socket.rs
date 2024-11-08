use crate::rings;
use std::{fmt, io::Error, os::fd::AsRawFd as _};

#[derive(Debug)]
pub enum SocketError {
    SocketCreation(Error),
    SetSockOpt { inner: Error, option: OptName },
    GetSockOpt { inner: Error, option: OptName },
    RingMap { inner: Error, ring: rings::Ring },
    Bind(Error),
}

impl std::error::Error for SocketError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(match self {
            Self::SocketCreation(e) => e,
            Self::SetSockOpt { inner, .. } => inner,
            Self::GetSockOpt { inner, .. } => inner,
            Self::RingMap { inner, .. } => inner,
            Self::Bind(e) => e,
        })
    }
}

impl fmt::Display for SocketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

pub struct XdpSocketBuilder {
    sock: std::os::fd::OwnedFd,
}

#[derive(Copy, Clone, Debug)]
#[repr(i32)]
pub enum OptName {
    UmemRegion = libc::XDP_UMEM_REG,
    UmemFillRing = libc::XDP_UMEM_FILL_RING,
    UmemCompletionRing = libc::XDP_UMEM_COMPLETION_RING,
    RxRing = libc::XDP_RX_RING,
    TxRing = libc::XDP_TX_RING,
    PreferBusyPoll = 69, // SO_PREFER_BUSY_POLL
    BusyPoll = libc::SO_BUSY_POLL,
    BusyPollBudget = 70, // SO_BUSY_POLL_BUDGET
    XdpMmapOffsets = libc::XDP_MMAP_OFFSETS,
}

/// The [`libc::sockaddr::sxdp_flags`](https://docs.rs/libc/latest/libc/struct.sockaddr_xdp.html#structfield.sxdp_flags)
/// to use when binding the AF_XDP socket
#[derive(Copy, Clone)]
pub struct BindFlags(u16);

impl BindFlags {
    fn new() -> Self {
        Self(0)
    }

    /// Forces zerocopy mode.
    ///
    /// By default, the kernel will attempt to use zerocopy mode, falling back
    /// to copy mode if the driver for the interface being bound does not support
    /// it.
    #[inline]
    pub fn force_zerocopy(&mut self) {
        self.0 |= libc::XDP_ZEROCOPY;
        self.0 &= !libc::XDP_COPY;
    }

    /// Forces copy mode.
    ///
    /// By default, the kernel will attempt to use zerocopy mode, falling back
    /// to copy mode if the driver for the interface being bound does not support
    /// it, forcing copy mode disregards support for zerocopy mode.
    ///
    /// Copy mode works
    #[inline]
    pub fn force_copy(&mut self) {
        self.0 |= libc::XDP_COPY;
        self.0 &= !libc::XDP_ZEROCOPY;
    }

    #[inline]
    fn needs_wakeup(&mut self) {
        self.0 |= libc::XDP_USE_NEED_WAKEUP;
    }
}

#[derive(Copy, Clone)]
pub struct NicIndex(u32);

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
}

impl From<NicIndex> for u32 {
    fn from(value: NicIndex) -> Self {
        value.0
    }
}

impl fmt::Debug for NicIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // attempt to retrieve the name via the index
        let mut name = [0u8; libc::IF_NAMESIZE];
        let name = if unsafe {
            !libc::if_indextoname(self.0, &mut name as *mut u8 as *mut i8).is_null()
        } {
            let len = name
                .iter()
                .position(|n| *n == 0)
                .unwrap_or(libc::IF_NAMESIZE);
            std::str::from_utf8(&name[..len]).unwrap_or("unknown")
        } else {
            "unknown"
        };

        write!(f, "{} \"{name}\"", self.0)
    }
}

impl PartialEq<u32> for NicIndex {
    fn eq(&self, other: &u32) -> bool {
        self.0 == *other
    }
}

impl XdpSocketBuilder {
    pub fn new() -> Result<Self, SocketError> {
        use std::os::fd::FromRawFd;

        // SAFETY: safe, barring kernel bugs
        let socket = unsafe { libc::socket(libc::AF_XDP, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0) };
        if socket < 0 {
            return Err(SocketError::SocketCreation(Error::last_os_error()));
        }

        Ok(Self {
            // SAFETY: we've validated the socket descriptor
            sock: unsafe { std::os::fd::OwnedFd::from_raw_fd(socket) },
        })
    }

    pub fn build_rings(
        &mut self,
        umem: &crate::Umem,
        cfg: rings::RingConfig,
    ) -> Result<(rings::Rings, BindFlags), SocketError> {
        let offsets = self.build_rings_inner(umem, &cfg)?;
        let socket = self.sock.as_raw_fd();

        let fill_ring = rings::FillRing::new(socket, &cfg, &offsets)?;

        // Setup the rings now that we have our offsets
        let rx_ring = if cfg.rx_count > 0 {
            Some(rings::RxRing::new(socket, &cfg, &offsets)?)
        } else {
            None
        };

        let completion_ring = rings::CompletionRing::new(socket, &cfg, &offsets)?;
        let tx_ring = if cfg.tx_count > 0 {
            Some(rings::TxRing::new(socket, &cfg, &offsets)?)
        } else {
            None
        };

        Ok((
            rings::Rings {
                fill_ring,
                rx_ring,
                completion_ring,
                tx_ring,
            },
            BindFlags::new(),
        ))
    }

    pub fn build_wakable_rings(
        &mut self,
        umem: &crate::Umem,
        cfg: rings::RingConfig,
    ) -> Result<(rings::WakableRings, BindFlags), SocketError> {
        let offsets = self.build_rings_inner(umem, &cfg)?;
        let socket = self.sock.as_raw_fd();

        let fill_ring = rings::WakableFillRing::new(socket, &cfg, &offsets)?;

        // Setup the rings now that we have our offsets
        let rx_ring = if cfg.rx_count > 0 {
            Some(rings::RxRing::new(socket, &cfg, &offsets)?)
        } else {
            None
        };

        let completion_ring = rings::CompletionRing::new(socket, &cfg, &offsets)?;
        let tx_ring = if cfg.tx_count > 0 {
            Some(rings::WakableTxRing::new(socket, &cfg, &offsets)?)
        } else {
            None
        };

        let mut bflags = BindFlags::new();
        bflags.needs_wakeup();

        Ok((
            rings::WakableRings {
                fill_ring,
                rx_ring,
                completion_ring,
                tx_ring,
            },
            bflags,
        ))
    }

    fn build_rings_inner(
        &mut self,
        umem: &crate::Umem,
        cfg: &rings::RingConfig,
    ) -> Result<libc::xdp_mmap_offsets, SocketError> {
        let umem_reg = libc::xdp_umem_reg {
            addr: umem.mmap.as_ptr() as _,
            len: umem.mmap.len() as _,
            chunk_size: umem.frame_size as _,
            headroom: umem.head_room as _,
            flags: if umem.frame_size.is_power_of_two() {
                0
            } else {
                libc::XDP_UMEM_UNALIGNED_CHUNK_FLAG
            },
        };

        // Configure the umem region for the socket
        self.set_sockopt(OptName::UmemRegion, &umem_reg)?;
        self.set_sockopt(OptName::UmemFillRing, &cfg.fill_count)?;
        self.set_sockopt(OptName::UmemCompletionRing, &cfg.completion_count)?;

        // Configure the recv rings
        if cfg.rx_count > 0 {
            self.set_sockopt(OptName::RxRing, &cfg.rx_count)?;
        }

        // Configure the tx rings
        if cfg.tx_count > 0 {
            self.set_sockopt(OptName::TxRing, &cfg.tx_count)?;
        }

        // SAFETY: xdp_mmap_offsets is POD
        let mut offsets = unsafe { std::mem::zeroed::<libc::xdp_mmap_offsets>() };

        let expected_size = std::mem::size_of_val(&offsets) as u32;
        let mut size = expected_size;

        let socket = self.sock.as_raw_fd();

        // Retrieve the mapping offsets
        // SAFETY: safe barring kernel bugs
        if unsafe {
            libc::getsockopt(
                socket,
                libc::SOL_XDP,
                OptName::XdpMmapOffsets as _,
                &mut offsets as *mut libc::xdp_mmap_offsets as *mut _,
                &mut size,
            )
        } != 0
        {
            return Err(SocketError::GetSockOpt {
                inner: std::io::Error::last_os_error(),
                option: OptName::XdpMmapOffsets,
            });
        }

        // Sanity check the result
        if size != expected_size {
            return Err(SocketError::GetSockOpt {
                inner: std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("expected size {expected_size} but size returned was {size}"),
                ),
                option: OptName::XdpMmapOffsets,
            });
        }

        Ok(offsets)
    }

    pub fn bind(
        self,
        interface_index: NicIndex,
        queue_id: u32,
        bind_flags: BindFlags,
    ) -> Result<XdpSocket, SocketError> {
        let xdp_sockaddr = libc::sockaddr_xdp {
            sxdp_family: libc::PF_XDP as _,
            sxdp_flags: bind_flags.0,
            sxdp_ifindex: interface_index.0,
            sxdp_queue_id: queue_id,
            sxdp_shared_umem_fd: 0,
        };

        if unsafe {
            libc::bind(
                self.sock.as_raw_fd(),
                &xdp_sockaddr as *const libc::sockaddr_xdp as *const _,
                std::mem::size_of_val(&xdp_sockaddr) as _,
            )
        } != 0
        {
            return Err(SocketError::Bind(std::io::Error::last_os_error()));
        }

        Ok(XdpSocket { sock: self.sock })
    }

    #[inline]
    fn set_sockopt<T>(&mut self, name: OptName, val: &T) -> Result<(), SocketError> {
        let level = if matches!(
            name,
            OptName::PreferBusyPoll | OptName::BusyPoll | OptName::BusyPollBudget
        ) {
            libc::SOL_SOCKET
        } else {
            libc::SOL_XDP
        };

        if unsafe {
            libc::setsockopt(
                self.sock.as_raw_fd(),
                level,
                name as i32,
                val as *const T as *const _,
                std::mem::size_of_val(val) as _,
            )
        } != 0
        {
            return Err(SocketError::SetSockOpt {
                inner: std::io::Error::last_os_error(),
                option: name,
            });
        }

        Ok(())
    }
}

pub struct XdpSocket {
    sock: std::os::fd::OwnedFd,
}

use std::time::Duration;

impl XdpSocket {
    #[inline]
    pub fn poll(&self, timeout: Option<Duration>) -> std::io::Result<bool> {
        self.poll_inner(libc::POLLIN | libc::POLLOUT, timeout)
    }

    #[inline]
    pub fn poll_read(&self, timeout: Option<Duration>) -> std::io::Result<bool> {
        self.poll_inner(libc::POLLIN, timeout)
    }

    #[inline]
    pub fn poll_write(&self, timeout: Option<Duration>) -> std::io::Result<bool> {
        self.poll_inner(libc::POLLOUT, timeout)
    }

    #[inline]
    pub fn poll_inner(&self, events: i16, timeout: Option<Duration>) -> std::io::Result<bool> {
        let timeout = timeout.map_or(-1, |d| {
            let ms = d.as_millis();
            if ms > i32::MAX as _ {
                0
            } else {
                ms as _
            }
        });
        let ret = unsafe {
            libc::poll(
                &mut libc::pollfd {
                    fd: self.sock.as_raw_fd(),
                    events,
                    revents: 0,
                },
                1,
                timeout,
            )
        };

        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                Ok(false)
            } else {
                Err(err)
            }
        } else {
            Ok(ret != 0)
        }
    }

    #[inline]
    pub fn raw_fd(&self) -> std::os::fd::RawFd {
        self.sock.as_raw_fd()
    }
}

impl std::os::fd::AsRawFd for XdpSocket {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.sock.as_raw_fd()
    }
}
