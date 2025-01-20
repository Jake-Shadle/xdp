use crate::{bindings, rings};
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
    /// Copy mode works regardless of NIC/driver
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
    ) -> Result<bindings::rings::xdp_mmap_offsets, SocketError> {
        #[repr(C)]
        struct XdpUmemReg {
            /// Base pointer of the packet mmap
            addr: u64,
            /// Length of the packet mmap in bytes
            len: u64,
            /// Size of each individual chunk/packet/packet
            chunk_size: u32,
            /// Size of the headroom the packet is offset from the beginning.
            /// Note this does not include the headroom that is already reserved by the kernel
            headroom: u32,
            flags: u32,
            /// Length of the TX metadata, if any.
            tx_metadata_len: u32,
        }

        let mut flags = 0;
        if !umem.frame_size.is_power_of_two() {
            flags |= libc::XDP_UMEM_UNALIGNED_CHUNK_FLAG;
        }

        if umem.tx_metadata {
            // This value is only available in very recent ~6.11 kernels and was introduced
            // for those who didn't zero initialize xdp_umem_reg
            flags |= libc::XDP_UMEM_TX_METADATA_LEN;
        }

        let umem_reg = XdpUmemReg {
            addr: umem.mmap.as_ptr() as _,
            len: umem.mmap.len() as _,
            chunk_size: umem.frame_size as _,
            headroom: umem.head_room as _,
            flags,
            tx_metadata_len: if umem.tx_metadata {
                std::mem::size_of::<crate::bindings::xsk_tx_metadata>() as _
            } else {
                0
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
        let mut offsets = unsafe { std::mem::zeroed::<bindings::rings::xdp_mmap_offsets>() };

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
                &mut offsets as *mut bindings::rings::xdp_mmap_offsets as *mut _,
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
        interface_index: crate::nic::NicIndex,
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

impl std::os::fd::AsRawFd for XdpSocketBuilder {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.sock.as_raw_fd()
    }
}

pub struct XdpSocket {
    sock: std::os::fd::OwnedFd,
}

#[derive(Copy, Clone)]
pub struct PollTimeout(i32);

impl PollTimeout {
    pub const fn new(duration: Option<std::time::Duration>) -> Self {
        let ms = if let Some(dur) = duration {
            let ms = dur.as_millis();
            if ms > i32::MAX as _ {
                panic!("timeout cannot exceed i32::MAX milliseconds");
            }

            ms as i32
        } else {
            -1
        };

        Self(ms)
    }
}

impl XdpSocket {
    #[inline]
    pub fn poll(&self, timeout: PollTimeout) -> std::io::Result<bool> {
        self.poll_inner(libc::POLLIN | libc::POLLOUT, timeout)
    }

    #[inline]
    pub fn poll_read(&self, timeout: PollTimeout) -> std::io::Result<bool> {
        self.poll_inner(libc::POLLIN, timeout)
    }

    #[inline]
    pub fn poll_write(&self, timeout: PollTimeout) -> std::io::Result<bool> {
        self.poll_inner(libc::POLLOUT, timeout)
    }

    #[inline]
    pub fn poll_inner(&self, events: i16, timeout: PollTimeout) -> std::io::Result<bool> {
        let ret = unsafe {
            libc::poll(
                &mut libc::pollfd {
                    fd: self.sock.as_raw_fd(),
                    events,
                    revents: 0,
                },
                1,
                timeout.0,
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
