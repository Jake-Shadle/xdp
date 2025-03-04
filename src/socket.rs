//! Initialization and polling of an [`AF_XDP`](https://en.wikipedia.org/wiki/Express_Data_Path#AF_XDP) socket

use crate::{
    libc::{self, InternalXdpFlags, socket, xdp},
    rings,
};
use std::{fmt, io::Error, os::fd::AsRawFd as _};

/// The various errors that can occur when setting up an `AF_XDP` socket
#[derive(Debug)]
pub enum SocketError {
    /// The socket could not be created
    SocketCreation(Error),
    /// A [`setsockopt`](https://www.man7.org/linux/man-pages/man3/setsockopt.3p.html) call failed
    SetSockOpt {
        /// The error
        inner: Error,
        /// The socket option we failed to set
        option: OptName,
    },
    /// A [`getsockopt`](https://www.man7.org/linux/man-pages/man3/getsockopt.3p.html) call failed
    GetSockOpt {
        /// The error
        inner: Error,
        /// The socket option we failed to get
        option: OptName,
    },
    /// Failed to map a ring
    RingMap {
        /// The error
        inner: Error,
        /// The ring that failed to map
        ring: rings::Ring,
    },
    /// Failed to bind the socket
    Bind(Error),
}

impl std::error::Error for SocketError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(match self {
            Self::SocketCreation(e) | Self::Bind(e) => e,
            Self::SetSockOpt { inner, .. }
            | Self::GetSockOpt { inner, .. }
            | Self::RingMap { inner, .. } => inner,
        })
    }
}

impl fmt::Display for SocketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// A builder for creating, initializing, and binding an [`XdpSocket`]
pub struct XdpSocketBuilder {
    sock: std::os::fd::OwnedFd,
}

/// The various socket options that are written or read during [`XdpSocketBuilder`]
/// intialization
#[derive(Copy, Clone, Debug)]
#[repr(i32)]
pub enum OptName {
    /// Configures the [`crate::Umem`] shared between the kernel and userspace
    UmemRegion = libc::xdp::SockOpts::XDP_UMEM_REG,
    /// Configures the length of the [`rings::FillRing`]
    UmemFillRing = libc::xdp::SockOpts::XDP_UMEM_FILL_RING,
    /// Configures the length of the [`rings::CompletionRing`]
    UmemCompletionRing = libc::xdp::SockOpts::XDP_UMEM_COMPLETION_RING,
    /// Configures the length of the [`rings::RxRing`]
    RxRing = libc::xdp::SockOpts::XDP_RX_RING,
    /// Configures the length of the [`rings::TxRing`]
    TxRing = libc::xdp::SockOpts::XDP_TX_RING,
    /// Used to retrieve the ring offsets configured by the kernel
    XdpMmapOffsets = libc::xdp::SockOpts::XDP_MMAP_OFFSETS,
    // PreferBusyPoll = 69, // SO_PREFER_BUSY_POLL
    // BusyPoll = libc::SO_BUSY_POLL,
    // BusyPollBudget = 70, // SO_BUSY_POLL_BUDGET
}

/// The [`libc::sockaddr::sxdp_flags`](https://docs.rs/libc/latest/libc/struct.sockaddr_xdp.html#structfield.sxdp_flags)
/// to use when binding the `AF_XDP` socket
#[derive(Copy, Clone)]
pub struct BindFlags(xdp::BindFlags::Enum);

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
        self.0 |= xdp::BindFlags::XDP_ZEROCOPY;
        self.0 &= !xdp::BindFlags::XDP_COPY;
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
        self.0 |= xdp::BindFlags::XDP_COPY;
        self.0 &= !xdp::BindFlags::XDP_ZEROCOPY;
    }

    #[inline]
    fn needs_wakeup(&mut self) {
        self.0 |= xdp::BindFlags::XDP_USE_NEED_WAKEUP;
    }
}

impl XdpSocketBuilder {
    /// Attempts to create an `AF_XDP` socket
    ///
    /// This creates a [`SOCK_RAW`](https://www.man7.org/linux/man-pages/man7/raw.7.html)
    /// socket, which requires higher ([`CAP_NET_RAW`](https://www.man7.org/linux/man-pages/man7/capabilities.7.html))
    /// privileges
    pub fn new() -> Result<Self, SocketError> {
        use std::os::fd::FromRawFd;

        let socket = socket::socket(
            socket::AddressFamily::AF_XDP,
            socket::Kind::SOCK_RAW | socket::Kind::SOCK_CLOEXEC,
            socket::Protocol::NONE,
        );
        if socket < 0 {
            return Err(SocketError::SocketCreation(Error::last_os_error()));
        }

        Ok(Self {
            // SAFETY: we've validated the socket descriptor
            sock: unsafe { std::os::fd::OwnedFd::from_raw_fd(socket) },
        })
    }

    /// Builds the rings used to interface between the kernel and userspace
    pub fn build_rings(
        &mut self,
        umem: &crate::Umem,
        cfg: rings::RingConfig,
    ) -> Result<(rings::Rings, BindFlags), SocketError> {
        let offsets = self.build_rings_inner(umem, &cfg)?;
        let socket = self.sock.as_raw_fd();

        // Setup the rings now that we have our offsets
        let fill_ring = rings::FillRing::new(socket, &cfg, &offsets)?;

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

    /// Builds a [`rings::WakableFillRing`] and [`rings::WakableTxRing`] that
    /// will emit syscalls when packets are enqueued to them to inform the kernel
    /// of the available buffers
    pub fn build_wakable_rings(
        &mut self,
        umem: &crate::Umem,
        cfg: rings::RingConfig,
    ) -> Result<(rings::WakableRings, BindFlags), SocketError> {
        let offsets = self.build_rings_inner(umem, &cfg)?;
        let socket = self.sock.as_raw_fd();

        // Setup the rings now that we have our offsets
        let fill_ring = rings::WakableFillRing::new(socket, &cfg, &offsets)?;

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
    ) -> Result<libc::rings::xdp_mmap_offsets, SocketError> {
        let mut flags = 0;
        // Internally umem uses frame_size - head room for the capacity of
        // each packet, but we need to readjust it here so the kernel knows
        // the actual size
        let chunk_size = umem.frame_size as u32 + xdp::XDP_PACKET_HEADROOM as u32;
        if !chunk_size.is_power_of_two() {
            flags |= xdp::UmemFlags::XDP_UMEM_UNALIGNED_CHUNK_FLAG;
        }

        if umem.options != 0 {
            // This value is only available in very recent ~6.11 kernels and was introduced
            // for those who didn't zero initialize xdp_umem_reg
            flags |= xdp::UmemFlags::XDP_UMEM_TX_METADATA_LEN;

            if umem.options & InternalXdpFlags::USE_SOFTWARE_OFFLOAD != 0 {
                flags |= xdp::UmemFlags::XDP_UMEM_TX_SW_CSUM;
            }
        }

        let umem_reg = xdp::XdpUmemReg {
            addr: umem.mmap.ptr as _,
            len: umem.mmap.len() as _,
            chunk_size,
            headroom: umem.head_room as _,
            flags,
            tx_metadata_len: if umem.options != 0 {
                std::mem::size_of::<libc::xdp::xsk_tx_metadata>() as _
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
        let mut offsets = unsafe { std::mem::zeroed::<libc::rings::xdp_mmap_offsets>() };

        let expected_size = std::mem::size_of_val(&offsets) as u32;
        let mut size = expected_size;

        let socket = self.sock.as_raw_fd();

        // Retrieve the mapping offsets
        // SAFETY: safe barring kernel bugs
        if unsafe {
            libc::socket::getsockopt(
                socket,
                libc::socket::Level::SOL_XDP,
                OptName::XdpMmapOffsets as _,
                (&mut offsets as *mut libc::rings::xdp_mmap_offsets).cast(),
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

    /// Binds the socket to the specified NIC and queue.
    pub fn bind(
        self,
        interface_index: crate::nic::NicIndex,
        queue_id: u32,
        bind_flags: BindFlags,
    ) -> Result<XdpSocket, SocketError> {
        let xdp_sockaddr = xdp::sockaddr_xdp {
            sxdp_family: socket::AddressFamily::AF_XDP as _,
            sxdp_flags: bind_flags.0,
            sxdp_ifindex: interface_index.0,
            sxdp_queue_id: queue_id,
            sxdp_shared_umem_fd: 0,
        };

        // SAFETY: syscall, all inputs are valid
        if unsafe {
            socket::bind(
                self.sock.as_raw_fd(),
                (&xdp_sockaddr as *const xdp::sockaddr_xdp).cast(),
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
        // SAFETY: syscall, all inputs are valid
        if unsafe {
            libc::socket::setsockopt(
                self.sock.as_raw_fd(),
                socket::Level::SOL_XDP,
                name as i32,
                (val as *const T).cast(),
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

/// An [`AF_XDP`](https://en.wikipedia.org/wiki/Express_Data_Path#AF_XDP) socket
/// that can be polled for I/O operations
pub struct XdpSocket {
    sock: std::os::fd::OwnedFd,
}

/// A timeout that must be passed to one of the poll operations on [`XdpSocket`]
#[derive(Copy, Clone)]
pub struct PollTimeout(i32);

impl PollTimeout {
    /// Creates a [`Self`] from a [`std::time::Duration`], passing `Option::None`
    /// will create an infinite timeout
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
    /// Polls both read and write
    #[inline]
    pub fn poll(&self, timeout: PollTimeout) -> std::io::Result<bool> {
        self.poll_inner(
            socket::PollEvents::POLLIN | socket::PollEvents::POLLOUT,
            timeout,
        )
    }

    /// Polls read
    #[inline]
    pub fn poll_read(&self, timeout: PollTimeout) -> std::io::Result<bool> {
        self.poll_inner(socket::PollEvents::POLLIN, timeout)
    }

    /// Polls write
    #[inline]
    pub fn poll_write(&self, timeout: PollTimeout) -> std::io::Result<bool> {
        self.poll_inner(socket::PollEvents::POLLOUT, timeout)
    }

    #[inline]
    fn poll_inner(&self, events: i16, timeout: PollTimeout) -> std::io::Result<bool> {
        // SAFETY: syscall, all inputs are valid
        let ret = unsafe {
            socket::poll(
                &mut socket::pollfd {
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

    /// Gets the file descriptor for the socket
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
