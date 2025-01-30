//! Errors that can be returned by various calls in this crate

pub use crate::{packet::PacketError, socket::SocketError};
use std::fmt;

/// Errors that can occur when using this crate
pub enum Error {
    /// A configuration error
    Cfg(ConfigError),
    /// A packet error
    Packet(PacketError),
    /// A socket error
    Socket(SocketError),
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Cfg(err) => err.source(),
            Self::Packet(err) => err.source(),
            Self::Socket(err) => err.source(),
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cfg(cerr) => {
                write!(f, "configuration error: {cerr:?}")
            }
            Self::Packet(ferr) => {
                write!(f, "packet error: {ferr:?}")
            }
            Self::Socket(serr) => {
                write!(f, "socket error: {serr:?}")
            }
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cfg(cerr) => {
                write!(f, "configuration error: {cerr}")
            }
            Self::Packet(ferr) => {
                write!(f, "packet error: {ferr}")
            }
            Self::Socket(serr) => {
                write!(f, "socket error: {serr}")
            }
        }
    }
}

impl From<ConfigError> for Error {
    fn from(value: ConfigError) -> Self {
        Self::Cfg(value)
    }
}

impl From<SocketError> for Error {
    fn from(value: SocketError) -> Self {
        Self::Socket(value)
    }
}

impl From<PacketError> for Error {
    fn from(value: PacketError) -> Self {
        Self::Packet(value)
    }
}

/// A configuration error
#[derive(Debug)]
pub struct ConfigError {
    /// The name of the setting/field
    pub name: &'static str,
    /// The error
    pub kind: ConfigErrorKind,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} is invalid: ", self.name)?;

        match &self.kind {
            ConfigErrorKind::Zero => f.write_str("cannot be zero"),
            ConfigErrorKind::NonPowerOf2 => f.write_str("must be a power of 2"),
            ConfigErrorKind::OutOfRange { size, range } => {
                write!(f, "value '{size}' was out of range '{range:?}")
            }
            ConfigErrorKind::MustSendOrRecv => {
                f.write_str("the socket must a tx ring or rx ring or both")
            }
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

/// Different configuration errors that can occur
#[derive(Debug)]
pub enum ConfigErrorKind {
    /// Many configuration options for buffer/ring sizes require non-zero values
    Zero,
    /// Many configuration options for buffer/ring sizes require powers of 2
    NonPowerOf2,
    /// A value was out of range
    OutOfRange {
        /// The size requested by the user
        size: usize,
        /// The valid range that size did not fall within
        range: std::ops::Range<usize>,
    },
    /// It is invalid for an XDP socket to have neither a [`TxRing`] nor a [`RxRing`]
    /// it must have one or both
    MustSendOrRecv,
}
