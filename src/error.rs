pub use crate::{frame::FrameError, socket::SocketError};
use std::fmt;

pub enum Error {
    Cfg(ConfigError),
    Frame(FrameError),
    Socket(SocketError),
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Cfg(err) => err.source(),
            Self::Frame(err) => err.source(),
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
            Self::Frame(ferr) => {
                write!(f, "frame error: {ferr:?}")
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
            Self::Frame(ferr) => {
                write!(f, "frame error: {ferr}")
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

impl From<FrameError> for Error {
    fn from(value: FrameError) -> Self {
        Self::Frame(value)
    }
}

#[derive(Debug)]
pub struct ConfigError {
    pub name: &'static str,
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

#[derive(Debug)]
pub enum ConfigErrorKind {
    /// Many configuration options for buffer/ring sizes require non-zero values
    Zero,
    /// Many configuration options for buffer/ring sizes require powers of 2
    NonPowerOf2,
    OutOfRange {
        size: usize,
        range: std::ops::Range<usize>,
    },
    /// It is invalid for an XDP socket to have neither a [`TxRing`] nor a [`RxRing`]
    /// it must have one or both
    MustSendOrRecv,
}

#[macro_export]
macro_rules! non_zero_and_power_of_2 {
    ($ctx:expr, $name:ident) => {{
        let val = $ctx.$name;
        if val == 0 {
            return Err($crate::error::ConfigError {
                name: stringify!($name),
                kind: $crate::error::ConfigErrorKind::Zero,
            }
            .into());
        } else if !val.is_power_of_two() {
            return Err($crate::error::ConfigError {
                name: stringify!($name),
                kind: $crate::error::ConfigErrorKind::NonPowerOf2,
            }
            .into());
        }

        val
    }};
}

#[macro_export]
macro_rules! within_range {
    ($ctx:expr, $name:ident, $range:expr) => {{
        let val = $ctx.$name;
        let uval = val as usize;

        if !$range.contains(&uval) {
            return Err($crate::error::ConfigError {
                name: stringify!($name),
                kind: $crate::error::ConfigErrorKind::OutOfRange {
                    size: uval,
                    range: $range,
                },
            }
            .into());
        }

        val
    }};
}
