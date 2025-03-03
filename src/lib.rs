#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

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

pub mod affinity;
pub mod error;
pub mod packet;
pub use packet::Packet;
pub mod libc;
mod mmap;
pub mod nic;
mod rings;
pub mod slab;
pub mod socket;
pub mod umem;

pub use umem::Umem;

pub use rings::{
    CompletionRing, FillRing, RingConfig, RingConfigBuilder, Rings, RxRing, TxRing,
    WakableFillRing, WakableRings, WakableTxRing,
};
