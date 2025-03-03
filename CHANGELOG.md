<!-- markdownlint-disable blanks-around-headings blanks-around-lists no-duplicate-heading -->

# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- next-header -->
## [Unreleased] - ReleaseDate
### Changed
- [PR#16](https://github.com/Jake-Shadle/xdp/pull/16) changed `RxRing` and `TxRing` to use the new `slab::Slab` trait.
- [PR#16](https://github.com/Jake-Shadle/xdp/pull/16) moved `HeapSlab` to the new `slab` module, and made it implement `slab::Slab`, changing it so that items are always pushed to the front and popped from the back, unlike the previous implementation which allowed both.

### Added
- [PR#16](https://github.com/Jake-Shadle/xdp/pull/16) added a new `slab::StackSlab<N>` fixed size ring buffer that implements `slab::Slab`.

### Fixed
- [PR#16](https://github.com/Jake-Shadle/xdp/pull/16) fixed some undefined behavior in the netlink code used to query NIC capabilities.
- [PR#16](https://github.com/Jake-Shadle/xdp/pull/16) fixed a bug where TX metadata would not be added and would return an error if the packet headroom was not large enough for the metadata, this is irrelevant.

## [0.5.0] - 2025-02-27
### Changed
- [PR#15](https://github.com/Jake-Shadle/xdp/pull/15) renamed `UdpPacket` -> `UdpHeaders`, and changed the contents to be the actual headers that can be de/serialized from/to the packet buffer.
- [PR#15](https://github.com/Jake-Shadle/xdp/pull/15) moved to edition 2024.

### Added
- [PR#15](https://github.com/Jake-Shadle/xdp/pull/15) added various utility methods to the types in `net_types`.
- [PR#15](https://github.com/Jake-Shadle/xdp/pull/15) added `Debug` impls for various types gated behind the `__debug` feature since they are mainly only for internal testing.
- [PR#15](https://github.com/Jake-Shadle/xdp/pull/15) added `miri` checking to CI, resolving [#13](https://github.com/Jake-Shadle/xdp/issues/13).

### Fixed
- [PR#15](https://github.com/Jake-Shadle/xdp/pull/15) fixed an issue where UDP checksum calculation could be incorrect depending on the input data.

### Removed
- [PR#15](https://github.com/Jake-Shadle/xdp/pull/15) removed the `Packet::item_at_offset` and `Packet::item_at_offset_mut` methods as they had undefined behavior, replaced by the `read` and `write` methods.
- [PR#15](https://github.com/Jake-Shadle/xdp/pull/15) removed `Packet::slice_at_offset` and `Packet::slice_at_offset_mut` in favor of just letting the user use `Deref/DerefMut`.

## [0.4.0] - 2025-02-17
### Changed
- [PR#11](https://github.com/Jake-Shadle/xdp/pull/11) fixed documentation, but also moved some types and constants around in the `libc` module.
- [PR#14](https://github.com/Jake-Shadle/xdp/pull/14) changed `Packet::array_at_offset` to take a `&mut [u8; N]` rather than return it.

### Fixed
- [PR#14](https://github.com/Jake-Shadle/xdp/pull/14) fixed a bug where inserting past the end of the tail would not return an `Err`.

### Added
- [PR#14](https://github.com/Jake-Shadle/xdp/pull/14) ungated the `Debug` impls for `XdpFeatures`, `XdpRxMetadata`, `XdpTxMetadata`, `XdpZeroCopy`, and `NetdevCapabilities`.

## [0.3.0] - 2025-02-14
### Changed
- [PR#7](https://github.com/Jake-Shadle/xdp/pull/7) removed `libc` in favor of inline bindings.
- [PR#9](https://github.com/Jake-Shadle/xdp/pull/9) removed `neli` in favor of a simpler inline implementation, resolving [#1](https://github.com/Jake-Shadle/xdp/issues/1).
- [PR#10](https://github.com/Jake-Shadle/xdp/pull/10) removed `memmap2` in favor of a simpler inline implementation, resolving [#8](https://github.com/Jake-Shadle/xdp/issues/8).

## [0.2.0] - 2025-01-30
### Fixed
- [PR#4](https://github.com/Jake-Shadle/xdp/pull/4) fixed support for [TX checksum offload](https://docs.kernel.org/networking/xsk-tx-metadata.html).

### Added
- [PR#6](https://github.com/Jake-Shadle/xdp/pull/6) fleshed out documentation
- [PR#6](https://github.com/Jake-Shadle/xdp/pull/6) added `crate::nic::InterfaceIter` to enumerate available interfaces

### Changed
- [PR#6](https://github.com/Jake-Shadle/xdp/pull/6) `crate::nic::NicIndex::queue_count` now returns a `crate::nic::Queues` struct rather than a tuple

## [0.1.0] - 2025-01-22
### Added
- [PR#3](https://github.com/Jake-Shadle/xdp/pull/3) added the first pass implementation of the crate with a (mostly) working implementation focused on UDP packets. See the PR for a more detailed description of what is and is not supported.

## [0.0.1] - 2024-10-23
### Added
- Initial crate squat

<!-- next-url -->
[Unreleased]: https://github.com/Jake-Shadle/xdp/compare/0.5.0...HEAD
[0.5.0]: https://github.com/Jake-Shadle/xdp/compare/0.4.0...0.5.0
[0.4.0]: https://github.com/Jake-Shadle/xdp/compare/0.3.0...0.4.0
[0.3.0]: https://github.com/Jake-Shadle/xdp/compare/0.2.0...0.3.0
[0.2.0]: https://github.com/Jake-Shadle/xdp/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/Jake-Shadle/xdp/compare/0.0.1...0.1.0
[0.0.1]: https://github.com/Jake-Shadle/xdp/releases/tag/0.0.1
