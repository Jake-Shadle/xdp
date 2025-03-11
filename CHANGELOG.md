<!-- markdownlint-disable blanks-around-headings blanks-around-lists no-duplicate-heading -->

# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- next-header -->
## [Unreleased] - ReleaseDate
### Fixed
- [PR#20](https://github.com/Jake-Shadle/xdp/pull/20) changed `EtherType` and `IpProto` from enums to scoped constants to avoid UB in the presence of invalid/corrupt data that didn't match a variant. Also removed a bunch of the `IpProto` variants as most will never be used, and since it's now scoped constants users can provide their own constants without needing them in the lib themselves. Resolved [#19](https://github.com/Jake-Shadle/xdp/issues/19).
- [PR#23](https://github.com/Jake-Shadle/xdp/pull/23) added sanity checks to avoid subtraction underflow if the user provides wildly out of range offsets and/or slices to `Packet` methods.
- [PR#23](https://github.com/Jake-Shadle/xdp/pull/23) fixed a bug in `Packet::array_at_offset` where the offset was incorrect if `head` was not 0.
- [PR#23](https://github.com/Jake-Shadle/xdp/pull/23) added a check in `UdpHeader::parse_packet` to ensure the UDP length matches the packet buffer length.

### Changed
- [PR#22](https://github.com/Jake-Shadle/xdp/pull/22) removed the `Index/Mut` impls from `XskProducer/Consumer` as they were unneccessary fluff in favor of much simpler internal methods.
- [PR#23](https://github.com/Jake-Shadle/xdp/pull/23) changed `data_offset` and `data_length` to just `data`, a range that is convertible to/from `std::ops::Range<usize>`. `data_length` is now a method that just returns `data.end - data.start`.

### Added
- [PR#23](https://github.com/Jake-Shadle/xdp/pull/23) added `Packet::append` as a simpler way to add data to the tail of the packet.
- [PR#23](https://github.com/Jake-Shadle/xdp/pull/23) added `csum::DataChecksum` as a simpler way to calculate the checksum of the data portion of a payload. `UdpHeaders::calc_checksum` now uses this instead of separate length and checksum arguments.

## [0.6.0] - 2025-03-04
### Changed
- [PR#16](https://github.com/Jake-Shadle/xdp/pull/16) changed `RxRing` and `TxRing` to use the new `slab::Slab` trait.
- [PR#16](https://github.com/Jake-Shadle/xdp/pull/16) moved `HeapSlab` to the new `slab` module, and made it implement `slab::Slab`, changing it so that items are always pushed to the front and popped from the back, unlike the previous implementation which allowed both.
- [PR#17](https://github.com/Jake-Shadle/xdp/pull/17) changed `CsumOffload::Request(xdp::libc::xdp::xsk_tx_request)` -> `CsumOffload::Request { start: u16, offset: u16 }`

### Added
- [PR#16](https://github.com/Jake-Shadle/xdp/pull/16) added a new `slab::StackSlab<N>` fixed size ring buffer that implements `slab::Slab`.
- [PR#17](https://github.com/Jake-Shadle/xdp/pull/17) added various doc examples.

### Fixed
- [PR#16](https://github.com/Jake-Shadle/xdp/pull/16) fixed some undefined behavior in the netlink code used to query NIC capabilities.
- [PR#16](https://github.com/Jake-Shadle/xdp/pull/16) fixed a bug where TX metadata would not be added and would return an error if the packet headroom was not large enough for the metadata, this is irrelevant.
- [PR#17](https://github.com/Jake-Shadle/xdp/pull/17) fixed the exceptional case where a UDP checksum is calculated to be 0, in which case it is set to `0xffff` instead.

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
[Unreleased]: https://github.com/Jake-Shadle/xdp/compare/0.6.0...HEAD
[0.6.0]: https://github.com/Jake-Shadle/xdp/compare/0.5.0...0.6.0
[0.5.0]: https://github.com/Jake-Shadle/xdp/compare/0.4.0...0.5.0
[0.4.0]: https://github.com/Jake-Shadle/xdp/compare/0.3.0...0.4.0
[0.3.0]: https://github.com/Jake-Shadle/xdp/compare/0.2.0...0.3.0
[0.2.0]: https://github.com/Jake-Shadle/xdp/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/Jake-Shadle/xdp/compare/0.0.1...0.1.0
[0.0.1]: https://github.com/Jake-Shadle/xdp/releases/tag/0.0.1
