<!-- markdownlint-disable blanks-around-headings blanks-around-lists no-duplicate-heading -->

# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- next-header -->
## [Unreleased] - ReleaseDate
### Changed
- [PR#11](https://github.com/Jake-Shadle/xdp/pull/11) fixed documentation, but also moved some types and constants around in the `libc` module.

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
[Unreleased]: https://github.com/Jake-Shadle/xdp/compare/0.3.0...HEAD
[0.3.0]: https://github.com/Jake-Shadle/xdp/compare/0.2.0...0.3.0
[0.2.0]: https://github.com/Jake-Shadle/xdp/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/Jake-Shadle/xdp/compare/0.0.1...0.1.0
[0.0.1]: https://github.com/Jake-Shadle/xdp/releases/tag/0.0.1
