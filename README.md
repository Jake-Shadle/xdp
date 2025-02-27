<!-- markdownlint-disable no-inline-html first-line-heading no-emphasis-as-heading -->

<div align="center">

# `📨 xdp`

**`AF_XDP` socket support in Rust**

[![Crates.io](https://img.shields.io/crates/v/xdp.svg)](https://crates.io/crates/xdp)
[![API Docs](https://docs.rs/xdp/badge.svg)](https://docs.rs/xdp)
[![dependency status](https://deps.rs/repo/github/Jake-Shadle/xdp/status.svg)](https://deps.rs/repo/github/Jake-Shadle/xdp)
[![Build Status](https://github.com/Jake-Shadle/xdp/workflows/CI/badge.svg)](https://github.com/Jake-Shadle/xdp/actions?workflow=CI)

</div>

This crate allows for the creation and usage of [AF_XDP] sockets on Linux, along with the attendant memory mappings and rings.

The primary difference between this crate and the other XSK/XDP crates available on crates.io is that this crate does not depend on any C code.

## Why not use this crate?

This crate is still early days, and focused on the needs of [Quilkin](https://github.com/googleforgames/quilkin), so feature requests or bug fixes that don't pertain to it would most likely need outside contribution. There are already several other Rust crates available that (probably) have more full featured support.

## Features

- [x] Network interface enumeration and capability querying
- [x] Basic Umem support
- [ ] Shared Umem support
- [x] Fill, RX, TX, Completion rings
- [x] [TX checksum offload/completion timestamp](https://docs.kernel.org/networking/xsk-tx-metadata.html)
- [ ] [RX metadata](https://docs.kernel.org/networking/xdp-rx-metadata.html)

## License

Licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

[AF_XDP]: https://docs.ebpf.io/linux/concepts/af_xdp/
