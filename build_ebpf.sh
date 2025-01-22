#!/bin/bash
set -e

CARGO_BUILD_TARGET_DIR="target" cargo +nightly build -Zbuild-std=core --manifest-path crates/socket-router/Cargo.toml --target bpfel-unknown-none --release

clang -target bpf -Wall -O2 -g -c crates/socket-router/src/main.c -o target/bpfel-unknown-none/release/socket-router-c.o
clang -target bpf -Wall -O2 -g -c crates/socket-router/src/dummy.c -o target/bpfel-unknown-none/release/dummy
#bpftool gen object target/bpfel-unknown-none/release/socket-router-bpf target/bpfel-unknown-none/release/socket-router-c.o
