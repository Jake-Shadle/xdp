#!/bin/sh

sudo ip link del client-one
sudo ip netns del ping-pong
RUST_LOG=trace cargo nextest run --no-capture
