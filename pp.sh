#!/bin/sh

sudo ip netns del ping-pong
sudo ip link del ping-pong-o
sudo ip netns del proxy
sudo ip link del proxy-o
sudo ip netns del client
sudo ip link del client-o
sudo ip netns del server
sudo ip link del server-o
RUST_LOG=trace cargo nextest run --no-capture proxy
