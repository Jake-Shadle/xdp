#!/bin/bash
set -e

# We need to change to the directory to pick up the cargo config
(cd crates/integ && cargo nextest run)
