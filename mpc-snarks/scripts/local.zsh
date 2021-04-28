#!/usr/bin/env zsh

set -e

cargo build --release --bin proof -q 2> /dev/null

BIN=./target/release/proof

$BIN -c squaring --computation-size $1 local | rg 'End: *crypto' | rg -o '[0-9][0-9.]*.s'
