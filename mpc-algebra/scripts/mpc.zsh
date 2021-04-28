#!/usr/bin/env zsh
set -e

cargo build --release --bin proof -q 2> /dev/null

BIN=./target/release/proof

#$BIN -c squaring --computation-size $1 mpc --port 8001 --peer-port 8000 --party 0 | rg 'End: *crypto' | rg -o '[0-9][0-9.]*.s' & ; pid0=$1
#$BIN -c squaring --computation-size $1 mpc --port 8000 --peer-port 8001 --party 1 | rg 'End: *crypto' | rg -o '[0-9][0-9.]*.s' & ; pid1=$1
RUST_LOG=proof::mpc::channel $BIN -c squaring --computation-size $1 mpc --port 8001 --peer-port 8000 --party 0 &
pid0=$!
$BIN -c squaring --computation-size $1 mpc --port 8000 --peer-port 8001 --party 1 | rg 'End: *crypto' | rg -o '[0-9][0-9.]*.s' &
pid1=$!

wait $pid0 $pid1
