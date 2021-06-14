#!/usr/bin/env zsh
set -e

cargo build --release --bin proof -q 2> /dev/null

BIN=./target/release/proof

#$BIN -c squaring --computation-size $1 mpc --hosts data/2 --party 0 | rg 'End: *crypto' | rg -o '[0-9][0-9.]*.s' & ; pid0=$1
#$BIN -c squaring --computation-size $1 mpc --hosts data/2 --party 1 | rg 'End: *crypto' | rg -o '[0-9][0-9.]*.s' & ; pid1=$1
RUST_LOG=proof::mpc::channel $BIN -p groth16 -c squaring --computation-size $1 mpc --hosts data/2 --party 0 &> /dev/null &
pid0=$!
RUST_LOG=proof::mpc::channel $BIN -p groth16 -c squaring --computation-size $1 mpc --hosts data/2 --party 1 &
#$BIN -c squaring --computation-size $1 mpc --hosts data/2 --party 1 | rg 'End: *crypto' | rg -o '[0-9][0-9.]*.s' &
pid1=$!

wait $pid0 $pid1

