set -xe

cargo build --bin proof

BIN=./target/debug/proof

BIN=$BIN ./scripts/bench.zsh groth16 local 10
BIN=$BIN ./scripts/bench.zsh groth16 ark-local 10
BIN=$BIN ./scripts/bench.zsh groth16 hbc 10
BIN=$BIN ./scripts/bench.zsh groth16 spdz 10
BIN=$BIN ./scripts/bench.zsh marlin local 10
BIN=$BIN ./scripts/bench.zsh marlin hbc 10
BIN=$BIN ./scripts/bench.zsh marlin spdz 10
BIN=$BIN ./scripts/bench.zsh plonk local 10
BIN=$BIN ./scripts/bench.zsh plonk hbc 10
BIN=$BIN ./scripts/bench.zsh plonk spdz 10
