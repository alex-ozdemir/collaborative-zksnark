set -xe

cargo build --bin proof

BIN=./target/debug/proof

BIN=$BIN ./scripts/bench.zsh groth16 local 10 2
BIN=$BIN ./scripts/bench.zsh groth16 ark-local 10 2
BIN=$BIN ./scripts/bench.zsh groth16 hbc 10 2
BIN=$BIN ./scripts/bench.zsh groth16 spdz 10 2
BIN=$BIN ./scripts/bench.zsh groth16 gsz 10 3
BIN=$BIN ./scripts/bench.zsh marlin local 10 2
BIN=$BIN ./scripts/bench.zsh marlin hbc 10 2
BIN=$BIN ./scripts/bench.zsh marlin spdz 10 2
BIN=$BIN ./scripts/bench.zsh marlin gsz 10 3
BIN=$BIN ./scripts/bench.zsh plonk local 10 2
BIN=$BIN ./scripts/bench.zsh plonk hbc 10 2
BIN=$BIN ./scripts/bench.zsh plonk spdz 10 2
