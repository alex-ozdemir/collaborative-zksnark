# Collaborative zkSNARKs

This is a proof-of-concept implementation of Collaborative zkSNARKs based
on Groth16, Marlin, and Plonk.
This implementation is not secure; it exists for benchmarking reasons.

This implementation accompanies the paper that introduced Collaborative zkSNARKs:
["Experimenting with Collaborative zk-SNARKs: Zero-Knowledge Proofs for
Distributed Secrets"][paper].

## Starting point

A good place to start is:

1. Enter `mpc-snarks`.
2. `cargo build --release --bin proof`.
3. `./scripts/bench.zsh plonk spdz 10 2`.

[paper]: https://www.usenix.org/conference/usenixsecurity22/presentation/ozdemir
