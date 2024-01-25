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


## Requirements
To run this project, you need to have Rust and Cargo installed on your system. 

You also need to use the nightly compiler, which is a version of Rust that has some unstable features that are required by this project. To install the nightly compiler, run this command:

`rustup install nightly`

To use the nightly compiler for this project, run this command:

`cargo +nightly build`

Or, to set the nightly compiler as the default for your system, run this command:

`rustup default nightly`

## Usage
To run the tests, run this command:

`cargo +nightly test`

To run the benchmarks, run this command:

`cargo +nightly bench`

To run the examples, run this command:

`cargo +nightly run --example <example-name>`

where <example-name> is one of the following:
1. addition: a simple example of proving and verifying the addition of two secret numbers.
2. multiplication: a simple example of proving and verifying the multiplication of two secret numbers.
3. r1cs: a general example of proving and verifying any relation that can be expressed as a rank-1 constraint system (R1CS).
4. merkle: an example of proving and verifying the membership of a secret element in a Merkle tree.

[paper]: https://www.usenix.org/conference/usenixsecurity22/presentation/ozdemir
