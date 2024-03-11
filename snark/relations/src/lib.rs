//! Core interface for working with various relations that are useful in
//! zkSNARKs. At the moment, we only implement APIs for working with Rank-1
//! Constraint Systems (R1CS).

#![no_std]

#![warn(
    unused,
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms,
    missing_docs
)]
#![deny(unsafe_code)]

#[cfg(feature = "std")]
extern crate std;
#[macro_use]
extern crate ark_std;

pub mod r1cs;
