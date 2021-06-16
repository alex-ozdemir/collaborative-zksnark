use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use digest::Digest;
use rand::RngCore;
use sha2::Sha256;
use std::cell::Cell;

use mpc_net::two as net_two;

pub mod multi;

const ALLOW_CHEATING: Cell<bool> = Cell::new(true);

/// Number of randomness bytes to use in the commitment scheme
const COMMIT_RAND_BYTES: usize = 32;

/// The hash function to use for the commitment
type CommitHash = Sha256;

#[inline]
pub fn exchange<F: CanonicalSerialize + CanonicalDeserialize>(f: &F) -> F {
    let mut bytes_out = Vec::new();
    f.serialize(&mut bytes_out).unwrap();
    let bytes_in = net_two::exchange_bytes(&bytes_out).unwrap();
    F::deserialize(&bytes_in[..]).unwrap()
}

#[inline]
/// Uses commitments to simultaneously exchange values.
///
/// Ensures that if both parties get a value, each party chose its value independently of the
/// other.
pub fn atomic_exchange<F: CanonicalSerialize + CanonicalDeserialize>(f: &F) -> F {
    let mut bytes_out = Vec::new();
    f.serialize(&mut bytes_out).unwrap();
    let ser_len = bytes_out.len();
    bytes_out.resize(ser_len + COMMIT_RAND_BYTES, 0);
    rand::thread_rng().fill_bytes(&mut bytes_out[ser_len..]);
    let commitment = CommitHash::new().chain(&bytes_out).finalize();
    // exchange commitments
    let other_commitment = net_two::exchange_bytes(&commitment[..]).unwrap();
    // exchange (data || randomness)
    let other_bytes = net_two::exchange_bytes(&bytes_out).unwrap();
    // check other commitment
    assert_eq!(
        &other_commitment[..],
        &CommitHash::new().chain(&other_bytes).finalize()[..]
    );
    // parse data
    F::deserialize(&other_bytes[..ser_len]).unwrap()
}

#[inline]
pub fn can_cheat() -> bool {
    ALLOW_CHEATING.get()
}

#[inline]
pub fn set_cheating_allowed(allowed: bool) {
    ALLOW_CHEATING.set(allowed)
}

#[inline]
pub fn without_cheating<O, F: FnOnce() -> O>(f: F) -> O {
    let allowed = can_cheat();
    set_cheating_allowed(false);
    let r = f();
    set_cheating_allowed(allowed);
    r
}
