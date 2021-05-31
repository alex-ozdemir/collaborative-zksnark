use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use mpc_net;

#[inline]
pub fn exchange<F: CanonicalSerialize + CanonicalDeserialize>(f: &F) -> F {
    let mut bytes_out = Vec::new();
    f.serialize(&mut bytes_out).unwrap();
    let bytes_in = mpc_net::exchange_bytes(&bytes_out).unwrap();
    F::deserialize(&bytes_in[..]).unwrap()
}
