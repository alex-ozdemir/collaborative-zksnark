use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use mpc_net::multi;

#[inline]
pub fn broadcast<T: CanonicalDeserialize + CanonicalSerialize>(out: &T) -> Vec<T> {
    let mut bytes_out = Vec::new();
    out.serialize(&mut bytes_out).unwrap();
    let bytes_in = multi::broadcast(&bytes_out);
    bytes_in
        .into_iter()
        .map(|b| T::deserialize(&b[..]).unwrap())
        .collect()
}

#[inline]
pub fn send_to_king<T: CanonicalDeserialize + CanonicalSerialize>(out: &T) -> Option<Vec<T>> {
    let mut bytes_out = Vec::new();
    out.serialize(&mut bytes_out).unwrap();
    multi::send_to_king(&bytes_out).map(|bytes_in| {
        bytes_in
            .into_iter()
            .map(|b| T::deserialize(&b[..]).unwrap())
            .collect()
    })
}

#[inline]
pub fn recv_from_king<T: CanonicalDeserialize + CanonicalSerialize>(out: Option<&Vec<T>>) -> T {
    let bytes_in = multi::recv_from_king(out.map(|outs| {
        outs.iter()
            .map(|out| {
                let mut bytes_out = Vec::new();
                out.serialize(&mut bytes_out).unwrap();
                bytes_out
            })
            .collect()
    }));
    T::deserialize(&bytes_in[..]).unwrap()
}
