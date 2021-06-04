use rand::Rng;

use ark_ff::bytes::{FromBytes, ToBytes};
use ark_ff::prelude::*;
use ark_serialize::{
    CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize,
    CanonicalSerializeWithFlags, Flags, SerializationError,
};

use std::cmp::Ord;
use std::fmt::{self, Debug, Display, Formatter};
use std::hash::Hash;
use std::io::{self, Read, Write};

use crate::channel;
use mpc_net;

use super::add::AdditiveScalarShare;
use super::field::{DenseOrSparsePolynomial, DensePolynomial, ScalarShare};
use crate::Reveal;

#[inline]
pub fn mac_share<F: Field>() -> F {
    if mpc_net::am_first() {
        F::one()
    } else {
        F::zero()
    }
}

#[inline]
/// A huge cheat. Useful for importing shares.
pub fn mac<F: Field>() -> F {
    F::one()
}



#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct SpdzScalarShare<T> {
    sh: AdditiveScalarShare<T>,
    mac: AdditiveScalarShare<T>,
}

macro_rules! impl_basics_spdz {
    ($share:ident, $bound:ident) => {
        impl<T: $bound> Display for $share<T> {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.sh)
            }
        }
        impl<T: $bound> Debug for $share<T> {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                write!(f, "{:?}", self.sh)
            }
        }
        impl<T: $bound> ToBytes for $share<T> {
            fn write<W: Write>(&self, _writer: W) -> io::Result<()> {
                unimplemented!("write")
            }
        }
        impl<T: $bound> FromBytes for $share<T> {
            fn read<R: Read>(_reader: R) -> io::Result<Self> {
                unimplemented!("read")
            }
        }
        impl<T: $bound> CanonicalSerialize for $share<T> {
            fn serialize<W: Write>(&self, _writer: W) -> Result<(), SerializationError> {
                unimplemented!("serialize")
            }
            fn serialized_size(&self) -> usize {
                unimplemented!("serialized_size")
            }
        }
        impl<T: $bound> CanonicalSerializeWithFlags for $share<T> {
            fn serialize_with_flags<W: Write, F: Flags>(
                &self,
                _writer: W,
                _flags: F,
            ) -> Result<(), SerializationError> {
                unimplemented!("serialize_with_flags")
            }

            fn serialized_size_with_flags<F: Flags>(&self) -> usize {
                unimplemented!("serialized_size_with_flags")
            }
        }
        impl<T: $bound> CanonicalDeserialize for $share<T> {
            fn deserialize<R: Read>(_reader: R) -> Result<Self, SerializationError> {
                unimplemented!("deserialize")
            }
        }
        impl<T: $bound> CanonicalDeserializeWithFlags for $share<T> {
            fn deserialize_with_flags<R: Read, F: Flags>(
                _reader: R,
            ) -> Result<(Self, F), SerializationError> {
                unimplemented!("deserialize_with_flags")
            }
        }
        impl<T: $bound> UniformRand for $share<T> {
            fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
                Self::from_add_shared(<T as UniformRand>::rand(rng))
            }
        }
    };
}
impl_basics_spdz!(SpdzScalarShare, Field);

impl<F: Field> Reveal for SpdzScalarShare<F> {
    type Base = F;

    fn reveal(self) -> F {
        let other_val: F = channel::exchange(&self.sh.val);
        // _Pragmatic MPC_ 6.6.2
        let x: F = self.sh.val + other_val;
        let dx_t: F = mac_share::<F>() * x + self.mac.val;
        let other_dx_t: F = channel::atomic_exchange(&dx_t);
        let sum: F = dx_t + other_dx_t;
        assert!(sum.is_zero());
        x
    }
    fn from_public(f: F) -> Self {
        Self {
            sh: Reveal::from_public(f),
            mac: Reveal::from_add_shared(f * mac_share::<F>()),
        }
    }
    fn from_add_shared(f: F) -> Self {
        Self {
            sh: Reveal::from_add_shared(f),
            mac: Reveal::from_add_shared(f * mac::<F>()),
        }
    }
}

impl<F: Field> ScalarShare<F> for SpdzScalarShare<F> {
    fn batch_open(selfs: impl IntoIterator<Item = Self>) -> Vec<F> {
        let (s_vals, macs): (Vec<F>, Vec<F>) =
            selfs.into_iter().map(|s| (s.sh.val, s.mac.val)).unzip();
        let o_vals = channel::exchange(&s_vals);
        let vals: Vec<F> = s_vals
            .iter()
            .zip(o_vals.iter())
            .map(|(a, b)| *a + b)
            .collect();
        let dx_ts: Vec<F> = macs
            .iter()
            .zip(vals.iter())
            .map(|(mac, val)| mac_share::<F>() * val + mac)
            .collect();
        let o_dx_ts: Vec<F> = channel::atomic_exchange(&dx_ts);
        for (a, b) in dx_ts.into_iter().zip(o_dx_ts) {
            let sum: F = a + b;
            assert!(sum.is_zero());
        }
        vals
    }
    fn add(&mut self, other: &Self) -> &mut Self {
        self.sh.add(&other.sh);
        self.mac.add(&other.mac);
        self
    }

    fn sub(&mut self, other: &Self) -> &mut Self {
        self.sh.sub(&other.sh);
        self.mac.sub(&other.mac);
        self
    }

    fn scale(&mut self, other: &F) -> &mut Self {
        self.sh.scale(other);
        self.mac.scale(other);
        self
    }

    fn shift(&mut self, other: &F) -> &mut Self {
        self.sh.shift(other);
        self.mac.val += mac_share::<F>() * other;
        self
    }

    fn univariate_div_qr<'a>(
        _num: DenseOrSparsePolynomial<Self>,
        _den: DenseOrSparsePolynomial<F>,
    ) -> Option<(DensePolynomial<Self>, DensePolynomial<Self>)> {
        todo!()
        // let num = Self::poly_share(num);
        // let den = Self::poly_share2(den);
        // num.divide_with_q_and_r(&den)
        //     .map(|(q, r)| (Self::d_poly_unshare(q), Self::d_poly_unshare(r)))
    }
}
