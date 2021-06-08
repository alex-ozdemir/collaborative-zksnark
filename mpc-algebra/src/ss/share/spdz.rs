use derivative::Derivative;
use rand::Rng;

use ark_ec::group::Group;
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
use std::marker::PhantomData;

use crate::channel;
use mpc_net;

use super::BeaverSource;
use super::add::{AdditiveGroupShare, AdditiveScalarShare, MulScalarShare};
use super::field::{DenseOrSparsePolynomial, DensePolynomial, ScalarShare, ExtFieldShare};
use super::group::GroupShare;
use super::msm::Msm;
use crate::Reveal;

#[derive(Derivative)]
#[derivative(
    Default(bound = ""),
    Clone(bound = ""),
)]
/// Panics if you ask it for triples.
struct PanicBeaverSource<F>(PhantomData<F>);

impl<F> BeaverSource<F, F, F> for PanicBeaverSource<F> {
    fn triple(&mut self) -> (F, F, F) {
        panic!("PanicBeaverSource")
    }

    fn inv_pair(&mut self) -> (F, F) {
        panic!("PanicBeaverSource")
    }
}

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
        let dx_t: F = mac_share::<F>() * x - self.mac.val;
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
            .map(|(mac, val)| mac_share::<F>() * val - mac)
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
        num: DenseOrSparsePolynomial<Self>,
        den: DenseOrSparsePolynomial<F>,
    ) -> Option<(DensePolynomial<Self>, DensePolynomial<Self>)> {
        let (num_sh, num_mac) = match num {
            Ok(dense) => {
                let (num_sh, num_mac): (Vec<_>, Vec<_>) =
                    dense.into_iter().map(|s| (s.sh, s.mac)).unzip();
                (Ok(num_sh), Ok(num_mac))
            }
            Err(sparse) => {
                let (num_sh, num_mac): (Vec<_>, Vec<_>) = sparse
                    .into_iter()
                    .map(|(i, s)| ((i, s.sh), (i, s.mac)))
                    .unzip();
                (Err(num_sh), Err(num_mac))
            }
        };
        let (q_sh, r_sh) = AdditiveScalarShare::univariate_div_qr(num_sh, den.clone()).unwrap();
        let (q_mac, r_mac) = AdditiveScalarShare::univariate_div_qr(num_mac, den).unwrap();
        Some((
            q_sh.into_iter()
                .zip(q_mac)
                .map(|(sh, mac)| Self { sh, mac })
                .collect(),
            r_sh.into_iter()
                .zip(r_mac)
                .map(|(sh, mac)| Self { sh, mac })
                .collect(),
        ))
    }
}

#[derive(Derivative)]
#[derivative(
    Default(bound = "T: Default"),
    Clone(bound = "T: Clone"),
    Copy(bound = "T: Copy"),
    PartialEq(bound = "T: PartialEq"),
    Eq(bound = "T: Eq"),
    PartialOrd(bound = "T: PartialOrd"),
    Ord(bound = "T: Ord"),
    Hash(bound = "T: Hash")
)]
pub struct SpdzGroupShare<T, M> {
    sh: AdditiveGroupShare<T, M>,
    mac: AdditiveGroupShare<T, M>,
}

impl<G: Group, M> Reveal for SpdzGroupShare<G, M> {
    type Base = G;

    fn reveal(self) -> G {
        let other_val: G = channel::exchange(&self.sh.val);
        // _Pragmatic MPC_ 6.6.2
        let x: G = self.sh.val + other_val;
        let dx_t: G = {
            let mut t = x.clone();
            t *= mac_share::<G::ScalarField>();
            t - self.mac.val
        };
        let other_dx_t: G = channel::atomic_exchange(&dx_t);
        let sum: G = dx_t + other_dx_t;
        assert!(sum.is_zero());
        x
    }
    fn from_public(f: G) -> Self {
        Self {
            sh: Reveal::from_public(f),
            mac: Reveal::from_add_shared({
                let mut t = f;
                t *= mac_share::<G::ScalarField>();
                t
            }),
        }
    }
    fn from_add_shared(f: G) -> Self {
        Self {
            sh: Reveal::from_add_shared(f),
            mac: Reveal::from_add_shared({
                let mut t = f;
                t *= mac::<G::ScalarField>();
                t
            }),
        }
    }
}
macro_rules! impl_spdz_basics_2_param {
    ($share:ident, $bound:ident) => {
        impl<T: $bound, M> Display for $share<T, M> {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.sh.val)
            }
        }
        impl<T: $bound, M> Debug for $share<T, M> {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                write!(f, "{:?}", self.sh.val)
            }
        }
        impl<T: $bound, M> ToBytes for $share<T, M> {
            fn write<W: Write>(&self, _writer: W) -> io::Result<()> {
                unimplemented!("write")
            }
        }
        impl<T: $bound, M> FromBytes for $share<T, M> {
            fn read<R: Read>(_reader: R) -> io::Result<Self> {
                unimplemented!("read")
            }
        }
        impl<T: $bound, M> CanonicalSerialize for $share<T, M> {
            fn serialize<W: Write>(&self, _writer: W) -> Result<(), SerializationError> {
                unimplemented!("serialize")
            }
            fn serialized_size(&self) -> usize {
                unimplemented!("serialized_size")
            }
        }
        impl<T: $bound, M> CanonicalSerializeWithFlags for $share<T, M> {
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
        impl<T: $bound, M> CanonicalDeserialize for $share<T, M> {
            fn deserialize<R: Read>(_reader: R) -> Result<Self, SerializationError> {
                unimplemented!("deserialize")
            }
        }
        impl<T: $bound, M> CanonicalDeserializeWithFlags for $share<T, M> {
            fn deserialize_with_flags<R: Read, F: Flags>(
                _reader: R,
            ) -> Result<(Self, F), SerializationError> {
                unimplemented!("deserialize_with_flags")
            }
        }
        impl<T: $bound, M> UniformRand for $share<T, M> {
            fn rand<R: Rng + ?Sized>(_rng: &mut R) -> Self {
                todo!()
                //Self::from_add_shared(<T as UniformRand>::rand(rng))
            }
        }
    };
}

impl_spdz_basics_2_param!(SpdzGroupShare, Group);

impl<G: Group, M: Msm<G, G::ScalarField>> GroupShare<G> for SpdzGroupShare<G, M> {
    type ScalarShare = SpdzScalarShare<G::ScalarField>;

    fn batch_open(selfs: impl IntoIterator<Item = Self>) -> Vec<G> {
        let (s_vals, macs): (Vec<G>, Vec<G>) =
            selfs.into_iter().map(|s| (s.sh.val, s.mac.val)).unzip();
        let o_vals = channel::exchange(&s_vals);
        let vals: Vec<G> = s_vals
            .iter()
            .zip(o_vals.iter())
            .map(|(a, b)| *a + b)
            .collect();
        let dx_ts: Vec<G> = macs
            .iter()
            .zip(vals.iter())
            .map(|(mac, val)| {
                let mut t = *val;
                t *= mac_share::<G::ScalarField>();
                t - mac
            })
            .collect();
        let o_dx_ts: Vec<G> = channel::atomic_exchange(&dx_ts);
        for (a, b) in dx_ts.into_iter().zip(o_dx_ts) {
            let sum: G = a + b;
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

    fn scale_pub_scalar(&mut self, scalar: &G::ScalarField) -> &mut Self {
        self.sh.scale_pub_scalar(scalar);
        self.mac.scale_pub_scalar(scalar);
        self
    }

    fn scale_pub_group(base: G, scalar: &Self::ScalarShare) -> Self {
        let sh = AdditiveGroupShare::scale_pub_group(base, &scalar.sh);
        let mac = AdditiveGroupShare::scale_pub_group(base, &scalar.mac);
        Self { sh, mac }
    }

    fn shift(&mut self, other: &G) -> &mut Self {
        if mpc_net::am_first() {
            self.sh.shift(other);
        }
        let mut other = other.clone();
        other *= mac_share::<G::ScalarField>();
        self.mac.val += other;
        self
    }

    fn multi_scale_pub_group(bases: &[G], scalars: &[Self::ScalarShare]) -> Self {
        let shares: Vec<G::ScalarField> = scalars.into_iter().map(|s| s.sh.val.clone()).collect();
        let macs: Vec<G::ScalarField> = scalars.into_iter().map(|s| s.sh.val.clone()).collect();
        let sh = AdditiveGroupShare::from_add_shared(M::msm(bases, &shares));
        let mac = AdditiveGroupShare::from_add_shared(M::msm(bases, &macs));
        Self { sh, mac }
    }
}

#[derive(Derivative)]
#[derivative(
    Clone(bound = "T: Clone"),
    Copy(bound = "T: Copy"),
    PartialEq(bound = "T: PartialEq"),
    Eq(bound = "T: Eq"),
    PartialOrd(bound = "T: PartialOrd"),
    Ord(bound = "T: Ord"),
    Hash(bound = "T: Hash")
)]
pub struct SpdzMulScalarShare<T, S> {
    sh: MulScalarShare<T>,
    mac: MulScalarShare<T>,
    _phants: PhantomData<S>,
}
impl_spdz_basics_2_param!(SpdzMulScalarShare, Field);

impl<F: Field, S: PrimeField> Reveal for SpdzMulScalarShare<F, S> {
    type Base = F;

    fn reveal(self) -> F {
        let other_val: F = channel::exchange(&self.sh.val);
        // _Pragmatic MPC_ 6.6.2
        let x: F = self.sh.val * other_val;
        let dx_t: F = x.pow(&mac_share::<S>().into_repr()) / self.mac.val;
        let other_dx_t: F = channel::atomic_exchange(&dx_t);
        let prod: F = dx_t * other_dx_t;
        assert!(prod.is_one());
        x
    }
    fn from_public(f: F) -> Self {
        Self {
            sh: Reveal::from_public(f),
            mac: Reveal::from_add_shared(f.pow(&mac_share::<S>().into_repr())),
            _phants: PhantomData::default(),
        }
    }
    fn from_add_shared(f: F) -> Self {
        Self {
            sh: Reveal::from_add_shared(f),
            mac: Reveal::from_add_shared(f.pow(&mac::<S>().into_repr())),
            _phants: PhantomData::default(),
        }
    }
}

impl<F: Field, S: PrimeField> ScalarShare<F> for SpdzMulScalarShare<F, S> {
    fn add(&mut self, _other: &Self) -> &mut Self {
        unimplemented!("add for SpdzMulScalarShare")
    }

    fn scale(&mut self, other: &F) -> &mut Self {
        if mpc_net::am_first() {
            self.sh.scale(other);
        }
        self.mac.scale(&other.pow(&mac_share::<S>().into_repr()));
        self
    }

    fn shift(&mut self, _other: &F) -> &mut Self {
        unimplemented!("add for SpdzMulScalarShare")
    }

    fn mul<S2: BeaverSource<Self, Self, Self>>(self, other: Self, _source: &mut S2) -> Self {
        self.sh.mul(other.sh, &mut PanicBeaverSource::default());
        self.mac.mul(other.mac, &mut PanicBeaverSource::default());
        self
    }

    fn batch_mul<S2: BeaverSource<Self, Self, Self>>(
        mut xs: Vec<Self>,
        ys: Vec<Self>,
        _source: &mut S2,
    ) -> Vec<Self> {
        for (x, y) in xs.iter_mut().zip(ys.iter()) {
            x.sh.mul(y.sh, &mut PanicBeaverSource::default());
            x.mac.mul(y.mac, &mut PanicBeaverSource::default());
        }
        xs
    }

    fn inv<S2: BeaverSource<Self, Self, Self>>(self, _source: &mut S2) -> Self {
        Self {
            sh: self.sh.inv(&mut PanicBeaverSource::default()),
            mac: self.mac.inv(&mut PanicBeaverSource::default()),
            _phants: PhantomData::default(),
        }
    }

    fn batch_inv<S2: BeaverSource<Self, Self, Self>>(xs: Vec<Self>, source: &mut S2) -> Vec<Self> {
        xs.into_iter().map(|x| x.inv(source)).collect()
    }
}

#[derive(Debug, Derivative)]
#[derivative(
    Default(bound = ""),
    Clone(bound = ""),
    Copy(bound = ""),
    PartialEq(bound = "F: PartialEq"),
    Eq(bound = "F: Eq"),
    Hash(bound = "F: Hash")
)]
pub struct SpdzMulExtFieldShare<F: Field, S>(pub PhantomData<(F, S)>);

impl<F: Field, S: PrimeField> ExtFieldShare<F> for SpdzMulExtFieldShare<F, S> {
    type Ext = SpdzMulScalarShare<F, S>;
    type Base = SpdzMulScalarShare<F::BasePrimeField, S>;
}


