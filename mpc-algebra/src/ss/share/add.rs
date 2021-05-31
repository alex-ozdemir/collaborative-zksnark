use derivative::Derivative;
use rand::Rng;

use ark_ec::group::Group;
use ark_ec::PairingEngine;
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

use super::field::{ExtFieldShare, ScalarShare};
use super::group::GroupShare;
use super::pairing::PairingShare;
use super::BeaverSource;
use mpc_trait::Reveal;

#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct AdditiveScalarShare<T> {
    val: T,
}

impl<F: Field> Reveal for AdditiveScalarShare<F> {
    type Base = F;

    fn reveal(self) -> F {
        let other_val = channel::exchange(&self.val);
        self.val + other_val
    }
    fn from_public(f: F) -> Self {
        Self {
            val: if mpc_net::am_first() { f } else { F::one() },
        }
    }
    fn from_add_shared(f: F) -> Self {
        Self { val: f }
    }
}
impl<F: Field> ScalarShare<F> for AdditiveScalarShare<F> {
    fn unwrap_as_public(self) -> F {
        self.val
    }

    fn wrap_as_shared(g: F) -> Self {
        Self { val: g }
    }

    fn batch_open(selfs: impl IntoIterator<Item = Self>) -> Vec<F> {
        let mut self_vec: Vec<F> = selfs.into_iter().map(|s| s.val).collect();
        let other_val = channel::exchange(&self_vec);
        for (s, o) in self_vec.iter_mut().zip(other_val.iter()) {
            *s += o;
        }
        self_vec
    }

    fn add(mut self, other: &Self) -> Self {
        self.val += other.val;
        self
    }

    fn scale(mut self, other: &F) -> Self {
        self.val *= other;
        self
    }

    fn shift(mut self, other: &F) -> Self {
        if mpc_net::am_first() {
            self.val += other;
        }
        self
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct AdditiveGroupShare<T> {
    val: T,
}

impl<G: Group> Reveal for AdditiveGroupShare<G> {
    type Base = G;

    fn reveal(self) -> G {
        let other_val = channel::exchange(&self.val);
        self.val + other_val
    }
    fn from_public(f: G) -> Self {
        Self {
            val: if mpc_net::am_first() { f } else { G::zero() },
        }
    }
    fn from_add_shared(f: G) -> Self {
        Self { val: f }
    }
}

impl<G: Group> GroupShare<G> for AdditiveGroupShare<G> {
    type ScalarShare = AdditiveScalarShare<G::ScalarField>;

    fn unwrap_as_public(self) -> G {
        self.val
    }

    fn wrap_as_shared(g: G) -> Self {
        Self { val: g }
    }

    fn batch_open(selfs: impl IntoIterator<Item = Self>) -> Vec<G> {
        let mut self_vec: Vec<G> = selfs.into_iter().map(|s| s.val).collect();
        let other_val = channel::exchange(&self_vec);
        for (s, o) in self_vec.iter_mut().zip(other_val.iter()) {
            *s += o;
        }
        self_vec
    }

    fn add(mut self, other: &Self) -> Self {
        self.val += &other.val;
        self
    }

    fn scale_pub_scalar(mut self, scalar: &G::ScalarField) -> Self {
        self.val *= *scalar;
        self
    }

    fn scale_pub_group(mut base: G, scalar: &Self::ScalarShare) -> Self {
        base *= scalar.val;
        AdditiveGroupShare { val: base }
    }

    fn shift(mut self, other: &G) -> Self {
        if mpc_net::am_first() {
            self.val += other;
        }
        self
    }
}

macro_rules! impl_basics {
    ($share:ident, $bound:ident) => {
        impl<T: $bound> Display for $share<T> {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.val)
            }
        }
        impl<T: $bound> Debug for $share<T> {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                write!(f, "{:?}", self.val)
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
                Self {
                    val: <T as UniformRand>::rand(rng),
                }
            }
        }
    };
}

impl_basics!(AdditiveScalarShare, Field);
impl_basics!(AdditiveGroupShare, Group);

#[derive(Debug, Derivative)]
#[derivative(
    Default(bound = ""),
    Clone(bound = ""),
    Copy(bound = ""),
    PartialEq(bound = "F: PartialEq"),
    Eq(bound = "F: Eq"),
    Hash(bound = "F: Hash")
)]
pub struct AdditiveExtFieldShare<F: Field>(pub PhantomData<F>);

impl<F: Field> ExtFieldShare<F> for AdditiveExtFieldShare<F> {
    type Ext = AdditiveScalarShare<F>;
    type Base = AdditiveScalarShare<F::BasePrimeField>;
}

#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct MulScalarShare<T> {
    val: T,
}

impl<F: Field> Reveal for MulScalarShare<F> {
    type Base = F;

    fn reveal(self) -> F {
        let other_val = channel::exchange(&self.val);
        self.val * other_val
    }
    fn from_public(f: F) -> Self {
        Self {
            val: if mpc_net::am_first() { f } else { F::one() },
        }
    }
    fn from_add_shared(f: F) -> Self {
        Self { val: f }
    }
}

impl<F: Field> ScalarShare<F> for MulScalarShare<F> {
    fn unwrap_as_public(self) -> F {
        self.val
    }

    fn wrap_as_shared(g: F) -> Self {
        Self { val: g }
    }

    fn batch_open(selfs: impl IntoIterator<Item = Self>) -> Vec<F> {
        let mut self_vec: Vec<F> = selfs.into_iter().map(|s| s.val).collect();
        let other_val = channel::exchange(&self_vec);
        for (s, o) in self_vec.iter_mut().zip(other_val.iter()) {
            *s *= o;
        }
        self_vec
    }

    fn add(self, _other: &Self) -> Self {
        unimplemented!("add for MulScalarShare")
    }

    fn scale(mut self, other: &F) -> Self {
        if mpc_net::am_first() {
            self.val *= other;
        }
        self
    }

    fn shift(self, _other: &F) -> Self {
        unimplemented!("add for MulScalarShare")
    }

    fn mul<S: BeaverSource<Self, Self, Self>>(self, other: Self, _source: &mut S) -> Self {
        Self {
            val: self.val * other.val,
        }
    }

    fn batch_mul<S: BeaverSource<Self, Self, Self>>(
        mut xs: Vec<Self>,
        ys: Vec<Self>,
        _source: &mut S,
    ) -> Vec<Self> {
        for (x, y) in xs.iter_mut().zip(ys.iter()) {
            x.val *= y.val;
        }
        xs
    }

    fn inv<S: BeaverSource<Self, Self, Self>>(mut self, _source: &mut S) -> Self {
        self.val = self.val.inverse().unwrap();
        self
    }

    fn batch_inv<S: BeaverSource<Self, Self, Self>>(xs: Vec<Self>, source: &mut S) -> Vec<Self> {
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
pub struct MulExtFieldShare<F: Field>(pub PhantomData<F>);

impl<F: Field> ExtFieldShare<F> for MulExtFieldShare<F> {
    type Ext = MulScalarShare<F>;
    type Base = MulScalarShare<F::BasePrimeField>;
}

impl_basics!(MulScalarShare, Field);

#[derive(Debug, Derivative)]
#[derivative(
    Default(bound = ""),
    Clone(bound = ""),
    Copy(bound = ""),
    PartialEq(bound = "E::G1Affine: PartialEq"),
    Eq(bound = "E::G1Affine: Eq"),
    Hash(bound = "E::G1Affine: Hash")
)]
pub struct AdditivePairingShare<E: PairingEngine>(pub PhantomData<E>);

impl<E: PairingEngine> PairingShare<E> for AdditivePairingShare<E> {
    type FrShare = AdditiveScalarShare<E::Fr>;
    type FqShare = AdditiveScalarShare<E::Fq>;
    type FqeShare = AdditiveExtFieldShare<E::Fqe>;
    // Not a typo. We want a multiplicative subgroup.
    type FqkShare = MulExtFieldShare<E::Fqk>;
    type G1AffineShare = AdditiveGroupShare<E::G1Affine>;
    type G2AffineShare = AdditiveGroupShare<E::G2Affine>;
    type G1ProjectiveShare = AdditiveGroupShare<E::G1Projective>;
    type G2ProjectiveShare = AdditiveGroupShare<E::G2Projective>;
    fn g1_share_aff_to_proj(g: Self::G1AffineShare) -> Self::G1ProjectiveShare {
        g.map_homo(|s| s.into())
    }
    fn g1_share_proj_to_aff(g: Self::G1ProjectiveShare) -> Self::G1AffineShare {
        g.map_homo(|s| s.into())
    }
    fn g2_share_aff_to_proj(g: Self::G2AffineShare) -> Self::G2ProjectiveShare {
        g.map_homo(|s| s.into())
    }
    fn g2_share_proj_to_aff(g: Self::G2ProjectiveShare) -> Self::G2AffineShare {
        g.map_homo(|s| s.into())
    }
}
