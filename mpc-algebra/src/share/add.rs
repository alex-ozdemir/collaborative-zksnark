#![macro_use]
use derivative::Derivative;
use rand::Rng;

use ark_ec::group::Group;
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::bytes::{FromBytes, ToBytes};
use ark_ff::prelude::*;
use ark_poly::UVPolynomial;
use ark_serialize::{
    CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize,
    CanonicalSerializeWithFlags, Flags, SerializationError,
};

use std::borrow::Cow;
use std::cmp::Ord;
use std::fmt::{self, Debug, Display, Formatter};
use std::hash::Hash;
use std::io::{self, Read, Write};
use std::marker::PhantomData;

use crate::channel;
use mpc_net;

use super::field::{
    DenseOrSparsePolynomial, DensePolynomial, ExtFieldShare, ScalarShare, SparsePolynomial,
};
use super::group::GroupShare;
use super::msm::Msm;
use super::pairing::{AffProjShare, PairingShare};
use super::BeaverSource;
use crate::Reveal;

#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct AdditiveScalarShare<T> {
    pub val: T,
}

impl<F: Field> AdditiveScalarShare<F> {
    fn poly_share<'a>(
        p: DenseOrSparsePolynomial<Self>,
    ) -> ark_poly::univariate::DenseOrSparsePolynomial<'a, F> {
        match p {
            Ok(p) => ark_poly::univariate::DenseOrSparsePolynomial::DPolynomial(Cow::Owned(
                Self::d_poly_share(p),
            )),
            Err(p) => ark_poly::univariate::DenseOrSparsePolynomial::SPolynomial(Cow::Owned(
                Self::s_poly_share(p),
            )),
        }
    }
    fn d_poly_share(p: DensePolynomial<Self>) -> ark_poly::univariate::DensePolynomial<F> {
        ark_poly::univariate::DensePolynomial::from_coefficients_vec(
            p.into_iter().map(|s| s.val).collect(),
        )
    }
    fn s_poly_share(p: SparsePolynomial<Self>) -> ark_poly::univariate::SparsePolynomial<F> {
        ark_poly::univariate::SparsePolynomial::from_coefficients_vec(
            p.into_iter().map(|(i, s)| (i, s.val)).collect(),
        )
    }
    fn poly_share2<'a>(
        p: DenseOrSparsePolynomial<F>,
    ) -> ark_poly::univariate::DenseOrSparsePolynomial<'a, F> {
        match p {
            Ok(p) => ark_poly::univariate::DenseOrSparsePolynomial::DPolynomial(Cow::Owned(
                ark_poly::univariate::DensePolynomial::from_coefficients_vec(p),
            )),
            Err(p) => ark_poly::univariate::DenseOrSparsePolynomial::SPolynomial(Cow::Owned(
                ark_poly::univariate::SparsePolynomial::from_coefficients_vec(p),
            )),
        }
    }
    fn d_poly_unshare(p: ark_poly::univariate::DensePolynomial<F>) -> DensePolynomial<Self> {
        p.coeffs
            .into_iter()
            .map(|s| Self::from_add_shared(s))
            .collect()
    }
}

impl<F: Field> Reveal for AdditiveScalarShare<F> {
    type Base = F;

    fn reveal(self) -> F {
        let other_val = channel::exchange(&self.val);
        self.val + other_val
    }
    fn from_public(f: F) -> Self {
        Self {
            val: if mpc_net::am_first() { f } else { F::zero() },
        }
    }
    fn from_add_shared(f: F) -> Self {
        Self { val: f }
    }
    fn unwrap_as_public(self) -> F {
        self.val
    }
}
impl<F: Field> ScalarShare<F> for AdditiveScalarShare<F> {
    fn batch_open(selfs: impl IntoIterator<Item = Self>) -> Vec<F> {
        let mut self_vec: Vec<F> = selfs.into_iter().map(|s| s.val).collect();
        let other_val = channel::exchange(&self_vec);
        for (s, o) in self_vec.iter_mut().zip(other_val.iter()) {
            *s += o;
        }
        self_vec
    }
    fn add(&mut self, other: &Self) -> &mut Self {
        self.val += &other.val;
        self
    }

    fn sub(&mut self, other: &Self) -> &mut Self {
        self.val -= &other.val;
        self
    }

    fn scale(&mut self, other: &F) -> &mut Self {
        self.val *= other;
        self
    }

    fn shift(&mut self, other: &F) -> &mut Self {
        if mpc_net::am_first() {
            self.val += other;
        }
        self
    }

    fn univariate_div_qr<'a>(
        num: DenseOrSparsePolynomial<Self>,
        den: DenseOrSparsePolynomial<F>,
    ) -> Option<(DensePolynomial<Self>, DensePolynomial<Self>)> {
        let num = Self::poly_share(num);
        let den = Self::poly_share2(den);
        num.divide_with_q_and_r(&den)
            .map(|(q, r)| (Self::d_poly_unshare(q), Self::d_poly_unshare(r)))
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
pub struct AdditiveGroupShare<T, M> {
    pub val: T,
    _phants: PhantomData<M>,
}

impl<G: Group, M> Reveal for AdditiveGroupShare<G, M> {
    type Base = G;

    fn reveal(self) -> G {
        let other_val = channel::exchange(&self.val);
        self.val + other_val
    }
    fn from_public(f: G) -> Self {
        Self {
            val: if mpc_net::am_first() { f } else { G::zero() },
            _phants: PhantomData::default(),
        }
    }
    fn from_add_shared(f: G) -> Self {
        Self {
            val: f,
            _phants: PhantomData::default(),
        }
    }
    fn unwrap_as_public(self) -> G {
        self.val
    }
}

impl<G: Group, M: Msm<G, G::ScalarField>> GroupShare<G> for AdditiveGroupShare<G, M> {
    type ScalarShare = AdditiveScalarShare<G::ScalarField>;

    fn batch_open(selfs: impl IntoIterator<Item = Self>) -> Vec<G> {
        let mut self_vec: Vec<G> = selfs.into_iter().map(|s| s.val).collect();
        let other_val = channel::exchange(&self_vec);
        for (s, o) in self_vec.iter_mut().zip(other_val.iter()) {
            *s += o;
        }
        self_vec
    }

    fn add(&mut self, other: &Self) -> &mut Self {
        self.val += &other.val;
        self
    }

    fn sub(&mut self, other: &Self) -> &mut Self {
        self.val -= &other.val;
        self
    }

    fn scale_pub_scalar(&mut self, scalar: &G::ScalarField) -> &mut Self {
        self.val *= *scalar;
        self
    }

    fn scale_pub_group(mut base: G, scalar: &Self::ScalarShare) -> Self {
        base *= scalar.val;
        Self {
            val: base,
            _phants: PhantomData::default(),
        }
    }

    fn shift(&mut self, other: &G) -> &mut Self {
        if mpc_net::am_first() {
            self.val += other;
        }
        self
    }

    fn multi_scale_pub_group(bases: &[G], scalars: &[Self::ScalarShare]) -> Self {
        let scalars: Vec<G::ScalarField> = scalars.into_iter().map(|s| s.val.clone()).collect();
        Self::from_add_shared(M::msm(bases, &scalars))
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
                Self::from_add_shared(<T as UniformRand>::rand(rng))
            }
        }
    };
}
macro_rules! impl_basics_2_param {
    ($share:ident, $bound:ident) => {
        impl<T: $bound, M> Display for $share<T, M> {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.val)
            }
        }
        impl<T: $bound, M> Debug for $share<T, M> {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                write!(f, "{:?}", self.val)
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
            fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
                Self {
                    val: <T as UniformRand>::rand(rng),
                    _phants: PhantomData::default(),
                }
            }
        }
    };
}

impl_basics!(AdditiveScalarShare, Field);
impl_basics_2_param!(AdditiveGroupShare, Group);

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
    pub val: T,
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
    fn unwrap_as_public(self) -> F {
        self.val
    }
}

impl<F: Field> ScalarShare<F> for MulScalarShare<F> {
    fn map_homo<FF: Field, SS: ScalarShare<FF>, Fun: Fn(F) -> FF>(self, _f: Fun) -> SS {
        unimplemented!()
    }
    fn batch_open(selfs: impl IntoIterator<Item = Self>) -> Vec<F> {
        let mut self_vec: Vec<F> = selfs.into_iter().map(|s| s.val).collect();
        let other_val = channel::exchange(&self_vec);
        for (s, o) in self_vec.iter_mut().zip(other_val.iter()) {
            *s *= o;
        }
        self_vec
    }

    fn add(&mut self, _other: &Self) -> &mut Self {
        unimplemented!("add for MulScalarShare")
    }

    fn scale(&mut self, other: &F) -> &mut Self {
        if mpc_net::am_first() {
            self.val *= other;
        }
        self
    }

    fn shift(&mut self, _other: &F) -> &mut Self {
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

macro_rules! groups_share {
    ($struct_name:ident, $affine:ident, $proj:ident) => {
        pub struct $struct_name<E: PairingEngine>(pub PhantomData<E>);

        impl<E: PairingEngine> AffProjShare<E::Fr, E::$affine, E::$proj> for $struct_name<E> {
            type FrShare = AdditiveScalarShare<E::Fr>;
            type AffineShare = AdditiveGroupShare<E::$affine, AdditiveAffineMsm<E::$affine>>;
            type ProjectiveShare = AdditiveGroupShare<E::$proj, AdditiveProjectiveMsm<E::$proj>>;

            fn sh_aff_to_proj(g: Self::AffineShare) -> Self::ProjectiveShare {
                g.map_homo(|s| s.into())
            }

            fn sh_proj_to_aff(g: Self::ProjectiveShare) -> Self::AffineShare {
                g.map_homo(|s| s.into())
            }

            fn add_sh_proj_sh_aff(
                mut a: Self::ProjectiveShare,
                o: &Self::AffineShare,
            ) -> Self::ProjectiveShare {
                a.val.add_assign_mixed(&o.val);
                a
            }
            fn add_sh_proj_pub_aff(mut a: Self::ProjectiveShare, o: &E::$affine) -> Self::ProjectiveShare {
                if mpc_net::am_first() {
                    a.val.add_assign_mixed(&o);
                }
                a
            }
            fn add_pub_proj_sh_aff(_a: &E::$proj, _o: Self::AffineShare) -> Self::ProjectiveShare {
                unimplemented!()
            }
        }
    };
}

groups_share!(AdditiveG1Share, G1Affine, G1Projective);
groups_share!(AdditiveG2Share, G2Affine, G2Projective);

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
    type G1AffineShare = AdditiveGroupShare<E::G1Affine, AdditiveAffineMsm<E::G1Affine>>;
    type G2AffineShare = AdditiveGroupShare<E::G2Affine, AdditiveAffineMsm<E::G2Affine>>;
    type G1ProjectiveShare =
        AdditiveGroupShare<E::G1Projective, AdditiveProjectiveMsm<E::G1Projective>>;
    type G2ProjectiveShare =
        AdditiveGroupShare<E::G2Projective, AdditiveProjectiveMsm<E::G2Projective>>;
    type G1 = AdditiveG1Share<E>;
    type G2 = AdditiveG2Share<E>;
}

#[derive(Debug, Derivative)]
#[derivative(Default(bound = ""), Clone(bound = ""), Copy(bound = ""))]
pub struct NaiveMsm<G: Group>(pub PhantomData<G>);

impl<G: Group> Msm<G, G::ScalarField> for NaiveMsm<G> {
    fn msm(bases: &[G], scalars: &[G::ScalarField]) -> G {
        bases
            .iter()
            .zip(scalars.iter())
            .map(|(b, s)| {
                let mut b = b.clone();
                b *= *s;
                b
            })
            .fold(G::zero(), |a, b| a + b)
    }
}

#[derive(Debug, Derivative)]
#[derivative(Default(bound = ""), Clone(bound = ""), Copy(bound = ""))]
pub struct AdditiveAffineMsm<G: AffineCurve>(pub PhantomData<G>);

impl<G: AffineCurve> Msm<G, G::ScalarField> for AdditiveAffineMsm<G> {
    fn msm(bases: &[G], scalars: &[G::ScalarField]) -> G {
        G::multi_scalar_mul(bases, scalars).into()
    }
}

#[derive(Debug, Derivative)]
#[derivative(Default(bound = ""), Clone(bound = ""), Copy(bound = ""))]
pub struct AdditiveProjectiveMsm<G: ProjectiveCurve>(pub PhantomData<G>);

impl<G: ProjectiveCurve> Msm<G, G::ScalarField> for AdditiveProjectiveMsm<G> {
    fn msm(bases: &[G], scalars: &[G::ScalarField]) -> G {
        let bases: Vec<G::Affine> = bases.iter().map(|s| s.clone().into()).collect();
        <G::Affine as AffineCurve>::multi_scalar_mul(&bases, scalars)
    }
}
