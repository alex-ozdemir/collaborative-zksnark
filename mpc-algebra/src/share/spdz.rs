#![macro_use]
use derivative::Derivative;
use rand::Rng;

use ark_ec::{group::Group, AffineCurve, PairingEngine, ProjectiveCurve};
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

use mpc_net::{MpcNet, MpcMultiNet as Net};
use crate::channel::{can_cheat, MpcSerNet};

use super::add::{AdditiveFieldShare, AdditiveGroupShare, MulFieldShare};
use super::field::{DenseOrSparsePolynomial, DensePolynomial, ExtFieldShare, FieldShare};
use super::group::GroupShare;
use super::msm::*;
use super::pairing::{AffProjShare, PairingShare};
use super::{BeaverSource, PanicBeaverSource};
use crate::Reveal;

#[inline]
pub fn mac_share<F: Field>() -> F {
    if Net::am_king() {
        F::one()
    } else {
        F::zero()
    }
}

#[inline]
/// A huge cheat. Useful for importing shares.
pub fn mac<F: Field>() -> F {
    if can_cheat() {
        F::one()
    } else {
        panic!("Attempted to grab the MAC secret while cheating was not allowed")
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct SpdzFieldShare<T> {
    sh: AdditiveFieldShare<T>,
    mac: AdditiveFieldShare<T>,
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
impl_basics_spdz!(SpdzFieldShare, Field);

impl<F: Field> Reveal for SpdzFieldShare<F> {
    type Base = F;

    fn reveal(self) -> F {
        let vals: Vec<F> = Net::broadcast(&self.sh.val);
        // _Pragmatic MPC_ 6.6.2
        let x: F = vals.iter().sum();
        let dx_t: F = mac_share::<F>() * x - self.mac.val;
        let all_dx_ts: Vec<F> = Net::atomic_broadcast(&dx_t);
        let sum: F = all_dx_ts.iter().sum();
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
    fn king_share<R: Rng>(f: Self::Base, rng: &mut R) -> Self {
        let mut r: Vec<F> = (0..(Net::n_parties()-1)).map(|_| F::rand(rng)).collect();
        let sum_r: F = r.iter().sum();
        r.push(f - sum_r);
        Self::from_add_shared(Net::recv_from_king( if Net::am_king() { Some(r) } else { None }))
    }
    fn king_share_batch<R: Rng>(f: Vec<Self::Base>, rng: &mut R) -> Vec<Self> {
        let mut rs: Vec<Vec<Self::Base>> =
            (0..(Net::n_parties()-1)).map(|_| {
            (0..f.len()).map(|_| {
                F::rand(rng)
            }).collect()
        }).collect();
        let final_shares: Vec<Self::Base> = (0..rs[0].len()).map(|i| {
            f[i] - &rs.iter().map(|r| &r[i]).sum()
        }).collect();
        rs.push(final_shares);
        Net::recv_from_king(if Net::am_king() { Some(rs) } else {None}).into_iter().map(Self::from_add_shared).collect()
    }
}

impl<F: Field> FieldShare<F> for SpdzFieldShare<F> {
    fn batch_open(selfs: impl IntoIterator<Item = Self>) -> Vec<F> {
        let (s_vals, macs): (Vec<F>, Vec<F>) =
            selfs.into_iter().map(|s| (s.sh.val, s.mac.val)).unzip();
        let n = s_vals.len();
        let all_vals = Net::broadcast(&s_vals);
        let vals: Vec<F> =
            (0..n).map(|i| all_vals.iter().map(|v| &v[i]).sum()).collect();
        let dx_ts: Vec<F> =
            macs
            .iter()
            .zip(vals.iter())
            .map(|(mac, val)| mac_share::<F>() * val - mac)
            .collect();
        let all_dx_ts: Vec<Vec<F>> = Net::atomic_broadcast(&dx_ts);
        for i in 0..n {
            let sum: F = all_dx_ts.iter().map(|dx_ts| &dx_ts[i]).sum();
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
        let (q_sh, r_sh) = AdditiveFieldShare::univariate_div_qr(num_sh, den.clone()).unwrap();
        let (q_mac, r_mac) = AdditiveFieldShare::univariate_div_qr(num_mac, den).unwrap();
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
        let vals: Vec<G> = Net::broadcast(&self.sh.val);
        // _Pragmatic MPC_ 6.6.2
        let x: G = vals.iter().sum();
        let dx_t: G = {
            let mut t = x.clone();
            t *= mac_share::<G::ScalarField>();
            t - self.mac.val
        };
        let all_dx_ts: Vec<G> = Net::atomic_broadcast(&dx_t);
        let sum: G = all_dx_ts.iter().sum();
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
    fn king_share<R: Rng>(f: Self::Base, rng: &mut R) -> Self {
        let mut r: Vec<G> = (0..(Net::n_parties()-1)).map(|_| G::rand(rng)).collect();
        let sum_r: G = r.iter().sum();
        r.push(f - sum_r);
        Self::from_add_shared(Net::recv_from_king( if Net::am_king() { Some(r) } else { None }))
    }
    fn king_share_batch<R: Rng>(f: Vec<Self::Base>, rng: &mut R) -> Vec<Self> {
        let mut rs: Vec<Vec<Self::Base>> =
            (0..(Net::n_parties()-1)).map(|_| {
            (0..f.len()).map(|_| {
                Self::Base::rand(rng)
            }).collect()
        }).collect();
        let final_shares: Vec<Self::Base> = (0..rs[0].len()).map(|i| {
            f[i] - &rs.iter().map(|r| &r[i]).sum()
        }).collect();
        rs.push(final_shares);
        Net::recv_from_king(if Net::am_king() { Some(rs) } else {None}).into_iter().map(Self::from_add_shared).collect()
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
    type FieldShare = SpdzFieldShare<G::ScalarField>;

    fn batch_open(selfs: impl IntoIterator<Item = Self>) -> Vec<G> {
        let (s_vals, macs): (Vec<G>, Vec<G>) =
            selfs.into_iter().map(|s| (s.sh.val, s.mac.val)).unzip();
        let n = s_vals.len();
        let all_vals = Net::broadcast(&s_vals);
        let vals: Vec<G> =
            (0..n).map(|i| all_vals.iter().map(|v| &v[i]).sum()).collect();
        let dx_ts: Vec<G> =
            macs
            .iter()
            .zip(vals.iter())
            .map(|(mac, val)| val.mul(&mac_share::<G::ScalarField>()) - mac)
            .collect();
        let all_dx_ts: Vec<Vec<G>> = Net::atomic_broadcast(&dx_ts);
        for i in 0..n {
            let sum: G = all_dx_ts.iter().map(|dx_ts| &dx_ts[i]).sum();
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

    fn scale_pub_group(base: G, scalar: &Self::FieldShare) -> Self {
        let sh = AdditiveGroupShare::scale_pub_group(base, &scalar.sh);
        let mac = AdditiveGroupShare::scale_pub_group(base, &scalar.mac);
        Self { sh, mac }
    }

    fn shift(&mut self, other: &G) -> &mut Self {
        if Net::am_king() {
            self.sh.shift(other);
        }
        let mut other = other.clone();
        other *= mac_share::<G::ScalarField>();
        self.mac.val += other;
        self
    }

    fn multi_scale_pub_group(bases: &[G], scalars: &[Self::FieldShare]) -> Self {
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
pub struct SpdzMulFieldShare<T, S> {
    sh: MulFieldShare<T>,
    mac: MulFieldShare<T>,
    _phants: PhantomData<S>,
}
impl_spdz_basics_2_param!(SpdzMulFieldShare, Field);

impl<F: Field, S: PrimeField> Reveal for SpdzMulFieldShare<F, S> {
    type Base = F;

    fn reveal(self) -> F {
        let vals: Vec<F> = Net::broadcast(&self.sh.val);
        // _Pragmatic MPC_ 6.6.2
        let x: F = vals.iter().product();
        let dx_t: F = x.pow(&mac_share::<S>().into_repr()) / self.mac.val;
        let all_dx_ts: Vec<F> = Net::atomic_broadcast(&dx_t);
        let prod: F = all_dx_ts.iter().product();
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

impl<F: Field, S: PrimeField> FieldShare<F> for SpdzMulFieldShare<F, S> {
    fn add(&mut self, _other: &Self) -> &mut Self {
        unimplemented!("add for SpdzMulFieldShare")
    }

    fn scale(&mut self, other: &F) -> &mut Self {
        if Net::am_king() {
            self.sh.scale(other);
        }
        self.mac.scale(&other.pow(&mac_share::<S>().into_repr()));
        self
    }

    fn shift(&mut self, _other: &F) -> &mut Self {
        unimplemented!("add for SpdzMulFieldShare")
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
    type Ext = SpdzMulFieldShare<F, S>;
    type Base = SpdzMulFieldShare<F::BasePrimeField, S>;
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
pub struct SpdzExtFieldShare<F: Field>(pub PhantomData<F>);

impl<F: Field> ExtFieldShare<F> for SpdzExtFieldShare<F> {
    type Ext = AdditiveFieldShare<F>;
    type Base = AdditiveFieldShare<F::BasePrimeField>;
}

macro_rules! groups_share {
    ($struct_name:ident, $affine:ident, $proj:ident) => {
        pub struct $struct_name<E: PairingEngine>(pub PhantomData<E>);

        impl<E: PairingEngine> AffProjShare<E::Fr, E::$affine, E::$proj> for $struct_name<E> {
            type FrShare = SpdzFieldShare<E::Fr>;
            type AffineShare = SpdzGroupShare<E::$affine, AffineMsm<E::$affine>>;
            type ProjectiveShare = SpdzGroupShare<E::$proj, ProjectiveMsm<E::$proj>>;

            fn sh_aff_to_proj(g: Self::AffineShare) -> Self::ProjectiveShare {
                SpdzGroupShare {
                    sh: g.sh.map_homo(|s| s.into()),
                    mac: g.mac.map_homo(|s| s.into()),
                }
            }

            fn sh_proj_to_aff(g: Self::ProjectiveShare) -> Self::AffineShare {
                SpdzGroupShare {
                    sh: g.sh.map_homo(|s| s.into()),
                    mac: g.mac.map_homo(|s| s.into()),
                }
            }

            fn add_sh_proj_sh_aff(
                mut a: Self::ProjectiveShare,
                o: &Self::AffineShare,
            ) -> Self::ProjectiveShare {
                a.sh.val.add_assign_mixed(&o.sh.val);
                a.mac.val.add_assign_mixed(&o.mac.val);
                a
            }
            fn add_sh_proj_pub_aff(
                mut a: Self::ProjectiveShare,
                o: &E::$affine,
            ) -> Self::ProjectiveShare {
                if Net::am_king() {
                    a.sh.val.add_assign_mixed(&o);
                }
                a.mac.val += &o.scalar_mul(mac_share::<E::Fr>());
                a
            }
            fn add_pub_proj_sh_aff(_a: &E::$proj, _o: Self::AffineShare) -> Self::ProjectiveShare {
                unimplemented!()
            }
        }
    };
}

groups_share!(SpdzG1Share, G1Affine, G1Projective);
groups_share!(SpdzG2Share, G2Affine, G2Projective);

#[derive(Debug, Derivative)]
#[derivative(
    Default(bound = ""),
    Clone(bound = ""),
    Copy(bound = ""),
    PartialEq(bound = "E::G1Affine: PartialEq"),
    Eq(bound = "E::G1Affine: Eq"),
    Hash(bound = "E::G1Affine: Hash")
)]
pub struct SpdzPairingShare<E: PairingEngine>(pub PhantomData<E>);

impl<E: PairingEngine> PairingShare<E> for SpdzPairingShare<E> {
    type FrShare = SpdzFieldShare<E::Fr>;
    type FqShare = SpdzFieldShare<E::Fq>;
    type FqeShare = SpdzExtFieldShare<E::Fqe>;
    // Not a typo. We want a multiplicative subgroup.
    type FqkShare = SpdzMulExtFieldShare<E::Fqk, E::Fr>;
    type G1AffineShare = SpdzGroupShare<E::G1Affine, AffineMsm<E::G1Affine>>;
    type G2AffineShare = SpdzGroupShare<E::G2Affine, AffineMsm<E::G2Affine>>;
    type G1ProjectiveShare =
        SpdzGroupShare<E::G1Projective, ProjectiveMsm<E::G1Projective>>;
    type G2ProjectiveShare =
        SpdzGroupShare<E::G2Projective, ProjectiveMsm<E::G2Projective>>;
    type G1 = SpdzG1Share<E>;
    type G2 = SpdzG2Share<E>;
}
