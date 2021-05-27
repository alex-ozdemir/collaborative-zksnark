use ark_ec::group::Group;
use ark_ec::msm::VariableBaseMSM;
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::bytes::{FromBytes, ToBytes};
use ark_ff::prelude::*;
use ark_ff::FftField;
use ark_serialize::{
    CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize,
    CanonicalSerializeWithFlags, Flags, SerializationError,
};
use ark_std::cfg_into_iter;
use ark_std::io::{self, Read, Write};
use core::ops::*;
use derivative::Derivative;
use rand::Rng;
use std::cmp::Ord;
use std::default::Default;
use std::fmt::{self, Debug, Display, Formatter};
use std::hash::Hash;
use std::iter::{Product, Sum};
use std::marker::PhantomData;
use zeroize::Zeroize;

use crate::mpc::channel;
use mpc_trait::MpcWire;

use super::super::share::field::{ExtFieldShare, ScalarShare};
use super::super::share::pairing::PairingShare;
use super::super::share::BeaverSource;
use super::field::MpcField;
use super::group::MpcGroup;

#[derive(Derivative)]
#[derivative(Default(bound = ""), Clone(bound = ""), Copy(bound = ""))]
pub struct DummyPairingTripleSource<E, S> {
    _phants: PhantomData<(E, S)>,
}

impl<E: PairingEngine, S: PairingShare<E>>
    BeaverSource<MpcG1Projective<E, S>, MpcG2Projective<E, S>, MpcExtField<E::Fqk, S::FqkShare>>
    for DummyPairingTripleSource<E, S>
{
    fn triple(
        &mut self,
    ) -> (
        MpcG1Projective<E, S>,
        MpcG2Projective<E, S>,
        MpcExtField<E::Fqk, S::FqkShare>,
    ) {
        let g1 = E::G1Projective::zero();
        let g2 = E::G2Projective::zero();
        (
            MpcG1Projective::from_public(g1.clone()),
            MpcG2Projective::from_public(g2.clone()),
            MpcExtField::from_public(E::pairing(g1, g2)),
        )
    }
    fn inv_pair(&mut self) -> (MpcG2Projective<E, S>, MpcG2Projective<E, S>) {
        unimplemented!("No inverses from Pairing triple source")
    }
}

#[derive(Debug, Derivative)]
#[derivative(
    Clone(bound = ""),
    Copy(bound = ""),
    PartialEq(bound = "E::G1Affine: PartialEq"),
    Eq(bound = "E::G1Affine: Eq"),
    Hash(bound = "E::G1Affine: Hash")
)]
pub struct MpcG1Affine<E: PairingEngine, PS: PairingShare<E>> {
    pub val: MpcGroup<E::G1Affine, PS::G1AffineShare>,
}

#[derive(Debug, Derivative)]
#[derivative(
    Clone(bound = ""),
    Copy(bound = ""),
    PartialEq(bound = "E::G1Affine: PartialEq"),
    Eq(bound = "E::G1Affine: Eq"),
    Hash(bound = "E::G1Affine: Hash")
)]
pub struct MpcG1Projective<E: PairingEngine, PS: PairingShare<E>> {
    pub val: MpcGroup<E::G1Projective, PS::G1ProjectiveShare>,
}

#[derive(Debug, Derivative)]
#[derivative(
    Clone(bound = ""),
    Copy(bound = ""),
    Default(bound = ""),
    PartialEq(bound = "E::G1Affine: PartialEq"),
    Eq(bound = "E::G1Affine: Eq"),
    Hash(bound = "E::G1Affine: Hash")
)]
/// Currently a dummy structure. Never used!
pub struct MpcG1Prep<E: PairingEngine, PS: PairingShare<E>> {
    pub _phants: PhantomData<(E, PS)>,
}

#[derive(Debug, Derivative)]
#[derivative(
    Clone(bound = ""),
    Copy(bound = ""),
    PartialEq(bound = "E::G1Affine: PartialEq"),
    Eq(bound = "E::G1Affine: Eq"),
    Hash(bound = "E::G1Affine: Hash")
)]
pub struct MpcG2Affine<E: PairingEngine, PS: PairingShare<E>> {
    pub val: MpcGroup<E::G2Affine, PS::G2AffineShare>,
}

#[derive(Debug, Derivative)]
#[derivative(
    Clone(bound = ""),
    Copy(bound = ""),
    PartialEq(bound = "E::G1Affine: PartialEq"),
    Eq(bound = "E::G1Affine: Eq"),
    Hash(bound = "E::G1Affine: Hash")
)]
pub struct MpcG2Projective<E: PairingEngine, PS: PairingShare<E>> {
    pub val: MpcGroup<E::G2Projective, PS::G2ProjectiveShare>,
}
#[derive(Debug, Derivative)]
#[derivative(
    Clone(bound = ""),
    Copy(bound = ""),
    Default(bound = ""),
    PartialEq(bound = "E::G1Affine: PartialEq"),
    Eq(bound = "E::G1Affine: Eq"),
    Hash(bound = "E::G1Affine: Hash")
)]
/// Currently a dummy structure. Never used!
pub struct MpcG2Prep<E: PairingEngine, PS: PairingShare<E>> {
    pub _phants: PhantomData<(E, PS)>,
}
#[derive(Derivative)]
#[derivative(
    Clone(bound = ""),
    Copy(bound = ""),
    PartialEq(bound = "F: PartialEq"),
    Eq(bound = "F: Eq"),
    Hash(bound = "F: Hash"),
    Debug(bound = "F: Debug"),
    PartialOrd(bound = "F: PartialOrd"),
    Ord(bound = "F: Ord")
)]
pub struct MpcExtField<F: Field, FS: ExtFieldShare<F>> {
    pub val: MpcField<F, FS::Ext>,
}

/// A wrapper for a pairing engine
#[derive(Derivative)]
#[derivative(
    Clone(bound = ""),
    Copy(bound = ""),
    Default(bound = ""),
    Debug(bound = ""),
    PartialEq(bound = ""),
    Eq(bound = "")
)]
pub struct MpcPairingEngine<E: PairingEngine, PS: PairingShare<E>> {
    _phants: PhantomData<(E, PS)>,
}

impl<E: PairingEngine, PS: PairingShare<E>> PairingEngine for MpcPairingEngine<E, PS> {
    type Fr = MpcField<E::Fr, PS::FrShare>;
    type Fq = MpcField<E::Fq, PS::FqShare>;
    type Fqe = MpcExtField<E::Fqe, PS::FqeShare>;
    type G1Affine = MpcG1Affine<E, PS>;
    type G1Projective = MpcG1Projective<E, PS>;
    type G1Prepared = MpcG1Prep<E, PS>;
    type G2Affine = MpcG2Affine<E, PS>;
    type G2Projective = MpcG2Projective<E, PS>;
    type G2Prepared = MpcG2Prep<E, PS>;
    type Fqk = MpcExtField<E::Fqk, PS::FqkShare>;

    fn miller_loop<'a, I>(_i: I) -> Self::Fqk
    where
        I: IntoIterator<Item = &'a (Self::G1Prepared, Self::G2Prepared)>,
    {
        unimplemented!("miller_loop")
        // <Bls12_377 as PairingEngine>::miller_loop(i)
    }

    fn final_exponentiation(_f: &Self::Fqk) -> Option<Self::Fqk> {
        unimplemented!("final_exponentiation")
        // <Bls12_377 as PairingEngine>::final_exponentiation(f)
    }

    /// Computes a product of pairings.
    #[must_use]
    fn product_of_pairings<'a, I>(_i: I) -> Self::Fqk
    where
        I: IntoIterator<Item = &'a (Self::G1Prepared, Self::G2Prepared)>,
    {
        // TODO: MPC!
        // <Bls12_377 as PairingEngine>::product_of_pairings(i)
        unimplemented!("pairing product")
    }

    /// Performs multiple pairing operations
    #[must_use]
    fn pairing<G1, G2>(p: G1, q: G2) -> Self::Fqk
    where
        G1: Into<Self::G1Affine>,
        G2: Into<Self::G2Affine>,
    {
        let source = &mut DummyPairingTripleSource::default();
        let a: Self::G1Affine = p.into();
        let b: Self::G2Affine = q.into();
        let a: Self::G1Projective = a.into();
        let b: Self::G2Projective = b.into();
        if a.is_shared() && b.is_shared() {
            //let a = a.unwrap_as_public();
            //let b = b.unwrap_as_public();
            // x * y = z
            let (x, y, z) = source.triple();
            // x + a
            let xa = (a + x).open();
            // y + b
            let yb = (b + y).open();
            let xayb: MpcExtField<E::Fqk, PS::FqkShare> =
                MpcExtField::wrap(MpcField::Public(E::pairing(xa, yb)));
            let xay: MpcExtField<E::Fqk, PS::FqkShare> = MpcExtField::wrap(MpcField::Shared(
                <PS::FqkShare as ExtFieldShare<E::Fqk>>::Ext::wrap_as_shared(E::pairing(
                    xa,
                    y.unwrap_as_public(),
                )),
            ));
            let xyb: MpcExtField<E::Fqk, PS::FqkShare> = MpcExtField::wrap(MpcField::Shared(
                <PS::FqkShare as ExtFieldShare<E::Fqk>>::Ext::wrap_as_shared(E::pairing(
                    x.unwrap_as_public(),
                    yb,
                )),
            ));
            z / xay / xyb * xayb
        } else {
            MpcExtField::wrap(MpcField::Public(E::pairing(a.open(), b.open())))
        }
    }
}

macro_rules! impl_pairing_mpc_wrapper {
    ($wrapped:ident, $bound1:ident, $bound2:ident, $base:ident, $share:ident, $wrap:ident) => {
        impl<E: $bound1, PS: $bound2<E>> Display for $wrap<E, PS> {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.val)
            }
        }
        impl<E: $bound1, PS: $bound2<E>> ToBytes for $wrap<E, PS> {
            fn write<W: Write>(&self, _writer: W) -> io::Result<()> {
                unimplemented!("write")
            }
        }
        impl<E: $bound1, PS: $bound2<E>> FromBytes for $wrap<E, PS> {
            fn read<R: Read>(_reader: R) -> io::Result<Self> {
                unimplemented!("read")
            }
        }
        impl<E: $bound1, PS: $bound2<E>> CanonicalSerialize for $wrap<E, PS> {
            fn serialize<W: Write>(&self, _writer: W) -> Result<(), SerializationError> {
                unimplemented!("serialize")
            }
            fn serialized_size(&self) -> usize {
                unimplemented!("serialized_size")
            }
        }
        impl<E: $bound1, PS: $bound2<E>> CanonicalSerializeWithFlags for $wrap<E, PS> {
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
        impl<E: $bound1, PS: $bound2<E>> CanonicalDeserialize for $wrap<E, PS> {
            fn deserialize<R: Read>(_reader: R) -> Result<Self, SerializationError> {
                unimplemented!("deserialize")
            }
        }
        impl<E: $bound1, PS: $bound2<E>> CanonicalDeserializeWithFlags for $wrap<E, PS> {
            fn deserialize_with_flags<R: Read, F: Flags>(
                _reader: R,
            ) -> Result<(Self, F), SerializationError> {
                unimplemented!("deserialize_with_flags")
            }
        }
        impl<E: $bound1, PS: $bound2<E>> UniformRand for $wrap<E, PS> {
            fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
                Self {
                    val: $wrapped::rand(rng),
                }
            }
        }
        impl<E: $bound1, PS: $bound2<E>> Add for $wrap<E, PS> {
            type Output = Self;
            fn add(self, other: Self) -> Self::Output {
                Self {
                    val: self.val + other.val,
                }
            }
        }
        impl<E: $bound1, PS: $bound2<E>> Neg for $wrap<E, PS> {
            type Output = Self;
            fn neg(self) -> Self::Output {
                Self { val: -self.val }
            }
        }
        impl<E: $bound1, PS: $bound2<E>> Sub for $wrap<E, PS> {
            type Output = Self;
            fn sub(self, other: Self) -> Self::Output {
                Self {
                    val: self.val - other.val,
                }
            }
        }
        impl<E: $bound1, PS: $bound2<E>> Zero for $wrap<E, PS> {
            fn zero() -> Self {
                Self {
                    val: $wrapped::zero(),
                }
            }
            fn is_zero(&self) -> bool {
                self.val.is_zero()
            }
        }
        impl<E: $bound1, PS: $bound2<E>> Sum for $wrap<E, PS> {
            fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
                iter.fold(Self::zero(), Add::add)
            }
        }
        impl<'a, E: $bound1, PS: $bound2<E>> Sum<&'a $wrap<E, PS>> for $wrap<E, PS> {
            fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
                iter.fold(Self::zero(), |x, y| x.add((*y).clone()))
            }
        }
        impl<E: $bound1, PS: $bound2<E>> Zeroize for $wrap<E, PS> {
            fn zeroize(&mut self) {
                self.val.zeroize();
            }
        }
        impl<E: $bound1, PS: $bound2<E>> Default for $wrap<E, PS> {
            fn default() -> Self {
                Self::zero()
            }
        }
        impl<E: $bound1, PS: $bound2<E>> MpcWire for $wrap<E, PS> {
            fn publicize(&mut self) {
                self.val.publicize();
            }
            fn set_shared(&mut self, shared: bool) {
                self.val.set_shared(shared);
            }
            fn is_shared(&self) -> bool {
                self.val.is_shared()
            }
        }
        impl_ref_ops!(Sub, SubAssign, sub, sub_assign, $bound1, $bound2, $wrap);
        impl_ref_ops!(Add, AddAssign, add, add_assign, $bound1, $bound2, $wrap);
    };
}
macro_rules! impl_ext_field_wrapper {
    ($wrapped:ident, $wrap:ident) => {
        impl<E: Field, PS: ExtFieldShare<E>> $wrap<E, PS> {
            pub fn wrap(val: $wrapped<E, PS::Ext>) -> Self {
                Self { val }
            }
            pub fn new(t: E, shared: bool) -> Self {
                Self::wrap($wrapped::new(t, shared))
            }
            pub fn from_public(t: E) -> Self {
                Self::wrap($wrapped::from_public(t))
            }
            pub fn unwrap_as_public(self) -> E {
                self.val.unwrap_as_public()
            }
        }
        impl_pairing_mpc_wrapper!($wrapped, Field, ExtFieldShare, BasePrimeField, Ext, $wrap);
        impl<E: Field, PS: ExtFieldShare<E>> Mul for $wrap<E, PS> {
            type Output = Self;
            fn mul(self, other: Self) -> Self::Output {
                Self::wrap(self.val.mul(other.val))
            }
        }
        impl<E: Field, PS: ExtFieldShare<E>> Div for $wrap<E, PS> {
            type Output = Self;
            fn div(self, other: Self) -> Self::Output {
                Self::wrap(self.val.div(other.val))
            }
        }
        impl_ref_ops!(Mul, MulAssign, mul, mul_assign, Field, ExtFieldShare, $wrap);
        impl_ref_ops!(Div, DivAssign, div, div_assign, Field, ExtFieldShare, $wrap);
        impl<E: Field, PS: ExtFieldShare<E>> One for $wrap<E, PS> {
            fn one() -> Self {
                Self {
                    val: $wrapped::one(),
                }
            }
            fn is_one(&self) -> bool {
                self.val.is_one()
            }
        }
        impl<E: Field, PS: ExtFieldShare<E>> Product for $wrap<E, PS> {
            fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
                iter.fold(Self::one(), Add::add)
            }
        }
        impl<'a, E: Field, PS: ExtFieldShare<E>> Product<&'a $wrap<E, PS>> for $wrap<E, PS> {
            fn product<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
                iter.fold(Self::one(), |x, y| x.add((*y).clone()))
            }
        }
        impl<E: Field, PS: ExtFieldShare<E>> $wrap<E, PS> {
            pub fn open(&self) -> E {
                self.val.open()
            }
        }
        from_prim!(bool, Field, ExtFieldShare, $wrap);
        from_prim!(u8, Field, ExtFieldShare, $wrap);
        from_prim!(u16, Field, ExtFieldShare, $wrap);
        from_prim!(u32, Field, ExtFieldShare, $wrap);
        from_prim!(u64, Field, ExtFieldShare, $wrap);
        from_prim!(u128, Field, ExtFieldShare, $wrap);
        impl<F: Field, S: ExtFieldShare<F>> Field for $wrap<F, S> {
            type BasePrimeField = MpcField<F::BasePrimeField, S::Base>;
            fn extension_degree() -> u64 {
                unimplemented!("extension_degree")
            }
            fn from_base_prime_field_elems(
                b: &[<Self as ark_ff::Field>::BasePrimeField],
            ) -> Option<Self> {
                assert!(b.len() > 0);
                let shared = b[0].is_shared();
                assert!(b.iter().all(|e| e.is_shared() == shared));
                let base_values = b.iter().map(|e| e.unwrap_as_public()).collect::<Vec<_>>();
                F::from_base_prime_field_elems(&base_values).map(|val| Self::new(val, shared))
            }
            fn double(&self) -> Self {
                Self::wrap(self.val * $wrapped::from_public(F::from(2u8)))
            }
            fn double_in_place(&mut self) -> &mut Self {
                self.val *= $wrapped::from_public(F::from(2u8));
                self
            }
            fn from_random_bytes_with_flags<Fl: Flags>(b: &[u8]) -> Option<(Self, Fl)> {
                F::from_random_bytes_with_flags(b).map(|(val, f)| (Self::new(val, true), f))
            }
            fn square(&self) -> Self {
                self.clone() * self
            }
            fn square_in_place(&mut self) -> &mut Self {
                *self *= self.clone();
                self
            }
            fn inverse(&self) -> Option<Self> {
                self.val.inv().map(Self::wrap)
            }
            fn inverse_in_place(&mut self) -> Option<&mut Self> {
                self.val.inv().map(|i| {
                    self.val = i;
                    self
                })
            }
            fn frobenius_map(&mut self, _: usize) {
                unimplemented!("frobenius_map")
            }
        }

        impl<F: FftField, S: ExtFieldShare<F>> FftField for $wrap<F, S> {
            type FftParams = F::FftParams;
            fn two_adic_root_of_unity() -> Self {
                Self::from_public(F::two_adic_root_of_unity())
            }
            fn large_subgroup_root_of_unity() -> Option<Self> {
                F::large_subgroup_root_of_unity().map(Self::from_public)
            }
            fn multiplicative_generator() -> Self {
                Self::from_public(F::multiplicative_generator())
            }
        }

        impl<F: PrimeField, S: ExtFieldShare<F>> std::str::FromStr for $wrap<F, S> {
            type Err = F::Err;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                $wrapped::from_str(s).map(Self::wrap)
            }
        }

        // impl<F: PrimeField, S: ExtFieldShare<F>> PrimeField for $wrap<F, S> {
        //     type Params = F::Params;
        //     type BigInt = F::BigInt;
        //     fn from_repr(r: <Self as PrimeField>::BigInt) -> Option<Self> {
        //         // F::from_repr(r.val).map(|v| MpcVal::new(v, r.shared))
        //         F::from_repr(r).map(|v| Self::from_public(v))
        //     }
        //     // We're assuming that into_repr is linear
        //     fn into_repr(&self) -> <Self as PrimeField>::BigInt {
        //         // MpcVal::new(self.val.into_repr(), self.shared)
        //         self.unwrap_as_public().into_repr()
        //     }
        // }

        impl<F: SquareRootField, S: ExtFieldShare<F>> SquareRootField for $wrap<F, S> {
            fn legendre(&self) -> ark_ff::LegendreSymbol {
                todo!()
            }
            fn sqrt(&self) -> Option<Self> {
                todo!()
            }
            fn sqrt_in_place(&mut self) -> Option<&mut Self> {
                todo!()
            }
        }
    };
}
macro_rules! impl_pairing_curve_wrapper {
    ($wrapped:ident, $bound1:ident, $bound2:ident, $base:ident, $share:ident, $wrap:ident) => {
        impl<E: $bound1, PS: $bound2<E>> $wrap<E, PS> {
            pub fn new(t: E::$base, shared: bool) -> Self {
                Self {
                    val: $wrapped::new(t, shared),
                }
            }
            pub fn from_public(t: E::$base) -> Self {
                Self {
                    val: $wrapped::from_public(t),
                }
            }
            pub fn unwrap_as_public(self) -> E::$base {
                self.val.unwrap_as_public()
            }
            pub fn open(&self) -> E::$base {
                self.val.open()
            }
        }
        impl_pairing_mpc_wrapper!($wrapped, $bound1, $bound2, $base, $share, $wrap);
        impl<E: $bound1, PS: $bound2<E>> Mul<MpcField<E::Fr, PS::FrShare>> for $wrap<E, PS> {
            type Output = Self;
            fn mul(self, other: MpcField<E::Fr, PS::FrShare>) -> Self::Output {
                Self {
                    val: self.val.mul(other),
                }
            }
        }
        impl<'a, E: $bound1, PS: $bound2<E>> Mul<&'a MpcField<E::Fr, PS::FrShare>>
            for $wrap<E, PS>
        {
            type Output = Self;
            fn mul(self, other: &'a MpcField<E::Fr, PS::FrShare>) -> Self::Output {
                Self {
                    val: self.val.mul(other),
                }
            }
        }
        impl<E: $bound1, PS: $bound2<E>> MulAssign<MpcField<E::Fr, PS::FrShare>> for $wrap<E, PS> {
            fn mul_assign(&mut self, other: MpcField<E::Fr, PS::FrShare>) {
                self.val.mul_assign(other);
            }
        }
        impl<'a, E: $bound1, PS: $bound2<E>> MulAssign<&'a MpcField<E::Fr, PS::FrShare>>
            for $wrap<E, PS>
        {
            fn mul_assign(&mut self, other: &'a MpcField<E::Fr, PS::FrShare>) {
                self.val.mul_assign(other);
            }
        }
    };
}

impl_pairing_curve_wrapper!(
    MpcGroup,
    PairingEngine,
    PairingShare,
    G1Affine,
    G1AffineShare,
    MpcG1Affine
);
impl_pairing_curve_wrapper!(
    MpcGroup,
    PairingEngine,
    PairingShare,
    G1Projective,
    G1ProjectiveShare,
    MpcG1Projective
);
impl_pairing_curve_wrapper!(
    MpcGroup,
    PairingEngine,
    PairingShare,
    G2Affine,
    G2AffineShare,
    MpcG2Affine
);
impl_pairing_curve_wrapper!(
    MpcGroup,
    PairingEngine,
    PairingShare,
    G2Projective,
    G2ProjectiveShare,
    MpcG2Projective
);
impl_ext_field_wrapper!(MpcField, MpcExtField);

macro_rules! impl_aff_proj {
    ($w_prep:ident, $prep:ident, $w_aff:ident, $w_pro:ident, $aff:ident, $pro:ident, $pro_to_aff:ident, $aff_to_pro:ident, $w_base:ident, $base:ident, $base_share:ident) => {
        impl<E: PairingEngine, PS: PairingShare<E>> Group for $w_aff<E, PS> {
            type ScalarField = MpcField<E::Fr, PS::FrShare>;
        }
        impl<E: PairingEngine, PS: PairingShare<E>> From<$w_pro<E, PS>> for $w_aff<E, PS> {
            fn from(o: $w_pro<E, PS>) -> Self {
                Self {
                    val: o.val.map(|s| s.into(), PS::$pro_to_aff),
                }
            }
        }
        impl<E: PairingEngine, PS: PairingShare<E>> From<$w_aff<E, PS>> for $w_pro<E, PS> {
            fn from(o: $w_aff<E, PS>) -> Self {
                Self {
                    val: o.val.map(|s| s.into(), PS::$aff_to_pro),
                }
            }
        }

        impl<E: PairingEngine, PS: PairingShare<E>> From<$w_aff<E, PS>> for $w_prep<E, PS> {
            fn from(_o: $w_aff<E, PS>) -> Self {
                unimplemented!("Prepared curves")
            }
        }

        impl<E: PairingEngine, PS: PairingShare<E>> ToBytes for $w_prep<E, PS> {
            fn write<W: Write>(&self, _writer: W) -> io::Result<()> {
                unimplemented!("Prepared curves")
            }
        }

        impl<E: PairingEngine, PS: PairingShare<E>> AffineCurve for $w_aff<E, PS> {
            type ScalarField = MpcField<E::Fr, PS::FrShare>;
            const COFACTOR: &'static [u64] = E::$aff::COFACTOR;
            type BaseField = $w_base<E::$base, PS::$base_share>;
            type Projective = $w_pro<E, PS>;
            fn prime_subgroup_generator() -> Self {
                Self::from_public(E::$aff::prime_subgroup_generator())
            }
            fn from_random_bytes(_: &[u8]) -> Option<Self> {
                todo!("AffineCurve::from_random_bytes")
            }
            fn mul<S: Into<<Self::ScalarField as PrimeField>::BigInt>>(
                &self,
                s: S,
            ) -> <Self as AffineCurve>::Projective {
                let bigint = s.into();
                let mut scalar = Self::ScalarField::from_repr(bigint).unwrap();
                scalar.set_shared(true);
                (Self {
                    val: self.val * scalar,
                })
                .into()
            }
            fn mul_by_cofactor_to_projective(&self) -> <Self as AffineCurve>::Projective {
                todo!("AffineCurve::mul_by_cofactor_to_projective")
            }
            fn mul_by_cofactor_inv(&self) -> Self {
                todo!("AffineCurve::mul_by_cofactor_inv")
            }
            fn multi_scalar_mul(bases: &[Self], scalars: &[Self::ScalarField]) -> Self::Projective {
                assert!(bases.iter().all(|b| !b.is_shared()));
                let bigint_scalars = cfg_into_iter!(scalars)
                    .map(|s| {
                        if s.is_shared() || channel::am_first() {
                            s.into_repr()
                        } else {
                            Self::ScalarField::from(0u64).into_repr()
                        }
                    })
                    .collect::<Vec<_>>();
                let mut product = VariableBaseMSM::multi_scalar_mul(&bases, &bigint_scalars);
                // This is shared because the big intergers are representations of a shared value.
                product.cast_to_shared();
                product
            }
        }
        impl<E: PairingEngine, PS: PairingShare<E>> ProjectiveCurve for $w_pro<E, PS> {
            type ScalarField = MpcField<E::Fr, PS::FrShare>;
            const COFACTOR: &'static [u64] = E::$aff::COFACTOR;
            type BaseField = $w_base<E::$base, PS::$base_share>;
            type Affine = $w_aff<E, PS>;
            fn prime_subgroup_generator() -> Self {
                Self::from_public(E::$pro::prime_subgroup_generator())
            }
            fn batch_normalization(_elems: &mut [Self]) {
                //TODO: wrong?
                // elems
                //     .iter_mut()
                //     .for_each(|e| E::$pro::batch_normalization(&mut [e.val]));
                todo!("ProjectiveCurve::batch_normalization")
            }
            fn is_normalized(&self) -> bool {
                todo!("ProjectiveCurve::is_normalized")
            }
            fn double_in_place(&mut self) -> &mut Self {
                self.val.double_in_place();
                self
            }
            fn add_assign_mixed(&mut self, o: &<Self as ProjectiveCurve>::Affine) {
                let o: Self = o.clone().into();
                *self += o;
            }
            fn mul<S: AsRef<[u64]>>(self, scalar_words: S) -> Self {
                // Cast s to bigint..
                let mut scalar = <Self::ScalarField as PrimeField>::BigInt::from(0u64);
                scalar.as_mut().copy_from_slice(scalar_words.as_ref());
                let mut scalar = Self::ScalarField::from_repr(scalar).unwrap();
                scalar.cast_to_shared();
                Self {
                    val: self.val * scalar,
                }
            }
        }
    };
}

impl_aff_proj!(
    MpcG1Prep,
    G1Prepared,
    MpcG1Affine,
    MpcG1Projective,
    G1Affine,
    G1Projective,
    g1_share_proj_to_aff,
    g1_share_aff_to_proj,
    MpcField,
    Fq,
    FqShare
);
impl_aff_proj!(
    MpcG2Prep,
    G2Prepared,
    MpcG2Affine,
    MpcG2Projective,
    G2Affine,
    G2Projective,
    g2_share_proj_to_aff,
    g2_share_aff_to_proj,
    MpcExtField,
    Fqe,
    FqeShare
);
