use ark_bls12_377::Bls12_377;
use ark_ec::msm::VariableBaseMSM;
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{FftField, Field, LegendreSymbol, One, PrimeField, SquareRootField, Zero};
use ark_serialize::*;
use ark_std::{cfg_into_iter, UniformRand};
use log::{debug, warn};
use rand::prelude::*;
use sha2::Digest;
use std::borrow::Cow;
use std::ops::*;

pub mod channel;
pub mod poly;
pub mod silly;

// const N_PARTIES: u32 = 2;

#[derive(Clone, Copy, Default, Hash, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct MpcVal<T> {
    val: T,
    shared: bool,
}

/// An MPC value who's group structure is multiplication
#[derive(Clone, Copy, Default, Hash, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct MpcMulVal<T> {
    val: T,
    shared: bool,
}

#[derive(Clone, Copy, Default, Hash, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct MpcCurve<T> {
    val: T,
    shared: bool,
}

#[derive(Clone, Copy, Default, Hash, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct MpcCurve2<T> {
    val: T,
    shared: bool,
}

#[derive(Clone, Copy, Default, Hash, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct MpcPrepCurve<T> {
    val: T,
    shared: bool,
}

#[derive(Clone, Copy, Default, Hash, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct MpcPrepCurve2<T> {
    val: T,
    shared: bool,
}

macro_rules! impl_basics {
    ($ty:ident) => {
        impl<F: std::fmt::Display> std::fmt::Display for $ty<F> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.val)?;
                if self.shared {
                    write!(f, " (shared)")
                } else {
                    write!(f, " (public)")
                }
            }
        }

        impl<T> $ty<T> {
            pub fn new(val: T, shared: bool) -> Self {
                Self { val, shared }
            }
            pub fn from_public(val: T) -> Self {
                Self::new(val, false)
            }
            pub fn from_shared(val: T) -> Self {
                Self::new(val, true)
            }
        }

        impl<F: zeroize::Zeroize> zeroize::Zeroize for $ty<F> {
            fn zeroize(&mut self) {
                self.val.zeroize();
            }
        }

        impl<F: AddAssign<F>> AddAssign<$ty<F>> for $ty<F> {
            fn add_assign(&mut self, other: $ty<F>) {
                match (self.shared, other.shared) {
                    (true, false) => {
                        if channel::am_first() {
                            self.val.add_assign(other.val);
                        } else {
                        }
                    }
                    (false, true) => {
                        if channel::am_first() {
                            self.val.add_assign(other.val);
                        } else {
                            self.val = other.val;
                        }
                    }
                    _ => {
                        self.val.add_assign(other.val);
                    }
                }
                self.shared = self.shared || other.shared;
            }
        }

        impl<F: Add<F, Output = F>> Add<$ty<F>> for $ty<F> {
            type Output = $ty<F>;
            fn add(self, other: $ty<F>) -> Self::Output {
                Self::new(
                    if self.shared == other.shared || channel::am_first() {
                        self.val.add(other.val)
                    } else if other.shared {
                        other.val
                    } else {
                        self.val
                    },
                    self.shared || other.shared,
                )
            }
        }

        impl<'a, F: AddAssign<&'a F> + Clone> AddAssign<&'a $ty<F>> for $ty<F> {
            fn add_assign(&mut self, other: &'a $ty<F>) {
                match (self.shared, other.shared) {
                    (true, false) => {
                        if channel::am_first() {
                            self.val.add_assign(&other.val);
                        } else {
                        }
                    }
                    (false, true) => {
                        if channel::am_first() {
                            self.val.add_assign(&other.val);
                        } else {
                            self.val = other.val.clone();
                        }
                    }
                    _ => {
                        self.val.add_assign(&other.val);
                    }
                }
                self.shared = self.shared || other.shared;
            }
        }

        impl<'a, F: Add<&'a F, Output = F> + Clone> Add<&'a $ty<F>> for $ty<F> {
            type Output = $ty<F>;
            fn add(self, other: &'a $ty<F>) -> Self::Output {
                Self::new(
                    if self.shared == other.shared || channel::am_first() {
                        self.val.add(&other.val)
                    } else if other.shared {
                        other.val.clone()
                    } else {
                        self.val
                    },
                    self.shared || other.shared,
                )
            }
        }

        impl<F: SubAssign<F> + Neg<Output = F>> SubAssign<$ty<F>> for $ty<F> {
            fn sub_assign(&mut self, other: $ty<F>) {
                match (self.shared, other.shared) {
                    (true, false) => {
                        if channel::am_first() {
                            self.val.sub_assign(other.val);
                        } else {
                        }
                    }
                    (false, true) => {
                        if channel::am_first() {
                            self.val.sub_assign(other.val);
                        } else {
                            self.val = -other.val;
                        }
                    }
                    _ => {
                        self.val.sub_assign(other.val);
                    }
                }
                self.shared = self.shared || other.shared;
            }
        }

        impl<F: Sub<F, Output = F> + Neg<Output = F>> Sub<$ty<F>> for $ty<F> {
            type Output = $ty<F>;
            fn sub(self, other: $ty<F>) -> Self::Output {
                Self::new(
                    if self.shared == other.shared || channel::am_first() {
                        self.val.sub(other.val)
                    } else if other.shared {
                        -other.val
                    } else {
                        self.val
                    },
                    self.shared || other.shared,
                )
            }
        }

        impl<'a, F: SubAssign<&'a F> + Clone + Neg<Output = F>> SubAssign<&'a $ty<F>> for $ty<F> {
            fn sub_assign(&mut self, other: &'a $ty<F>) {
                match (self.shared, other.shared) {
                    (true, false) => {
                        if channel::am_first() {
                            self.val.sub_assign(&other.val);
                        } else {
                        }
                    }
                    (false, true) => {
                        if channel::am_first() {
                            self.val.sub_assign(&other.val);
                        } else {
                            self.val = -other.val.clone();
                        }
                    }
                    _ => {
                        self.val.sub_assign(&other.val);
                    }
                }
                self.shared = self.shared || other.shared;
            }
        }

        impl<'a, F: Sub<&'a F, Output = F> + Clone + Neg<Output = F>> Sub<&'a $ty<F>> for $ty<F> {
            type Output = $ty<F>;
            fn sub(self, other: &'a $ty<F>) -> Self::Output {
                Self::new(
                    if self.shared == other.shared || channel::am_first() {
                        self.val.sub(&other.val)
                    } else if other.shared {
                        -other.val.clone()
                    } else {
                        self.val
                    },
                    self.shared || other.shared,
                )
            }
        }
        impl<F: Neg<Output = F>> Neg for $ty<F> {
            type Output = $ty<F>;
            fn neg(mut self) -> Self::Output {
                self.val = self.val.neg();
                self
            }
        }

        impl<
                F: for<'a> AddAssign<&'a F>
                    + ark_serialize::CanonicalSerialize
                    + ark_serialize::CanonicalDeserialize
                    + Clone
                    + std::cmp::PartialEq,
            > ark_serialize::CanonicalSerialize for $ty<F>
        {
            fn serialize<W>(
                &self,
                w: W,
            ) -> std::result::Result<(), ark_serialize::SerializationError>
            where
                W: ark_serialize::Write,
            {
                self.publicize_cow().val.serialize(w)
            }
            fn serialized_size(&self) -> usize {
                self.val.serialized_size()
            }
        }
        impl<
                F: for<'a> AddAssign<&'a F>
                    + ark_serialize::CanonicalSerialize
                    + ark_serialize::CanonicalDeserialize
                    + Clone,
            > ark_serialize::CanonicalDeserialize for $ty<F>
        {
            fn deserialize<R>(r: R) -> std::result::Result<Self, ark_serialize::SerializationError>
            where
                R: ark_serialize::Read,
            {
                F::deserialize(r).map($ty::from_public)
            }
        }
        impl<
                F: for<'a> AddAssign<&'a F>
                    + ark_serialize::CanonicalSerialize
                    + ark_serialize::CanonicalDeserializeWithFlags
                    + Clone,
            > ark_serialize::CanonicalDeserializeWithFlags for $ty<F>
        {
            fn deserialize_with_flags<R, Fl>(
                r: R,
            ) -> std::result::Result<(Self, Fl), ark_serialize::SerializationError>
            where
                R: ark_serialize::Read,
                Fl: Flags,
            {
                F::deserialize_with_flags(r).map(|(s, f)| ($ty::from_public(s), f))
            }
        }

        impl<
                F: for<'a> AddAssign<&'a F>
                    + ark_serialize::CanonicalSerializeWithFlags
                    + ark_serialize::CanonicalDeserialize
                    + Clone
                    + std::cmp::PartialEq,
            > ark_serialize::CanonicalSerializeWithFlags for $ty<F>
        {
            fn serialize_with_flags<W, Fl>(
                &self,
                w: W,
                f: Fl,
            ) -> std::result::Result<(), ark_serialize::SerializationError>
            where
                W: ark_serialize::Write,
                Fl: Flags,
            {
                self.publicize_cow().val.serialize_with_flags(w, f)
            }
            fn serialized_size_with_flags<Fl>(&self) -> usize
            where
                Fl: ark_serialize::Flags,
            {
                self.val.serialized_size_with_flags::<Fl>()
            }
        }

        impl<
                F: for<'a> AddAssign<&'a F>
                    + ark_serialize::CanonicalSerialize
                    + ark_serialize::CanonicalDeserialize
                    + Clone
                    + std::cmp::PartialEq,
            > MpcWire for $ty<F>
        {
            //            type Base = F;
            fn publicize(&mut self) {
                if self.shared {
                    let other_val = channel::exchange(self.val.clone());
                    self.val += &other_val;
                    self.shared = false;
                }
                debug_assert!({
                    println!("Check publicize");
                    let other_val = channel::exchange(self.val.clone());
                    self.val == other_val
                })
            }
            //            fn publicize_unwrap(self) -> Self::Base {
            //                self.publicize().val
            //            }
            fn is_shared(&self) -> bool {
                self.shared
            }
            fn set_shared(&mut self, shared: bool) {
                self.shared = shared;
            }
            fn publicize_cow<'b>(&'b self) -> Cow<'b, Self> {
                if self.shared {
                    let mut other_val = channel::exchange(self.val.clone());
                    other_val += &self.val;
                    Cow::Owned(Self::from_public(other_val))
                } else {
                    Cow::Borrowed(self)
                }
            }
        }

        impl<
                F: for<'a> AddAssign<&'a F>
                    + ark_serialize::CanonicalSerialize
                    + ark_serialize::CanonicalDeserialize
                    + Clone
                    + std::cmp::PartialEq,
            > $ty<F>
        {
            pub fn publicize_unwrap(mut self) -> F {
                self.publicize();
                self.val
            }
        }

        impl<F: ark_ff::FromBytes> ark_ff::FromBytes for $ty<F> {
            #[inline]
            fn read<R: ark_std::io::Read>(reader: R) -> ark_std::io::Result<Self> {
                F::read(reader).map(Self::from_public)
            }
        }

        impl<F: UniformRand> Distribution<$ty<F>> for rand::distributions::Standard {
            fn sample<R: ?Sized>(&self, r: &mut R) -> $ty<F>
            where
                R: Rng,
            {
                $ty {
                    val: F::rand(r),
                    shared: true,
                }
            }
        }

        impl<F: AsMut<[u64]>> AsMut<[u64]> for $ty<F> {
            fn as_mut(&mut self) -> &mut [u64] {
                self.val.as_mut()
            }
        }

        impl<F: AsRef<[u64]>> AsRef<[u64]> for $ty<F> {
            fn as_ref(&self) -> &[u64] {
                self.val.as_ref()
            }
        }

        impl<F: std::str::FromStr> std::str::FromStr for $ty<F> {
            type Err = F::Err;
            fn from_str(s: &str) -> Result<Self, F::Err> {
                F::from_str(s).map(Self::from_public)
            }
        }
    };
}

macro_rules! impl_to_bytes_pub {
    ($ty:ident) => {
        impl<
                F: for<'a> AddAssign<&'a F>
                    + ark_serialize::CanonicalSerialize
                    + ark_serialize::CanonicalDeserialize
                    + ark_ff::ToBytes
                    + Clone
                    + std::cmp::PartialEq,
            > ark_ff::ToBytes for $ty<F>
        {
            #[inline]
            fn write<W: ark_std::io::Write>(&self, writer: W) -> ark_std::io::Result<()> {
                self.publicize_cow().val.write(writer)
            }
        }
        impl<
                F: ark_ff::Zero
                    + ark_serialize::CanonicalSerialize
                    + ark_serialize::CanonicalDeserialize
                    + Clone,
            > ark_ff::Zero for $ty<F>
        {
            fn zero() -> Self {
                Self::from_public(F::zero())
            }
            fn is_zero(&self) -> bool {
                // TODO: avoid revealing?
                if self.shared {
                    //println!("Warning: zero check on shared data");
                    false
                    //let mut other_val = channel::exchange(self.val.clone());
                    //(other_val + self.val.clone()).is_zero()
                } else {
                    self.val.is_zero()
                }
                // if self.shared {
                //     warn!("is_zero on shared data: returning false without checking");
                //     false
                // } else {
                //     self.val.is_zero()
                // }
            }
        }

        impl<
                F: ark_ff::Zero
                    + Add
                    + ark_serialize::CanonicalSerialize
                    + ark_serialize::CanonicalDeserialize
                    + Clone,
            > ark_std::iter::Sum<$ty<F>> for $ty<F>
        {
            fn sum<I>(i: I) -> Self
            where
                I: Iterator<Item = $ty<F>>,
            {
                i.fold($ty::zero(), Add::add)
            }
        }
        impl<
                'a,
                F: 'a
                    + ark_ff::Zero
                    + Add<&'a F, Output = F>
                    + Clone
                    + ark_serialize::CanonicalSerialize
                    + ark_serialize::CanonicalDeserialize,
            > ark_std::iter::Sum<&'a $ty<F>> for $ty<F>
        {
            fn sum<I>(i: I) -> Self
            where
                I: Iterator<Item = &'a $ty<F>>,
            {
                i.fold($ty::zero(), Add::add)
            }
        }
    };
}
macro_rules! impl_to_bytes_abort_if_shared {
    ($ty:ident) => {
        impl<F: ark_ff::ToBytes> ark_ff::ToBytes for $ty<F> {
            #[inline]
            fn write<W: ark_std::io::Write>(&self, writer: W) -> ark_std::io::Result<()> {
                assert!(!self.shared);
                self.val.write(writer)
            }
        }
        impl<F: ark_ff::Zero> ark_ff::Zero for $ty<F> {
            fn zero() -> Self {
                Self::from_public(F::zero())
            }
            fn is_zero(&self) -> bool {
                // TODO: avoid revealing?
                if self.shared {
                    panic!("Cannot is_zero shared data")
                } else {
                    self.val.is_zero()
                }
            }
        }

        impl<F: ark_ff::Zero + Add> ark_std::iter::Sum<$ty<F>> for $ty<F> {
            fn sum<I>(i: I) -> Self
            where
                I: Iterator<Item = $ty<F>>,
            {
                i.fold($ty::zero(), Add::add)
            }
        }
        impl<'a, F: 'a + ark_ff::Zero + Add<&'a F, Output = F> + Clone>
            ark_std::iter::Sum<&'a $ty<F>> for $ty<F>
        {
            fn sum<I>(i: I) -> Self
            where
                I: Iterator<Item = &'a $ty<F>>,
            {
                i.fold($ty::zero(), Add::add)
            }
        }
    };
}

impl_basics!(MpcVal);
impl_basics!(MpcCurve);
impl_basics!(MpcCurve2);
impl_basics!(MpcPrepCurve);
impl_basics!(MpcPrepCurve2);
impl_to_bytes_pub!(MpcVal);
impl_to_bytes_pub!(MpcCurve);
impl_to_bytes_pub!(MpcCurve2);
impl_to_bytes_abort_if_shared!(MpcPrepCurve);
impl_to_bytes_abort_if_shared!(MpcPrepCurve2);

macro_rules! impl_mult_basics {
    ($ty:ident) => {
        impl<F: std::fmt::Display> std::fmt::Display for $ty<F> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.val)?;
                if self.shared {
                    write!(f, " (shared)")
                } else {
                    write!(f, " (public)")
                }
            }
        }

        impl<T> $ty<T> {
            pub fn new(val: T, shared: bool) -> Self {
                Self { val, shared }
            }
            pub fn from_public(val: T) -> Self {
                Self::new(val, false)
            }
            pub fn from_shared(val: T) -> Self {
                Self::new(val, true)
            }
        }

        impl<F: zeroize::Zeroize> zeroize::Zeroize for $ty<F> {
            fn zeroize(&mut self) {
                self.val.zeroize();
            }
        }

        impl<F: ark_ff::ToBytes> ark_ff::ToBytes for $ty<F> {
            #[inline]
            fn write<W: ark_std::io::Write>(&self, writer: W) -> ark_std::io::Result<()> {
                assert!(!self.shared);
                self.val.write(writer)
            }
        }

        impl<F: AddAssign<F>> AddAssign<$ty<F>> for $ty<F> {
            fn add_assign(&mut self, other: $ty<F>) {
                assert!(
                    !self.shared && !other.shared,
                    "Cannot add shared Fq* elements"
                );
                self.val.add_assign(other.val);
            }
        }

        impl<F: Add<F, Output = F>> Add<$ty<F>> for $ty<F> {
            type Output = $ty<F>;
            fn add(self, other: $ty<F>) -> Self::Output {
                assert!(
                    !self.shared && !other.shared,
                    "Cannot add shared Fq* elements"
                );
                Self::from_public(self.val.add(other.val))
            }
        }

        impl<'a, F: AddAssign<&'a F> + Clone> AddAssign<&'a $ty<F>> for $ty<F> {
            fn add_assign(&mut self, other: &'a $ty<F>) {
                assert!(
                    !self.shared && !other.shared,
                    "Cannot add shared Fq* elements"
                );
                self.val.add_assign(&other.val);
            }
        }

        impl<'a, F: Add<&'a F, Output = F> + Clone> Add<&'a $ty<F>> for $ty<F> {
            type Output = $ty<F>;
            fn add(self, other: &'a $ty<F>) -> Self::Output {
                assert!(
                    !self.shared && !other.shared,
                    "Cannot add shared Fq* elements"
                );
                Self::from_public(self.val.add(&other.val))
            }
        }

        impl<F: SubAssign<F> + Neg<Output = F>> SubAssign<$ty<F>> for $ty<F> {
            fn sub_assign(&mut self, other: $ty<F>) {
                assert!(
                    !self.shared && !other.shared,
                    "Cannot sub shared Fq* elements"
                );
                self.val.sub_assign(other.val);
            }
        }

        impl<F: Sub<F, Output = F> + Neg<Output = F>> Sub<$ty<F>> for $ty<F> {
            type Output = $ty<F>;
            fn sub(self, other: $ty<F>) -> Self::Output {
                assert!(
                    !self.shared && !other.shared,
                    "Cannot sub shared Fq* elements"
                );
                Self::from_public(self.val.sub(other.val))
            }
        }

        impl<'a, F: SubAssign<&'a F> + Clone + Neg<Output = F>> SubAssign<&'a $ty<F>> for $ty<F> {
            fn sub_assign(&mut self, other: &'a $ty<F>) {
                assert!(
                    !self.shared && !other.shared,
                    "Cannot sub shared Fq* elements"
                );
                self.val.sub_assign(&other.val);
            }
        }

        impl<'a, F: Sub<&'a F, Output = F> + Clone + Neg<Output = F>> Sub<&'a $ty<F>> for $ty<F> {
            type Output = $ty<F>;
            fn sub(self, other: &'a $ty<F>) -> Self::Output {
                assert!(
                    !self.shared && !other.shared,
                    "Cannot sub shared Fq* elements"
                );
                Self::from_public(self.val.sub(&other.val))
            }
        }
        impl<F: Neg<Output = F>> Neg for $ty<F> {
            type Output = $ty<F>;
            fn neg(mut self) -> Self::Output {
                if self.shared && channel::am_first() {
                    self.val = self.val.neg();
                }
                self
            }
        }
        impl<
                F: for<'a> MulAssign<&'a F>
                    + ark_serialize::CanonicalSerialize
                    + ark_serialize::CanonicalDeserialize
                    + Clone
                    + std::cmp::PartialEq,
            > ark_serialize::CanonicalSerialize for $ty<F>
        {
            fn serialize<W>(
                &self,
                w: W,
            ) -> std::result::Result<(), ark_serialize::SerializationError>
            where
                W: ark_serialize::Write,
            {
                self.publicize_cow().val.serialize(w)
            }
            fn serialized_size(&self) -> usize {
                self.val.serialized_size()
            }
        }
        impl<
                F: for<'a> MulAssign<&'a F>
                    + ark_serialize::CanonicalSerialize
                    + ark_serialize::CanonicalDeserialize
                    + Clone,
            > ark_serialize::CanonicalDeserialize for $ty<F>
        {
            fn deserialize<R>(r: R) -> std::result::Result<Self, ark_serialize::SerializationError>
            where
                R: ark_serialize::Read,
            {
                F::deserialize(r).map($ty::from_public)
            }
        }
        impl<
                F: for<'a> MulAssign<&'a F>
                    + ark_serialize::CanonicalSerialize
                    + ark_serialize::CanonicalDeserializeWithFlags
                    + Clone,
            > ark_serialize::CanonicalDeserializeWithFlags for $ty<F>
        {
            fn deserialize_with_flags<R, Fl>(
                r: R,
            ) -> std::result::Result<(Self, Fl), ark_serialize::SerializationError>
            where
                R: ark_serialize::Read,
                Fl: Flags,
            {
                F::deserialize_with_flags(r).map(|(s, f)| ($ty::from_public(s), f))
            }
        }

        impl<
                F: for<'a> MulAssign<&'a F>
                    + ark_serialize::CanonicalSerializeWithFlags
                    + ark_serialize::CanonicalDeserialize
                    + Clone
                    + std::cmp::PartialEq,
            > ark_serialize::CanonicalSerializeWithFlags for $ty<F>
        {
            fn serialize_with_flags<W, Fl>(
                &self,
                w: W,
                f: Fl,
            ) -> std::result::Result<(), ark_serialize::SerializationError>
            where
                W: ark_serialize::Write,
                Fl: Flags,
            {
                self.publicize_cow().val.serialize_with_flags(w, f)
            }
            fn serialized_size_with_flags<Fl>(&self) -> usize
            where
                Fl: ark_serialize::Flags,
            {
                self.val.serialized_size_with_flags::<Fl>()
            }
        }
        //        impl<F: std::fmt::Display> std::fmt::Display for $ty<F> {
        //            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        //                write!(f, "{}", self.val)?;
        //                if self.shared {
        //                    write!(f, " (shared)")
        //                } else {
        //                    write!(f, " (public)")
        //                }
        //            }
        //        }
        //
        //        impl<T> $ty<T> {
        //            pub fn new(val: T, shared: bool) -> Self {
        //                Self { val, shared }
        //            }
        //            pub fn from_public(val: T) -> Self {
        //                Self::new(val, false)
        //            }
        //            pub fn from_shared(val: T) -> Self {
        //                Self::new(val, true)
        //            }
        //        }
        //
        //        impl<F: zeroize::Zeroize> zeroize::Zeroize for $ty<F> {
        //            fn zeroize(&mut self) {
        //                self.val.zeroize();
        //            }
        //        }
        //
        //        impl<F: ark_ff::ToBytes> ark_ff::ToBytes for $ty<F> {
        //            #[inline]
        //            fn write<W: ark_std::io::Write>(&self, writer: W) -> ark_std::io::Result<()> {
        //                assert!(!self.shared);
        //                self.val.write(writer)
        //            }
        //        }
        //
        //        impl<F: MulAssign<F>> AddAssign<$ty<F>> for $ty<F> {
        //            fn add_assign(&mut self, other: $ty<F>) {
        //                match (self.shared, other.shared) {
        //                    (true, false) => {
        //                        if channel::am_first() {
        //                            self.val.mul_assign(other.val);
        //                        } else {
        //                        }
        //                    }
        //                    (false, true) => {
        //                        if channel::am_first() {
        //                            self.val.mul_assign(other.val);
        //                        } else {
        //                            self.val = other.val;
        //                        }
        //                    }
        //                    _ => {
        //                        self.val.mul_assign(other.val);
        //                    }
        //                }
        //                self.shared = self.shared || other.shared;
        //            }
        //        }
        //
        //        impl<F: Mul<F, Output = F>> Add<$ty<F>> for $ty<F> {
        //            type Output = $ty<F>;
        //            fn add(self, other: $ty<F>) -> Self::Output {
        //                Self::new(
        //                    if self.shared == other.shared || channel::am_first() {
        //                        self.val.mul(other.val)
        //                    } else if other.shared {
        //                        other.val
        //                    } else {
        //                        self.val
        //                    },
        //                    self.shared || other.shared,
        //                )
        //            }
        //        }
        //
        //        impl<'a, F: MulAssign<&'a F> + Clone> AddAssign<&'a $ty<F>> for $ty<F> {
        //            fn add_assign(&mut self, other: &'a $ty<F>) {
        //                match (self.shared, other.shared) {
        //                    (true, false) => {
        //                        if channel::am_first() {
        //                            self.val.mul_assign(&other.val);
        //                        } else {
        //                        }
        //                    }
        //                    (false, true) => {
        //                        if channel::am_first() {
        //                            self.val.mul_assign(&other.val);
        //                        } else {
        //                            self.val = other.val.clone();
        //                        }
        //                    }
        //                    _ => {
        //                        self.val.mul_assign(&other.val);
        //                    }
        //                }
        //                self.shared = self.shared || other.shared;
        //            }
        //        }
        //
        //        impl<'a, F: Mul<&'a F, Output = F> + Clone> Add<&'a $ty<F>> for $ty<F> {
        //            type Output = $ty<F>;
        //            fn add(self, other: &'a $ty<F>) -> Self::Output {
        //                Self::new(
        //                    if self.shared == other.shared || channel::am_first() {
        //                        self.val.mul(&other.val)
        //                    } else if other.shared {
        //                        other.val.clone()
        //                    } else {
        //                        self.val
        //                    },
        //                    self.shared || other.shared,
        //                )
        //            }
        //        }
        //
        //        impl<F: Field> SubAssign<$ty<F>> for $ty<F> {
        //            fn sub_assign(&mut self, other: $ty<F>) {
        //                match (self.shared, other.shared) {
        //                    (true, false) => {
        //                        if channel::am_first() {
        //                            self.val.div_assign(other.val);
        //                        } else {
        //                        }
        //                    }
        //                    (false, true) => {
        //                        if channel::am_first() {
        //                            self.val.div_assign(other.val);
        //                        } else {
        //                            self.val.inverse_in_place().unwrap();
        //                        }
        //                    }
        //                    _ => {
        //                        self.val.div_assign(other.val);
        //                    }
        //                }
        //                self.shared = self.shared || other.shared;
        //            }
        //        }
        //
        //        impl<F: Field> Sub<$ty<F>> for $ty<F> {
        //            type Output = $ty<F>;
        //            fn sub(self, other: $ty<F>) -> Self::Output {
        //                Self::new(
        //                    if self.shared == other.shared || channel::am_first() {
        //                        self.val.div(other.val)
        //                    } else if other.shared {
        //                        other.val.inverse().unwrap()
        //                    } else {
        //                        self.val
        //                    },
        //                    self.shared || other.shared,
        //                )
        //            }
        //        }
        //
        //        impl<'a, F: Field> SubAssign<&'a $ty<F>> for $ty<F> {
        //            fn sub_assign(&mut self, other: &'a $ty<F>) {
        //                match (self.shared, other.shared) {
        //                    (true, false) => {
        //                        if channel::am_first() {
        //                            self.val.div_assign(&other.val);
        //                        } else {
        //                        }
        //                    }
        //                    (false, true) => {
        //                        if channel::am_first() {
        //                            self.val.div_assign(&other.val);
        //                        } else {
        //                            self.val.inverse_in_place().unwrap();
        //                        }
        //                    }
        //                    _ => {
        //                        self.val.sub_assign(&other.val);
        //                    }
        //                }
        //                self.shared = self.shared || other.shared;
        //            }
        //        }
        //
        //        impl<'a, F: Field> Sub<&'a $ty<F>> for $ty<F> {
        //            type Output = $ty<F>;
        //            fn sub(self, other: &'a $ty<F>) -> Self::Output {
        //                Self::new(
        //                    if self.shared == other.shared || channel::am_first() {
        //                        self.val.div(&other.val)
        //                    } else if other.shared {
        //                        other.val.inverse().unwrap()
        //                    } else {
        //                        self.val
        //                    },
        //                    self.shared || other.shared,
        //                )
        //            }
        //        }
        //        impl<F: Field> Neg for $ty<F> {
        //            type Output = $ty<F>;
        //            fn neg(mut self) -> Self::Output {
        //                self.val.inverse_in_place().unwrap();
        //                self
        //            }
        //        }
        //        impl<
        //                F: for<'a> MulAssign<&'a F>
        //                    + ark_serialize::CanonicalSerialize
        //                    + ark_serialize::CanonicalDeserialize
        //                    + Clone,
        //            > ark_serialize::CanonicalSerialize for $ty<F>
        //        {
        //            fn serialize<W>(&self, w: W) -> std::result::Result<(), ark_serialize::SerializationError>
        //            where
        //                W: ark_serialize::Write,
        //            {
        //                self.publicize_cow().val.serialize(w)
        //            }
        //            fn serialized_size(&self) -> usize {
        //                self.val.serialized_size()
        //            }
        //        }
        //        impl<
        //                F: for<'a> MulAssign<&'a F>
        //                    + ark_serialize::CanonicalSerialize
        //                    + ark_serialize::CanonicalDeserialize
        //                    + Clone,
        //            > ark_serialize::CanonicalDeserialize for $ty<F>
        //        {
        //            fn deserialize<R>(r: R) -> std::result::Result<Self, ark_serialize::SerializationError>
        //            where
        //                R: ark_serialize::Read,
        //            {
        //                F::deserialize(r).map($ty::from_public)
        //            }
        //        }
        //        impl<
        //                F: for<'a> MulAssign<&'a F>
        //                    + ark_serialize::CanonicalSerialize
        //                    + ark_serialize::CanonicalDeserializeWithFlags
        //                    + Clone,
        //            > ark_serialize::CanonicalDeserializeWithFlags for $ty<F>
        //        {
        //            fn deserialize_with_flags<R, Fl>(
        //                r: R,
        //            ) -> std::result::Result<(Self, Fl), ark_serialize::SerializationError>
        //            where
        //                R: ark_serialize::Read,
        //                Fl: Flags,
        //            {
        //                F::deserialize_with_flags(r).map(|(s, f)| ($ty::from_public(s), f))
        //            }
        //        }
        //
        //        impl<
        //                F: for<'a> MulAssign<&'a F>
        //                    + ark_serialize::CanonicalSerializeWithFlags
        //                    + ark_serialize::CanonicalDeserialize
        //                    + Clone,
        //            > ark_serialize::CanonicalSerializeWithFlags for $ty<F>
        //        {
        //            fn serialize_with_flags<W, Fl>(
        //                &self,
        //                w: W,
        //                f: Fl,
        //            ) -> std::result::Result<(), ark_serialize::SerializationError>
        //            where
        //                W: ark_serialize::Write,
        //                Fl: Flags,
        //            {
        //                self.publicize_cow().val.serialize_with_flags(w, f)
        //            }
        //            fn serialized_size_with_flags<Fl>(&self) -> usize
        //            where
        //                Fl: ark_serialize::Flags,
        //            {
        //                self.val.serialized_size_with_flags::<Fl>()
        //            }
        //        }

        impl<
                F: for<'a> MulAssign<&'a F>
                    + ark_serialize::CanonicalSerialize
                    + ark_serialize::CanonicalDeserialize
                    + Clone
                    + std::cmp::PartialEq,
            > MpcWire for $ty<F>
        {
            //type Base = F;
            fn publicize(&mut self) {
                if self.shared {
                    let other_val = channel::exchange(self.val.clone());
                    self.val *= &other_val;
                    self.shared = false;
                }
                debug_assert!({
                    println!("Check publicize");
                    let other_val = channel::exchange(self.val.clone());
                    self.val == other_val
                })
            }
            fn is_shared(&self) -> bool {
                self.shared
            }
            fn set_shared(&mut self, shared: bool) {
                self.shared = shared;
            }
            fn publicize_cow<'b>(&'b self) -> Cow<'b, Self> {
                if self.shared {
                    let mut other_val = channel::exchange(self.val.clone());
                    other_val *= &self.val;
                    Cow::Owned(Self::from_public(other_val))
                } else {
                    Cow::Borrowed(self)
                }
            }
        }

        impl<
                F: for<'a> MulAssign<&'a F>
                    + ark_serialize::CanonicalSerialize
                    + ark_serialize::CanonicalDeserialize
                    + Clone
                    + std::cmp::PartialEq,
            > $ty<F>
        {
            pub fn publicize_unwrap(mut self) -> F {
                self.publicize();
                self.val
            }
        }

        impl<F: ark_ff::FromBytes> ark_ff::FromBytes for $ty<F> {
            #[inline]
            fn read<R: ark_std::io::Read>(reader: R) -> ark_std::io::Result<Self> {
                F::read(reader).map(Self::from_public)
            }
        }

        impl<F: UniformRand> Distribution<$ty<F>> for rand::distributions::Standard {
            fn sample<R: ?Sized>(&self, r: &mut R) -> $ty<F>
            where
                R: Rng,
            {
                $ty {
                    val: F::rand(r),
                    // TODO: Good for FRI, bad in general?
                    shared: false,
                }
            }
        }

        impl<F: AsMut<[u64]>> AsMut<[u64]> for $ty<F> {
            fn as_mut(&mut self) -> &mut [u64] {
                self.val.as_mut()
            }
        }

        impl<F: AsRef<[u64]>> AsRef<[u64]> for $ty<F> {
            fn as_ref(&self) -> &[u64] {
                self.val.as_ref()
            }
        }

        impl<F: std::str::FromStr> std::str::FromStr for $ty<F> {
            type Err = F::Err;
            fn from_str(s: &str) -> Result<Self, F::Err> {
                F::from_str(s).map(Self::from_public)
            }
        }

        impl<F: ark_ff::Zero> ark_ff::Zero for $ty<F> {
            fn zero() -> Self {
                Self::from_public(F::zero())
            }
            fn is_zero(&self) -> bool {
                if self.shared {
                    warn!("is_zero on shared data: returning false without checking");
                    false
                } else {
                    self.val.is_zero()
                }
            }
        }

        impl<F: ark_ff::Zero + Add> ark_std::iter::Sum<$ty<F>> for $ty<F> {
            fn sum<I>(i: I) -> Self
            where
                I: Iterator<Item = $ty<F>>,
            {
                i.fold($ty::zero(), Add::add)
            }
        }
        impl<'a, F: 'a + ark_ff::Zero + Add<&'a F, Output = F> + Clone>
            ark_std::iter::Sum<&'a $ty<F>> for $ty<F>
        {
            fn sum<I>(i: I) -> Self
            where
                I: Iterator<Item = &'a $ty<F>>,
            {
                i.fold($ty::zero(), Add::add)
            }
        }
        //impl<F: ark_ff::One + PartialEq> ark_ff::Zero for $ty<F> {
        //    fn zero() -> Self {
        //        Self::from_public(F::one())
        //    }
        //    fn is_zero(&self) -> bool {
        //        assert!(!self.shared);
        //        self.val.is_one()
        //    }
        //}

        //impl<F: ark_ff::One + Mul + PartialEq> ark_std::iter::Sum<$ty<F>> for $ty<F> {
        //    fn sum<I>(i: I) -> Self
        //    where
        //        I: Iterator<Item = $ty<F>>,
        //    {
        //        i.fold($ty::zero(), Add::add)
        //    }
        //}
        //impl<'a, F: 'a + ark_ff::One + Mul<&'a F, Output = F> + Clone + PartialEq> ark_std::iter::Sum<&'a $ty<F>>
        //    for $ty<F>
        //{
        //    fn sum<I>(i: I) -> Self
        //    where
        //        I: Iterator<Item = &'a $ty<F>>,
        //    {
        //        i.fold($ty::zero(), Add::add)
        //    }
        //}
    };
}

impl_mult_basics!(MpcMulVal);

macro_rules! wrap_conv {
    ($f:ident, $t:ident) => {
        impl<T> std::convert::From<$f<T>> for $t<T> {
            fn from(f: $f<T>) -> Self {
                Self {
                    val: f.val,
                    shared: f.shared,
                }
            }
        }
    };
}

wrap_conv!(MpcCurve, MpcCurve2);
wrap_conv!(MpcCurve2, MpcCurve);
wrap_conv!(MpcVal, MpcCurve);
wrap_conv!(MpcCurve, MpcVal);
wrap_conv!(MpcVal, MpcCurve2);
wrap_conv!(MpcCurve2, MpcVal);
wrap_conv!(MpcVal, MpcMulVal);
wrap_conv!(MpcMulVal, MpcVal);

// macro_rules! add_op {
//    ($T:ty,$L:ty,$R:ty,$O:ty,$f:ident) => {
//        impl<F: Field> $T<$R<F>> for $L<F> {
//            type Output = $O;
//
//            fn add(self, other: $R<R>) -> Self::Output {
//                Self {
//                    shared: self.shared || other.shared,
//                    val: match (self.shared, other.shared) {
//                        (true, true) => self.val.$f(other.val),
//                        (true, false) => self.val.$f(other.val /
// F::from(N_PARTIES)),                        (false, true) => (self.val /
// F::from(N_PARTIES)).$f(other.val),                        (false, false) =>
// self.val.$f(other.val),                    },
//                }
//            }
//        }
//    }
//}
// add_op!(Sub,MpcVal,MpcVal,MpcVal,sub);

macro_rules! wrap_mul {
    ($wrap:ident) => {
        impl<F: Field> MulAssign<$wrap<F>> for $wrap<F> {
            fn mul_assign(&mut self, other: $wrap<F>) {
                match (self.shared, other.shared) {
                    (true, true) => {
                        *self = channel::field_mul((*self).into(), other.into()).into();
                    }
                    _ => self.val.mul_assign(other.val),
                };
                self.shared = self.shared || other.shared;
            }
        }

        impl<F: Field> Mul<$wrap<F>> for $wrap<F> {
            type Output = $wrap<F>;
            fn mul(self, other: $wrap<F>) -> Self::Output {
                Self::Output::new(
                    match (self.shared, other.shared) {
                        (true, true) => channel::field_mul(self.into(), other.into()).val,
                        _ => self.val.mul(other.val),
                    },
                    self.shared || other.shared,
                )
            }
        }

        impl<'a, F: Field> MulAssign<&'a $wrap<F>> for $wrap<F> {
            fn mul_assign(&mut self, other: &'a $wrap<F>) {
                match (self.shared, other.shared) {
                    (true, true) => {
                        *self = channel::field_mul((*self).into(), (*other).into()).into();
                    }
                    _ => self.val.mul_assign(&other.val),
                };
                self.shared = self.shared || other.shared;
            }
        }
        impl<'a, F: Field> Mul<&'a $wrap<F>> for $wrap<F> {
            type Output = $wrap<F>;
            fn mul(self, other: &'a $wrap<F>) -> Self::Output {
                Self::Output::new(
                    match (self.shared, other.shared) {
                        (true, true) => channel::field_mul(self.into(), (*other).into()).val,
                        _ => self.val.mul(&other.val),
                    },
                    self.shared || other.shared,
                )
            }
        }
        impl<F: Field> DivAssign<$wrap<F>> for $wrap<F> {
            fn div_assign(&mut self, other: $wrap<F>) {
                match (self.shared, other.shared) {
                    (true, true) => {
                        *self = channel::field_div((*self).into(), other.into()).into();
                    }
                    _ => self.val.div_assign(other.val),
                };
                self.shared = self.shared || other.shared;
            }
        }
        impl<F: Field> Div<$wrap<F>> for $wrap<F> {
            type Output = $wrap<F>;
            fn div(mut self, other: $wrap<F>) -> Self::Output {
                self.div_assign(other);
                self
            }
        }
        impl<'a, F: Field> DivAssign<&'a $wrap<F>> for $wrap<F> {
            fn div_assign(&mut self, other: &'a $wrap<F>) {
                match (self.shared, other.shared) {
                    (true, true) => {
                        self.val = channel::field_div((*self).into(), (*other).into()).val
                    }
                    _ => self.val.div_assign(&other.val),
                };
                self.shared = self.shared || other.shared;
            }
        }
        impl<'a, F: Field> Div<&'a $wrap<F>> for $wrap<F> {
            type Output = $wrap<F>;
            fn div(mut self, other: &'a $wrap<F>) -> Self::Output {
                self.div_assign(other);
                self
            }
        }

        impl<F: Field> ark_ff::One for $wrap<F> {
            fn one() -> Self {
                Self::from_public(F::one())
            }
        }

        impl<F: Field> ark_std::iter::Product<$wrap<F>> for $wrap<F> {
            fn product<I>(i: I) -> Self
            where
                I: Iterator<Item = $wrap<F>>,
            {
                i.fold($wrap::one(), Mul::mul)
            }
        }
        impl<'a, F: 'a + Field> ark_std::iter::Product<&'a $wrap<F>> for $wrap<F> {
            fn product<I>(i: I) -> Self
            where
                I: Iterator<Item = &'a $wrap<F>>,
            {
                i.fold($wrap::one(), Mul::mul)
            }
        }
    };
}

macro_rules! wrap_lin_mul {
    ($wrap:ident) => {
        impl<F: Field> MulAssign<$wrap<F>> for $wrap<F> {
            fn mul_assign(&mut self, other: $wrap<F>) {
                match (self.shared, other.shared) {
                    (true, false) => {
                        if channel::am_first() {
                            self.val.mul_assign(other.val);
                        } else {
                        }
                    }
                    (false, true) => {
                        if channel::am_first() {
                            self.val.mul_assign(other.val);
                        } else {
                            self.val = other.val;
                        }
                    }
                    _ => {
                        self.val.mul_assign(other.val);
                    }
                }
                self.shared = self.shared || other.shared;
            }
        }

        impl<F: Field> Mul<$wrap<F>> for $wrap<F> {
            type Output = $wrap<F>;
            fn mul(self, other: $wrap<F>) -> Self::Output {
                Self::new(
                    if self.shared == other.shared || channel::am_first() {
                        self.val.mul(other.val)
                    } else if other.shared {
                        other.val
                    } else {
                        self.val
                    },
                    self.shared || other.shared,
                )
            }
        }

        impl<'a, F: Field> MulAssign<&'a $wrap<F>> for $wrap<F> {
            fn mul_assign(&mut self, other: &'a $wrap<F>) {
                match (self.shared, other.shared) {
                    (true, false) => {
                        if channel::am_first() {
                            self.val.mul_assign(&other.val);
                        } else {
                        }
                    }
                    (false, true) => {
                        if channel::am_first() {
                            self.val.mul_assign(&other.val);
                        } else {
                            self.val = other.val;
                        }
                    }
                    _ => {
                        self.val.mul_assign(&other.val);
                    }
                }
                self.shared = self.shared || other.shared;
            }
        }
        impl<'a, F: Field> Mul<&'a $wrap<F>> for $wrap<F> {
            type Output = $wrap<F>;
            fn mul(self, other: &'a $wrap<F>) -> Self::Output {
                Self::new(
                    if self.shared == other.shared || channel::am_first() {
                        self.val.mul(&other.val)
                    } else if other.shared {
                        other.val
                    } else {
                        self.val
                    },
                    self.shared || other.shared,
                )
            }
        }
        impl<F: Field> DivAssign<$wrap<F>> for $wrap<F> {
            fn div_assign(&mut self, other: $wrap<F>) {
                match (self.shared, other.shared) {
                    (true, false) => {
                        if channel::am_first() {
                            self.val.div_assign(other.val);
                        } else {
                        }
                    }
                    (false, true) => {
                        if channel::am_first() {
                            self.val.div_assign(other.val);
                        } else {
                            self.val = other.val.inverse().unwrap();
                        }
                    }
                    _ => {
                        self.val.div_assign(other.val);
                    }
                }
                self.shared = self.shared || other.shared;
            }
        }
        impl<F: Field> Div<$wrap<F>> for $wrap<F> {
            type Output = $wrap<F>;
            fn div(mut self, other: $wrap<F>) -> Self::Output {
                self.div_assign(other);
                self
            }
        }
        impl<'a, F: Field> DivAssign<&'a $wrap<F>> for $wrap<F> {
            fn div_assign(&mut self, other: &'a $wrap<F>) {
                match (self.shared, other.shared) {
                    (true, false) => {
                        if channel::am_first() {
                            self.val.div_assign(other.val);
                        } else {
                        }
                    }
                    (false, true) => {
                        if channel::am_first() {
                            self.val.div_assign(other.val);
                        } else {
                            self.val = other.val.inverse().unwrap();
                        }
                    }
                    _ => {
                        self.val.div_assign(other.val);
                    }
                }
                self.shared = self.shared || other.shared;
            }
        }
        impl<'a, F: Field> Div<&'a $wrap<F>> for $wrap<F> {
            type Output = $wrap<F>;
            fn div(mut self, other: &'a $wrap<F>) -> Self::Output {
                self.div_assign(other);
                self
            }
        }

        impl<F: Field> ark_ff::One for $wrap<F> {
            fn one() -> Self {
                Self::from_public(F::one())
            }
        }

        impl<F: Field> ark_std::iter::Product<$wrap<F>> for $wrap<F> {
            fn product<I>(i: I) -> Self
            where
                I: Iterator<Item = $wrap<F>>,
            {
                i.fold($wrap::one(), Mul::mul)
            }
        }
        impl<'a, F: 'a + Field> ark_std::iter::Product<&'a $wrap<F>> for $wrap<F> {
            fn product<I>(i: I) -> Self
            where
                I: Iterator<Item = &'a $wrap<F>>,
            {
                i.fold($wrap::one(), Mul::mul)
            }
        }
    };
}

wrap_mul!(MpcVal);
wrap_lin_mul!(MpcMulVal);

impl<G: ProjectiveCurve> MulAssign<MpcVal<G::ScalarField>> for MpcCurve<G> {
    fn mul_assign(&mut self, other: MpcVal<G::ScalarField>) {
        *self = channel::curve_mul((*self).into(), other).into();
    }
}

impl<G: ProjectiveCurve> MulAssign<MpcVal<G::ScalarField>> for MpcCurve2<G> {
    fn mul_assign(&mut self, other: MpcVal<G::ScalarField>) {
        *self = channel::curve_mul((*self).into(), other.into()).into();
    }
}
//impl<F: ark_serialize::ConstantSerializedSize> ark_serialize::ConstantSerializedSize for MpcVal<F> {
//    const SERIALIZED_SIZE: usize = F::SERIALIZED_SIZE;
//    const UNCOMPRESSED_SIZE: usize = F::UNCOMPRESSED_SIZE;
//}

macro_rules! from_prim {
    ($t:ty, $wrap:ident) => {
        impl<F: std::convert::From<$t>> std::convert::From<$t> for $wrap<F> {
            fn from(t: $t) -> Self {
                Self::from_public(F::from(t))
            }
        }
    };
}

from_prim!(bool, MpcVal);
from_prim!(u8, MpcVal);
from_prim!(u16, MpcVal);
from_prim!(u32, MpcVal);
from_prim!(u64, MpcVal);
from_prim!(u128, MpcVal);
from_prim!(bool, MpcMulVal);
from_prim!(u8, MpcMulVal);
from_prim!(u16, MpcMulVal);
from_prim!(u32, MpcMulVal);
from_prim!(u64, MpcMulVal);
from_prim!(u128, MpcMulVal);

macro_rules! shared_field {
    ($Pf:ty,$PrimeField:ty) => {
        impl Field for MpcVal<$Pf> {
            type BasePrimeField = MpcVal<$PrimeField>;
            fn extension_degree() -> u64 {
                todo!()
            }
            fn from_base_prime_field_elems(b: &[<Self as Field>::BasePrimeField]) -> Option<Self> {
                assert!(b.len() > 0);
                let shared = b[0].shared;
                assert!(b.iter().all(|e| e.shared == shared));
                let base_values = b.iter().map(|e| e.val.clone()).collect::<Vec<_>>();
                <$Pf as Field>::from_base_prime_field_elems(&base_values)
                    .map(|val| Self { val, shared })
            }
            fn double(&self) -> Self {
                Self {
                    val: self.val.double(),
                    shared: self.shared,
                }
            }
            fn double_in_place(&mut self) -> &mut Self {
                self.val.double_in_place();
                self
            }
            fn from_random_bytes_with_flags<F: Flags>(b: &[u8]) -> Option<(Self, F)> {
                <$Pf>::from_random_bytes_with_flags(b).map(|(val, f)| (Self::from_shared(val), f))
            }
            fn square(&self) -> Self {
                if self.shared {
                    channel::field_mul(self.clone(), self.clone())
                } else {
                    Self::new(self.val.square(), self.shared)
                }
            }
            fn square_in_place(&mut self) -> &mut Self {
                if self.shared {
                    *self = channel::field_mul(self.clone(), *self);
                } else {
                    self.val.square_in_place();
                }
                self
            }
            fn inverse(&self) -> Option<Self> {
                if self.shared {
                    //TODO: incomplete
                    Some(channel::field_inv(self.clone()))
                } else {
                    self.val.inverse().map(Self::from_public)
                }
            }
            fn inverse_in_place(&mut self) -> Option<&mut Self> {
                if self.shared {
                    *self = channel::field_inv(self.clone());
                    Some(self)
                } else {
                    if self.val.inverse_in_place().is_some() {
                        Some(self)
                    } else {
                        None
                    }
                }
            }
            fn frobenius_map(&mut self, _: usize) {
                todo!()
            }
            fn batch_product_in_place(selfs: &mut [Self], others: &[Self]) {
                selfs.copy_from_slice(&channel::field_batch_mul(
                    selfs.to_owned(),
                    others.to_owned(),
                ));
            }
        }
    };
}

macro_rules! shared_mul_field {
    ($Pf:ty,$PrimeField:ty) => {
        impl Field for MpcMulVal<$Pf> {
            type BasePrimeField = MpcVal<$PrimeField>;
            fn extension_degree() -> u64 {
                todo!()
            }
            fn from_base_prime_field_elems(b: &[<Self as Field>::BasePrimeField]) -> Option<Self> {
                assert!(b.len() > 0);
                let shared = b[0].shared;
                assert!(b.iter().all(|e| e.shared == shared));
                let base_values = b.iter().map(|e| e.val.clone()).collect::<Vec<_>>();
                <$Pf as Field>::from_base_prime_field_elems(&base_values)
                    .map(|val| Self { val, shared })
            }
            fn double(&self) -> Self {
                Self {
                    val: self.val.square(),
                    shared: self.shared,
                }
            }
            fn double_in_place(&mut self) -> &mut Self {
                self.val.double_in_place();
                self
            }
            fn from_random_bytes_with_flags<F: Flags>(b: &[u8]) -> Option<(Self, F)> {
                <$Pf>::from_random_bytes_with_flags(b).map(|(val, f)| (Self::from_shared(val), f))
            }
            fn square(&self) -> Self {
                if self.shared {
                    unimplemented!("mul field square")
                } else {
                    Self::new(self.val.square(), self.shared)
                }
            }
            fn square_in_place(&mut self) -> &mut Self {
                if self.shared {
                    unimplemented!("mul field square in place")
                } else {
                    self.val.square_in_place();
                    self
                }
            }
            fn inverse(&self) -> Option<Self> {
                if self.shared {
                    unimplemented!("mul field inv")
                } else {
                    self.val.inverse().map(Self::from_public)
                }
            }
            fn inverse_in_place(&mut self) -> Option<&mut Self> {
                if self.shared {
                    unimplemented!("mul field inv in place")
                } else {
                    if self.val.inverse_in_place().is_some() {
                        Some(self)
                    } else {
                        None
                    }
                }
            }
            fn frobenius_map(&mut self, _: usize) {
                todo!()
            }
        }
    };
}

macro_rules! shared_prime_field {
    ($Pf:ty, $Repr:ty) => {
        impl FftField for MpcVal<$Pf> {
            type FftParams = <$Pf as FftField>::FftParams;
            fn two_adic_root_of_unity() -> Self {
                Self::from_public(<$Pf as FftField>::two_adic_root_of_unity())
            }
            fn large_subgroup_root_of_unity() -> Option<Self> {
                <$Pf as FftField>::large_subgroup_root_of_unity().map(Self::from_public)
            }
            fn multiplicative_generator() -> Self {
                Self::from_public(<$Pf as FftField>::multiplicative_generator())
            }
        }

        impl PrimeField for MpcVal<$Pf> {
            type Params = <$Pf as PrimeField>::Params;
            // type BigInt = MpcVal<F::BigInt>;
            type BigInt = <$Pf as PrimeField>::BigInt;
            // We're assuming that from_repr is linear
            fn from_repr(r: <Self as PrimeField>::BigInt) -> Option<Self> {
                // F::from_repr(r.val).map(|v| MpcVal::new(v, r.shared))
                <$Pf>::from_repr(r).map(|v| MpcVal::from_public(v))
            }
            // We're assuming that into_repr is linear
            fn into_repr(&self) -> <Self as PrimeField>::BigInt {
                // MpcVal::new(self.val.into_repr(), self.shared)
                self.val.into_repr()
            }
        }

        impl From<$Repr> for MpcVal<$Pf> {
            /// Converts `Self::BigInteger` into `Self`
            ///
            /// # Panics
            /// This method panics if `int` is larger than `P::MODULUS`.
            fn from(int: $Repr) -> Self {
                Self::from_repr(int).unwrap()
            }
        }

        impl From<MpcVal<$Pf>> for $Repr {
            /// Converts `Self::BigInteger` into `Self`
            ///
            /// # Panics
            /// This method panics if `int` is larger than `P::MODULUS`.
            fn from(int: MpcVal<$Pf>) -> Self {
                int.into_repr()
            }
        }
    };
}
macro_rules! shared_sqrt_field {
    ($Pf:ty) => {
        impl SquareRootField for MpcVal<$Pf> {
            fn legendre(&self) -> LegendreSymbol {
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

shared_field!(ark_bls12_377::Fr, ark_bls12_377::Fr);
shared_prime_field!(ark_bls12_377::Fr, ark_ff::BigInteger256);
shared_sqrt_field!(ark_bls12_377::Fr);

shared_field!(ark_bls12_377::Fq, ark_bls12_377::Fq);
shared_prime_field!(ark_bls12_377::Fq, ark_ff::BigInteger384);
shared_sqrt_field!(ark_bls12_377::Fq);

shared_field!(ark_bls12_377::Fq2, ark_bls12_377::Fq);
shared_sqrt_field!(ark_bls12_377::Fq2);

shared_field!(ark_bls12_377::Fq12, ark_bls12_377::Fq);
shared_mul_field!(ark_bls12_377::Fq12, ark_bls12_377::Fq);

macro_rules! curve_impl {
    ($curve:path, $curve_proj:path, $base:path, $scalar:path, $cofactor:path, $curve_wrapper:ident) => {
        impl AffineCurve for $curve_wrapper<$curve> {
            type ScalarField = MpcVal<$scalar>;
            const COFACTOR: &'static [u64] = $cofactor;
            type BaseField = MpcVal<$base>;
            type Projective = $curve_wrapper<$curve_proj>;
            fn prime_subgroup_generator() -> Self {
                Self::from_public(<$curve as AffineCurve>::prime_subgroup_generator())
            }
            fn from_random_bytes(_: &[u8]) -> Option<Self> {
                todo!("AffineCurve::from_random_bytes")
            }
            fn mul<S: Into<<Self::ScalarField as PrimeField>::BigInt>>(
                &self,
                s: S,
            ) -> <Self as AffineCurve>::Projective {
                if self.shared {
                    // Cast s to bigint..
                    let bigint = s.into();
                    let mut scalar = Self::ScalarField::from_repr(bigint).unwrap();
                    let proj: Self::Projective = self.clone().into();
                    scalar.cast_to_shared();
                    channel::curve_mul(proj.into(), scalar).into()
                } else {
                    let s = s.into();
                    $curve_wrapper::from_shared(self.val.mul(s))
                }
            }
            fn mul_by_cofactor_to_projective(&self) -> <Self as AffineCurve>::Projective {
                todo!("AffineCurve::mul_by_cofactor_to_projective")
            }
            fn mul_by_cofactor_inv(&self) -> Self {
                todo!("AffineCurve::mul_by_cofactor_inv")
            }
            fn multi_scalar_mul(bases: &[Self], scalars: &[Self::ScalarField]) -> Self::Projective {
                assert!(bases.iter().all(|b| !b.shared));
                let bigint_scalars = cfg_into_iter!(scalars)
                    .map(|s| {
                        if s.shared || channel::am_first() {
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
        impl From<$curve_wrapper<$curve_proj>> for $curve_wrapper<$curve> {
            fn from(p: $curve_wrapper<$curve_proj>) -> Self {
                Self::new(p.val.into(), p.shared)
            }
        }
        impl From<$curve_wrapper<$curve>> for $curve_wrapper<$curve_proj> {
            fn from(p: $curve_wrapper<$curve>) -> Self {
                Self::new(p.val.into(), p.shared)
            }
        }
        impl ProjectiveCurve for $curve_wrapper<$curve_proj> {
            const COFACTOR: &'static [u64] = $cofactor;
            type ScalarField = MpcVal<$scalar>;
            type BaseField = MpcVal<$base>;
            type Affine = $curve_wrapper<$curve>;
            fn prime_subgroup_generator() -> Self {
                Self::from_public(<$curve_proj as ProjectiveCurve>::prime_subgroup_generator())
            }
            fn batch_normalization(elems: &mut [Self]) {
                //TODO: wrong?
                elems
                    .iter_mut()
                    .for_each(|e| <$curve_proj>::batch_normalization(&mut [e.val]));
                //todo!("ProjectiveCurve::batch_normalization")
            }
            fn is_normalized(&self) -> bool {
                todo!("ProjectiveCurve::is_normalized")
            }
            fn double_in_place(&mut self) -> &mut Self {
                <$curve_proj as ProjectiveCurve>::double_in_place(&mut self.val);
                self
            }
            fn add_assign_mixed(&mut self, o: &<Self as ProjectiveCurve>::Affine) {
                debug!(
                    "ProjectiveCurve::add_assign_mixed({}, {})",
                    self.shared, o.shared
                );
                match (self.shared, o.shared) {
                    (true, true) | (false, false) => {
                        self.val.add_assign_mixed(&o.val);
                    }
                    (true, false) => {
                        if channel::am_first() {
                            self.val.add_assign_mixed(&o.val);
                        } else {
                        }
                    }
                    (false, true) => {
                        self.val = o.val.into();
                    }
                }
                self.shared = self.shared || o.shared;
            }
            fn mul<S: AsRef<[u64]>>(self, scalar_words: S) -> Self {
                if self.shared {
                    // Cast s to bigint..
                    let mut scalar = <Self::ScalarField as PrimeField>::BigInt::from(0u64);
                    scalar.as_mut().copy_from_slice(scalar_words.as_ref());
                    let mut scalar = Self::ScalarField::from_repr(scalar).unwrap();
                    scalar.cast_to_shared();
                    channel::curve_mul(self.into(), scalar).into()
                } else {
                    $curve_wrapper::from_shared(self.val.mul(scalar_words))
                }
            }
        }
    };
}

// macro_rules! group_impl {
//     ($gp:path, $scalar:path) => {
//
//         impl Group for MpcCurve<$gp> {
//             type ScalarField = MpcVal<$scalar>;
//             fn double_in_place<'a> (&'a mut self) -> &'a mut Self {
//                 <$gp as Group>::double_in_place(&mut self.val);
//                 self
//             }
//             fn double(&self) -> Self {
//                 Self::new(
//                     self.val.double(),
//                     self.shared,
//                 )
//             }
//         }
//     }
// }

curve_impl!(
    ark_bls12_377::G1Affine,
    ark_bls12_377::G1Projective,
    ark_bls12_377::Fq,
    ark_bls12_377::Fr,
    ark_bls12_377::G1Affine::COFACTOR,
    MpcCurve
);
curve_impl!(
    ark_bls12_377::G2Affine,
    ark_bls12_377::G2Projective,
    ark_bls12_377::Fq2,
    ark_bls12_377::Fr,
    ark_bls12_377::G2Affine::COFACTOR,
    MpcCurve2
);
//group_impl!(ark_bls12_377::G1Projective, ark_bls12_377::Fr);

//    type ScalarField: PrimeField + SquareRootField + Into<<Self::ScalarField
// as PrimeField>::BigInt>;    type BaseField: Field;
//    type Projective: ProjectiveCurve<Affine = Self, ScalarField =
// Self::ScalarField, BaseField = Self::BaseField> + From<Self> + Into<Self> +
// MulAssign<Self::ScalarField>;
//
//    pub const COFACTOR: &'static [u64];
//
//    fn prime_subgroup_generator() -> Self;
//    fn from_random_bytes(bytes: &[u8]) -> Option<Self>;
//    fn mul<S: Into<<Self::ScalarField as PrimeField>::BigInt>>(
//        &self,
//        other: S
//    ) -> Self::Projective;
//    fn mul_by_cofactor_to_projective(&self) -> Self::Projective;
//    fn mul_by_cofactor_inv(&self) -> Self;
//
//    fn into_projective(&self) -> Self::Projective { ... }
//    fn mul_by_cofactor(&self) -> Self { ... }
//}

/// A wrapper for a pairing engine
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MpcPairingEngine<E: PairingEngine> {
    inner: E,
}

macro_rules! impl_prep {
    ($wrap:ident, $curve:path, $prep_wrap:ident, $prep_curve:path) => {
        impl std::convert::From<$wrap<$curve>> for $prep_wrap<$prep_curve> {
            fn from(f: $wrap<$curve>) -> Self {
                Self::new(f.val.into(), f.shared)
            }
        }
    };
}

type BlsG1Prep = <ark_bls12_377::Bls12_377 as PairingEngine>::G1Prepared;
impl_prep!(MpcCurve, ark_bls12_377::G1Affine, MpcPrepCurve, BlsG1Prep);
type BlsG2Prep = <ark_bls12_377::Bls12_377 as PairingEngine>::G2Prepared;
impl_prep!(MpcCurve2, ark_bls12_377::G2Affine, MpcPrepCurve2, BlsG2Prep);

impl PairingEngine for MpcPairingEngine<Bls12_377> {
    type Fr = MpcVal<<Bls12_377 as PairingEngine>::Fr>;
    type G1Projective = MpcCurve<<Bls12_377 as PairingEngine>::G1Projective>;
    type G1Affine = MpcCurve<<Bls12_377 as PairingEngine>::G1Affine>;
    type G1Prepared = MpcPrepCurve<<Bls12_377 as PairingEngine>::G1Prepared>;
    type G2Projective = MpcCurve2<<Bls12_377 as PairingEngine>::G2Projective>;
    type G2Affine = MpcCurve2<<Bls12_377 as PairingEngine>::G2Affine>;
    type G2Prepared = MpcPrepCurve2<<Bls12_377 as PairingEngine>::G2Prepared>;
    type Fq = MpcVal<<Bls12_377 as PairingEngine>::Fq>;
    type Fqe = MpcVal<<Bls12_377 as PairingEngine>::Fqe>;
    type Fqk = MpcMulVal<<Bls12_377 as PairingEngine>::Fqk>;

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
        let p: Self::G1Affine = p.into();
        let q: Self::G2Affine = q.into();
        let p_val: MpcVal<<Bls12_377 as PairingEngine>::G1Projective> =
            MpcVal::new(p.val.into(), p.shared);
        let q_val: MpcVal<<Bls12_377 as PairingEngine>::G2Projective> =
            MpcVal::new(q.val.into(), q.shared);
        channel::pairing::<Bls12_377>(p_val, q_val).into()
    }
}

// /// Vector-Commitable Field

use mpc_trait::MpcWire;

/// Vector-Commitable Field
pub trait ComField: FftField + MpcWire {
    type Commitment: ark_serialize::CanonicalSerialize;
    type Key;
    type OpeningProof: ark_serialize::CanonicalSerialize;
    fn public_rand<R: Rng>(r: &mut R) -> Self;
    fn commit(vs: &[Self]) -> (Self::Key, Self::Commitment);
    fn open_at(vs: &[Self], key: &Self::Key, i: usize) -> (Self, Self::OpeningProof);
    fn check_opening(c: &Self::Commitment, p: Self::OpeningProof, i: usize, v: Self) -> bool;
}

impl ComField for MpcVal<<Bls12_377 as PairingEngine>::Fr> {
    type Commitment = (Vec<u8>, Vec<u8>);
    type Key = Vec<Vec<Vec<u8>>>;
    type OpeningProof = (
        <Bls12_377 as PairingEngine>::Fr,
        <Bls12_377 as PairingEngine>::Fr,
        Vec<(Vec<u8>, Vec<u8>)>,
    );
    fn public_rand<R: Rng>(r: &mut R) -> Self {
        Self {
            val: <Bls12_377 as PairingEngine>::Fr::rand(r),
            shared: false,
        }
    }
    fn commit(vs: &[Self]) -> (Self::Key, Self::Commitment) {
        let mut tree = Vec::new();
        let mut hashes: Vec<Vec<u8>> = vs
            .into_iter()
            .enumerate()
            .map(|(i, v)| {
                let mut bytes_out = Vec::new();
                v.val.serialize(&mut bytes_out).unwrap();
                let o = sha2::Sha256::digest(&bytes_out[..]).as_slice().to_owned();
                debug!("Hash {} {}: {:?}", vs.len(), i, o);
                o
            })
            .collect();
        assert!(hashes.len().is_power_of_two());
        while hashes.len() > 1 {
            let n = hashes.len() / 2;
            let mut new = Vec::new();
            for i in 0..n {
                let mut h = sha2::Sha256::default();
                h.update(&hashes[2 * i]);
                h.update(&hashes[2 * i + 1]);
                new.push(h.finalize().as_slice().to_owned());
                debug!("Hash {} {}: {:?}", hashes.len() / 2, i, new[new.len() - 1]);
            }
            tree.push(std::mem::replace(&mut hashes, new));
        }
        let slf = hashes.pop().unwrap();
        let other = channel::exchange_bytes(slf.clone());
        if channel::am_first() {
            (tree, (other, slf))
        } else {
            (tree, (slf, other))
        }
    }
    fn open_at(inputs: &[Self], tree: &Self::Key, mut i: usize) -> (Self, Self::OpeningProof) {
        let self_f = inputs[i].val.clone();
        let other_f = channel::exchange(self_f.clone());
        let mut siblings = Vec::new();
        for level in 0..tree.len() {
            debug!("sib {}: {:?}", level, tree[level][i ^ 1]);
            siblings.push(tree[level][i ^ 1].clone());
            i /= 2;
        }
        assert_eq!(i / 2, 0);
        let other = siblings
            .clone()
            .into_iter()
            .map(|s| channel::exchange_bytes(s));
        let p = if channel::am_first() {
            siblings.into_iter().zip(other.into_iter()).collect()
        } else {
            other.into_iter().zip(siblings.into_iter()).collect()
        };
        (
            MpcVal::from_public(self_f + other_f),
            if channel::am_first() {
                (self_f, other_f, p)
            } else {
                (other_f, self_f, p)
            },
        )
    }
    fn check_opening(c: &Self::Commitment, p: Self::OpeningProof, i: usize, v: Self) -> bool {
        if p.0 + p.1 != v.val {
            return false;
        }
        let mut hash0 = Vec::new();
        p.0.serialize(&mut hash0).unwrap();
        hash0 = sha2::Sha256::digest(&hash0).as_slice().to_owned();
        let mut hash1 = Vec::new();
        p.1.serialize(&mut hash1).unwrap();
        hash1 = sha2::Sha256::digest(&hash1).as_slice().to_owned();
        debug!("Hash init0: {:?}", hash0);
        debug!("Hash init1: {:?}", hash1);
        debug!("i: {}", i);
        for (j, (sib0, sib1)) in p.2.into_iter().enumerate() {
            let mut h0 = sha2::Sha256::default();
            let mut h1 = sha2::Sha256::default();
            debug!("Sib0: {}: {:?}", j, sib0);
            debug!("Sib1: {}: {:?}", j, sib1);
            debug!("Hash first: {}: {}", j, (i >> j) & 1 == 0);
            if (i >> j) & 1 == 0 {
                h0.update(&hash0);
                h0.update(&sib0);
                h1.update(&hash1);
                h1.update(&sib1);
            } else {
                h0.update(&sib0);
                h0.update(&hash0);
                h1.update(&sib1);
                h1.update(&hash1);
            }
            hash0 = h0.finalize().as_slice().to_owned();
            hash1 = h1.finalize().as_slice().to_owned();
            debug!("Hash0: {}: {:?}", j, hash0);
            debug!("Hash1: {}: {:?}", j, hash1);
        }
        debug!("Comm0: {:?}", c.1);
        debug!("Comm1: {:?}", c.0);
        &(hash1, hash0) == c
    }
}

pub trait BatchProd: Field {
    fn batch_product(mut xs: Vec<Self>, ys: Vec<Self>) -> Vec<Self> {
        assert_eq!(xs.len(), ys.len());
        ark_std::cfg_iter_mut!(xs)
            .zip(ys)
            .for_each(|(a, b)| *a *= b);

        xs
    }
}
impl BatchProd for ark_bls12_377::Fr {}
impl BatchProd for MpcVal<ark_bls12_377::Fr> {
    fn batch_product(xs: Vec<Self>, ys: Vec<Self>) -> Vec<Self> {
        channel::field_batch_mul(xs, ys)
    }
}
//macro_rules! mpc_debug {
//    ($e:expr) => {
//        debug!("{}: {}", stringify!($e), ($e).clone().publicize())
//    }
//}
