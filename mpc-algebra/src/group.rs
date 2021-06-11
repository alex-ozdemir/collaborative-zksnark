use ark_ec::group::Group;
use ark_ff::bytes::{FromBytes, ToBytes};
use ark_ff::prelude::*;
use ark_serialize::{
    CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize,
    CanonicalSerializeWithFlags, Flags, SerializationError,
};
use ark_std::io::{self, Read, Write};
use core::ops::*;
use rand::Rng;
use std::cmp::Ord;
use std::default::Default;
use std::fmt::{self, Debug, Display, Formatter};
use std::hash::Hash;
use std::iter::Sum;
use std::marker::PhantomData;
use zeroize::Zeroize;

use mpc_trait::MpcWire;

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct MulFieldGroup<F: Field, S: PrimeField> {
    val: F,
    _scalar: PhantomData<S>,
}

//impl_basics!(ExtFieldMulGroup, Field);
impl<T: Field, S: PrimeField> MulFieldGroup<T, S> {
    pub fn new(val: T) -> Self {
        Self {
            val,
            _scalar: PhantomData::default(),
        }
    }
}

impl<T: Field, S: PrimeField> Display for MulFieldGroup<T, S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{} (shared)", self.val)
    }
}
impl<T: Field, S: PrimeField> ToBytes for MulFieldGroup<T, S> {
    fn write<W: Write>(&self, _writer: W) -> io::Result<()> {
        unimplemented!("write")
    }
}
impl<T: Field, S: PrimeField> FromBytes for MulFieldGroup<T, S> {
    fn read<R: Read>(_reader: R) -> io::Result<Self> {
        unimplemented!("read")
    }
}
impl<T: Field, S: PrimeField> CanonicalSerialize for MulFieldGroup<T, S> {
    fn serialize<W: Write>(&self, _writer: W) -> Result<(), SerializationError> {
        unimplemented!("serialize")
    }
    fn serialized_size(&self) -> usize {
        unimplemented!("serialized_size")
    }
}
impl<T: Field, S: PrimeField> CanonicalSerializeWithFlags for MulFieldGroup<T, S> {
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
impl<T: Field, S: PrimeField> CanonicalDeserialize for MulFieldGroup<T, S> {
    fn deserialize<R: Read>(_reader: R) -> Result<Self, SerializationError> {
        unimplemented!("deserialize")
    }
}
impl<T: Field, S: PrimeField> CanonicalDeserializeWithFlags for MulFieldGroup<T, S> {
    fn deserialize_with_flags<R: Read, F: Flags>(
        _reader: R,
    ) -> Result<(Self, F), SerializationError> {
        unimplemented!("deserialize_with_flags")
    }
}
impl<T: Field, S: PrimeField> UniformRand for MulFieldGroup<T, S> {
    fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
        Self::new(<T as UniformRand>::rand(rng))
    }
}
impl<T: Field, S: PrimeField> PubUniformRand for MulFieldGroup<T, S> {
}

impl<T: Field, S: PrimeField> Add for MulFieldGroup<T, S> {
    type Output = Self;
    fn add(self, other: Self) -> Self::Output {
        Self::new(self.val * other.val)
    }
}
impl<T: Field, S: PrimeField> Sum for MulFieldGroup<T, S> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), Add::add)
    }
}
impl<'a, T: Field, S: PrimeField> Sum<&'a MulFieldGroup<T, S>> for MulFieldGroup<T, S> {
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), |x, y| x.add(y.clone()))
    }
}
impl<T: Field, S: PrimeField> Neg for MulFieldGroup<T, S> {
    type Output = Self;
    fn neg(self) -> Self::Output {
        Self::new(self.val.inverse().unwrap())
    }
}
impl<T: Field, S: PrimeField> Sub for MulFieldGroup<T, S> {
    type Output = Self;
    fn sub(self, other: Self) -> Self::Output {
        Self::new(self.val / other.val)
    }
}
impl<T: Field, S: PrimeField> Zero for MulFieldGroup<T, S> {
    fn zero() -> Self {
        Self::new(T::one())
    }
    fn is_zero(&self) -> bool {
        self.val.is_one()
    }
}
impl<T: Field, S: PrimeField> Zeroize for MulFieldGroup<T, S> {
    fn zeroize(&mut self) {
        *self = Self::zero();
    }
}
impl<T: Field, S: PrimeField> Default for MulFieldGroup<T, S> {
    fn default() -> Self {
        Self::zero()
    }
}
impl<T: Field, S: PrimeField> MulAssign<S> for MulFieldGroup<T, S> {
    fn mul_assign(&mut self, other: S) {
        self.val = self.val.pow(other.into_repr());
    }
}
impl<T: Field, S: PrimeField> MpcWire for MulFieldGroup<T, S> {
    // Not actually shared, so no-ops
}
macro_rules! impl_mul_ref_ops {
    ($op:ident, $assop:ident, $opfn:ident, $assopfn:ident, $bound:ident, $bound2:ident, $wrap:ident) => {
        impl<'a, T: $bound, S: $bound2> $op<&'a $wrap<T, S>> for $wrap<T, S> {
            type Output = Self;
            fn $opfn(self, other: &$wrap<T, S>) -> Self::Output {
                self.$opfn(other.clone())
            }
        }
        impl<T: $bound, S: $bound2> $assop<$wrap<T, S>> for $wrap<T, S> {
            fn $assopfn(&mut self, other: $wrap<T, S>) {
                *self = self.clone().$opfn(other.clone());
            }
        }
        impl<'a, T: $bound, S: $bound2> $assop<&'a $wrap<T, S>> for $wrap<T, S> {
            fn $assopfn(&mut self, other: &$wrap<T, S>) {
                *self = self.clone().$opfn(other.clone());
            }
        }
    };
}
impl_mul_ref_ops!(
    Add,
    AddAssign,
    add,
    add_assign,
    Field,
    PrimeField,
    MulFieldGroup
);
impl_mul_ref_ops!(
    Sub,
    SubAssign,
    sub,
    sub_assign,
    Field,
    PrimeField,
    MulFieldGroup
);

impl<T: Field, S: PrimeField> Group for MulFieldGroup<T, S> {
    type ScalarField = S;
}
