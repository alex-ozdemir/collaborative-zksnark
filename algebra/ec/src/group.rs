use core::{
    fmt::{Debug, Display},
    hash::Hash,
    ops::{Add, AddAssign, MulAssign, Neg, Sub, SubAssign},
};
use num_traits::Zero;

use ark_ff::{
    bytes::{FromBytes, ToBytes},
    fields::PrimeField,
    UniformRand,
    PubUniformRand,
};
use ark_serialize::{
    CanonicalSerialize,
    CanonicalDeserialize,
};

pub trait Group:
    ToBytes
    + 'static
    + FromBytes
    + Copy
    + Clone
    + Debug
    + Display
    + Default
    + Send
    + Sync
    + Eq
    + Hash
    + Neg<Output = Self>
    + UniformRand
    + PubUniformRand
    + Zero
    + Add<Self, Output = Self>
    + Sub<Self, Output = Self>
    + AddAssign<Self>
    + SubAssign<Self>
    + MulAssign<<Self as Group>::ScalarField>
    + for<'a> Add<&'a Self, Output = Self>
    + for<'a> Sub<&'a Self, Output = Self>
    + for<'a> AddAssign<&'a Self>
    + for<'a> SubAssign<&'a Self>
    + core::iter::Sum<Self>
    + for<'a> core::iter::Sum<&'a Self>
    + mpc_trait::MpcWire
    + CanonicalSerialize
    + CanonicalDeserialize
{
    type ScalarField: PrimeField;
    // type ScalarField: PrimeField + Into<<Self::ScalarField as PrimeField>::BigInt>;

    /// Returns `self + self`.
    #[must_use]
    fn double(&self) -> Self {
        *self + self
    }

    /// Sets `self := self + self`.
    fn double_in_place(&mut self) -> &mut Self {
        *self += self.clone();
        self
    }

    #[must_use]
    fn mul<'a>(&self, other: &'a Self::ScalarField) -> Self {
        let mut copy = *self;
        copy *= *other;
        copy
    }
}
