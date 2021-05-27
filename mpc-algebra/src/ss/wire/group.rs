use derivative::Derivative;
use rand::Rng;
use zeroize::Zeroize;

use ark_ec::group::Group;
use ark_ff::bytes::{FromBytes, ToBytes};
use ark_ff::prelude::*;
use ark_serialize::{
    CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize,
    CanonicalSerializeWithFlags, Flags, SerializationError,
};
use mpc_trait::MpcWire;

use std::fmt::{self, Debug, Display, Formatter};
use std::io::{self, Read, Write};
use std::iter::Sum;
use std::marker::PhantomData;
use std::ops::*;

use crate::mpc::channel;
use super::super::share::field::ScalarShare;
use super::super::share::group::GroupShare;
use super::super::share::BeaverSource;
use super::field::MpcField;

#[derive(Clone, Copy, Hash, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum MpcGroup<G: Group, S: GroupShare<G>> {
    Public(G),
    Shared(S),
}

impl_basics_2!(GroupShare, Group, MpcGroup);

#[derive(Derivative)]
#[derivative(Default(bound = ""), Clone(bound = ""), Copy(bound = ""))]
pub struct DummyGroupTripleSource<T, S> {
    _scalar: PhantomData<T>,
    _share: PhantomData<S>,
}

impl<T: Group, S: GroupShare<T>> BeaverSource<S, S::ScalarShare, S>
    for DummyGroupTripleSource<T, S>
{
    fn triple(&mut self) -> (S, S::ScalarShare, S) {
        (
            S::from_public(T::zero()),
            <S::ScalarShare as ScalarShare<T::ScalarField>>::from_public(T::ScalarField::one()),
            S::from_public(T::zero()),
        )
    }
    fn inv_pair(&mut self) -> (S::ScalarShare, S::ScalarShare) {
        (
            <S::ScalarShare as ScalarShare<T::ScalarField>>::from_public(T::ScalarField::one()),
            <S::ScalarShare as ScalarShare<T::ScalarField>>::from_public(T::ScalarField::one()),
        )
    }
}

impl_ref_ops!(Add, AddAssign, add, add_assign, Group, GroupShare, MpcGroup);
impl_ref_ops!(Sub, SubAssign, sub, sub_assign, Group, GroupShare, MpcGroup);

impl<T: Group, S: GroupShare<T>> MpcWire for MpcGroup<T, S> {
    fn publicize(&mut self) {
        match self {
            MpcGroup::Shared(s) => {
                *self = MpcGroup::Public(s.open());
            }
            _ => {}
        }
        debug_assert!({
            println!("Check publicize");
            let self_val = if let MpcGroup::Public(s) = self {
                s.clone()
            } else {
                unreachable!()
            };
            let other_val = channel::exchange(self_val);
            self_val == other_val
        })
    }
    fn set_shared(&mut self, shared: bool) {
        match self {
            MpcGroup::Shared(s) => {
                if !shared {
                    *self = MpcGroup::Public(s.open());
                }
            }
            MpcGroup::Public(s) => {
                if shared {
                    *self = MpcGroup::Shared(S::from_public(*s));
                }
            }
        }
    }
    fn is_shared(&self) -> bool {
        match self {
            MpcGroup::Shared(_) => true,
            MpcGroup::Public(_) => false,
        }
    }
}

impl<T: Group, S: GroupShare<T>> MpcGroup<T, S> {
    pub fn open(mut self) -> T {
        self.publicize();
        if let Self::Public(s) = self {
            s
        } else {
            unreachable!()
        }
    }
}

impl<T: Group, S: GroupShare<T>> Mul<MpcField<T::ScalarField, S::ScalarShare>> for MpcGroup<T, S> {
    type Output = Self;
    fn mul(self, other: MpcField<T::ScalarField, S::ScalarShare>) -> Self::Output {
        match (self, other) {
            (MpcGroup::Public(x), MpcField::Public(y)) => MpcGroup::Public(x.mul(&y)),
            (MpcGroup::Public(x), MpcField::Shared(y)) => {
                MpcGroup::Shared(S::scale_pub_group(x, &y))
            }
            (MpcGroup::Shared(x), MpcField::Public(y)) => MpcGroup::Shared(x.scale_pub_scalar(&y)),
            (MpcGroup::Shared(x), MpcField::Shared(y)) => {
                MpcGroup::Shared(x.scale(y, &mut DummyGroupTripleSource::default()))
            }
        }
    }
}

impl<'a, T: Group, S: GroupShare<T>> Mul<&'a MpcField<T::ScalarField, S::ScalarShare>>
    for MpcGroup<T, S>
{
    type Output = Self;
    fn mul(self, other: &MpcField<T::ScalarField, S::ScalarShare>) -> Self::Output {
        self.mul(other.clone())
    }
}
impl<T: Group, S: GroupShare<T>> MulAssign<MpcField<T::ScalarField, S::ScalarShare>>
    for MpcGroup<T, S>
{
    fn mul_assign(&mut self, other: MpcField<T::ScalarField, S::ScalarShare>) {
        *self = self.clone().mul(other.clone());
    }
}
impl<'a, T: Group, S: GroupShare<T>> MulAssign<&'a MpcField<T::ScalarField, S::ScalarShare>>
    for MpcGroup<T, S>
{
    fn mul_assign(&mut self, other: &MpcField<T::ScalarField, S::ScalarShare>) {
        *self = self.clone().mul(other.clone());
    }
}

impl<T: Group, S: GroupShare<T>> Group for MpcGroup<T, S> {
    type ScalarField = MpcField<T::ScalarField, S::ScalarShare>;
}
