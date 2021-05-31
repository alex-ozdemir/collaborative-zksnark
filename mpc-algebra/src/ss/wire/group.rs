use derivative::Derivative;
use log::debug;
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

use super::super::share::group::GroupShare;
use super::super::share::BeaverSource;
use super::field::MpcField;
use mpc_net;
use mpc_trait::Reveal;

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
    #[inline]
    fn triple(&mut self) -> (S, S::ScalarShare, S) {
        (
            S::from_add_shared(T::zero()),
            <S::ScalarShare as Reveal>::from_add_shared(if mpc_net::am_first() {T::ScalarField::one()} else {T::ScalarField::zero()}),
            S::from_add_shared(T::zero()),
        )
    }
    #[inline]
    fn inv_pair(&mut self) -> (S::ScalarShare, S::ScalarShare) {
        (
            <S::ScalarShare as Reveal>::from_add_shared(if mpc_net::am_first() {T::ScalarField::one()} else {T::ScalarField::zero()}),
            <S::ScalarShare as Reveal>::from_add_shared(if mpc_net::am_first() {T::ScalarField::one()} else {T::ScalarField::zero()}),
        )
    }
}

impl_ref_ops!(Add, AddAssign, add, add_assign, Group, GroupShare, MpcGroup);
impl_ref_ops!(Sub, SubAssign, sub, sub_assign, Group, GroupShare, MpcGroup);

impl<T: Group, S: GroupShare<T>> MpcWire for MpcGroup<T, S> {
    #[inline]
    fn publicize(&mut self) {
        match self {
            MpcGroup::Shared(s) => {
                *self = MpcGroup::Public(s.reveal());
            }
            _ => {}
        }
        debug_assert!({
            let self_val = if let MpcGroup::Public(s) = self {
                s.clone()
            } else {
                unreachable!()
            };
            super::macros::check_eq(self_val);
            true
        })
    }
    #[inline]
    fn set_shared(&mut self, shared: bool) {
        if shared != self.is_shared() {
            match self {
                Self::Shared(s) => {
                    let p = s.unwrap_as_public();
                    *self = Self::Public(p);
                }
                Self::Public(s) => {
                    *self = Self::Shared(S::wrap_as_shared(*s));
                }
            }
        }
    }
    #[inline]
    fn is_shared(&self) -> bool {
        match self {
            MpcGroup::Shared(_) => true,
            MpcGroup::Public(_) => false,
        }
    }
}

impl<T: Group, S: GroupShare<T>> Reveal for MpcGroup<T, S> {
    type Base = T;
    #[inline]
    fn reveal(self) -> Self::Base {
        let result = match self {
            Self::Shared(s) => s.reveal(),
            Self::Public(s) => s,
        };
        super::macros::check_eq(result.clone());
        result
    }
    #[inline]
    fn from_public(b: Self::Base) -> Self {
        Self::Public(b)
    }
    #[inline]
    fn from_add_shared(b: Self::Base) -> Self {
        Self::Shared(S::from_add_shared(b))
    }
}

impl<T: Group, S: GroupShare<T>> Mul<MpcField<T::ScalarField, S::ScalarShare>> for MpcGroup<T, S> {
    type Output = Self;
    #[inline]
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
    #[inline]
    fn mul(self, other: &MpcField<T::ScalarField, S::ScalarShare>) -> Self::Output {
        self.mul(other.clone())
    }
}
impl<T: Group, S: GroupShare<T>> MulAssign<MpcField<T::ScalarField, S::ScalarShare>>
    for MpcGroup<T, S>
{
    #[inline]
    fn mul_assign(&mut self, other: MpcField<T::ScalarField, S::ScalarShare>) {
        *self = self.clone().mul(other.clone());
    }
}
impl<'a, T: Group, S: GroupShare<T>> MulAssign<&'a MpcField<T::ScalarField, S::ScalarShare>>
    for MpcGroup<T, S>
{
    #[inline]
    fn mul_assign(&mut self, other: &MpcField<T::ScalarField, S::ScalarShare>) {
        *self = self.clone().mul(other.clone());
    }
}

impl<T: Group, S: GroupShare<T>> Group for MpcGroup<T, S> {
    type ScalarField = MpcField<T::ScalarField, S::ScalarShare>;
}
