use ark_ff::prelude::*;

use std::cmp::Ord;
use std::hash::Hash;

use crate::channel;
use mpc_net;

use super::{AdditiveScalarShare};
use crate::Reveal;

#[inline]
pub fn mac_share<F: Field>() -> F {
    if mpc_net::am_first() {
        F::one()
    } else {
        F::zero()
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct SpdzScalarShare<T> {
    sh: AdditiveScalarShare<T>,
    mac: AdditiveScalarShare<T>,
}

impl<F: Field> Reveal for SpdzScalarShare<F> {
    type Base = F;

    fn reveal(self) -> F {
        let other_val: F = channel::exchange(&self.sh.val);
        // _Pragmatic MPC_ 6.6.2
        let x: F = self.sh.val + other_val;
        let dx_t: F = mac_share::<F>() * x + self.mac.val;
        let other_dx_t: F = channel::atomic_exchange(&dx_t);
        let sum: F = dx_t + other_dx_t;
        assert!(sum.is_zero());
        x
    }
    fn from_public(_f: F) -> Self {
        todo!()
    }
    fn from_add_shared(_f: F) -> Self {
        todo!()
    }
}

// #[derive(Derivative)]
// #[derivative(
//     Default(bound = "T: Default"),
//     Clone(bound = "T: Clone"),
//     Copy(bound = "T: Copy"),
//     PartialEq(bound = "T: PartialEq"),
//     Eq(bound = "T: Eq"),
//     PartialOrd(bound = "T: PartialOrd"),
//     Ord(bound = "T: Ord"),
//     Hash(bound = "T: Hash")
// )]
// pub struct SpdzGroupShare<T, M> {
//     val: T,
//     _phants: PhantomData<M>,
// }
// 
// #[derive(Debug, Derivative)]
// #[derivative(
//     Default(bound = ""),
//     Clone(bound = ""),
//     Copy(bound = ""),
//     PartialEq(bound = "F: PartialEq"),
//     Eq(bound = "F: Eq"),
//     Hash(bound = "F: Hash")
// )]
// pub struct SpdzExtFieldShare<F: Field>(pub PhantomData<F>);
// 
// #[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
// pub struct MulScalarShare<T> {
//     val: T,
// }
