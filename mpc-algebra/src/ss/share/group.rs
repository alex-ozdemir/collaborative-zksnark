use ark_ec::group::Group;
use ark_ff::bytes::{FromBytes, ToBytes};
use ark_ff::prelude::*;
use ark_serialize::{
    CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize,
    CanonicalSerializeWithFlags,
};
use core::ops::*;
use std::fmt::{Debug, Display};
use std::hash::Hash;

use super::BeaverSource;
use mpc_trait::Reveal;
use super::field::ScalarShare;

/// Secret sharing scheme which support affine functions of secrets.
pub trait GroupShare<G: Group>:
    Clone
    + Copy
    + Display
    + Debug
    + Send
    + Sync
    + Eq
    + Hash
    + CanonicalSerialize
    + CanonicalDeserialize
    + CanonicalSerializeWithFlags
    + CanonicalDeserializeWithFlags
    + UniformRand
    + ToBytes
    + FromBytes
    + 'static
    + Reveal<Base = G>
{
    type ScalarShare: ScalarShare<G::ScalarField>;

    fn open(&self) -> G {
        <Self as Reveal>::reveal(*self)
    }

    fn unwrap_as_public(self) -> G;

    fn wrap_as_shared(g: G) -> Self;

    fn map_homo<G2: Group, S2: GroupShare<G2>, Fun: Fn(G) -> G2>(self, f: Fun) -> S2 {
        S2::wrap_as_shared(f(self.unwrap_as_public()))
    }

    fn batch_open(selfs: impl IntoIterator<Item = Self>) -> Vec<G> {
        selfs.into_iter().map(|s| s.open()).collect()
    }

    fn add(self, other: &Self) -> Self;

    fn sub(&self, other: Self) -> Self {
        other.neg().add(self)
    }
    fn neg(self) -> Self {
        self.scale_pub_scalar(&-<G::ScalarField as ark_ff::One>::one())
    }

    fn scale_pub_scalar(self, scalar: &G::ScalarField) -> Self;

    fn scale_pub_group(base: G, scalar: &Self::ScalarShare) -> Self;

    fn shift(self, other: &G) -> Self;

    fn scale<S: BeaverSource<Self, Self::ScalarShare, Self>>(
        self,
        other: Self::ScalarShare,
        source: &mut S,
    ) -> Self {
        let (x, y, z) = source.triple();
        let s = self;
        let o = other;
        // output: z - open(s + x)y - x*open(o + y) + open(s + x)open(o + y)
        //         xy - sy - xy - ox - yx + so + sy + xo + xy
        //         so
        let mut sx = s.add(&x).open();
        let oy = o.add(&y).open();
        let out = z
            .sub(Self::scale_pub_group(sx.clone(), &y))
            .sub(x.scale_pub_scalar(&oy));
        sx *= oy;
        let result = out.shift(&sx);
        #[cfg(debug_assertions)]
        {
            let a = s.reveal();
            let b = o.reveal();
            let mut acp = a.clone();
            acp *= b;
            let r = result.reveal();
            if acp != r {
                println!("Bad multiplication!.\n{}\n*\n{}\n=\n{}", a, b, r);
                panic!("Bad multiplication");
            }
        }
        result
    }
}

