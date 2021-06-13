use ark_ec::group::Group;
use ark_ff::bytes::{FromBytes, ToBytes};
use ark_ff::prelude::*;
use ark_serialize::{
    CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize,
    CanonicalSerializeWithFlags,
};
use ark_std::{end_timer, start_timer};
use core::ops::*;
use std::fmt::{Debug, Display};
use std::hash::Hash;

use super::field::FieldShare;
use super::BeaverSource;
use crate::Reveal;

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
    type FieldShare: FieldShare<G::ScalarField>;

    fn open(&self) -> G {
        <Self as Reveal>::reveal(*self)
    }

    fn map_homo<G2: Group, S2: GroupShare<G2>, Fun: Fn(G) -> G2>(self, f: Fun) -> S2 {
        S2::from_add_shared(f(self.unwrap_as_public()))
    }

    fn batch_open(selfs: impl IntoIterator<Item = Self>) -> Vec<G> {
        selfs.into_iter().map(|s| s.open()).collect()
    }

    fn add(&mut self, other: &Self) -> &mut Self;

    fn sub(&mut self, other: &Self) -> &mut Self {
        let mut t = other.clone();
        t.neg();
        t.add(&self);
        *self = t;
        self
    }
    fn neg(&mut self) -> &mut Self {
        self.scale_pub_scalar(&-<G::ScalarField as ark_ff::One>::one())
    }

    fn scale_pub_scalar(&mut self, scalar: &G::ScalarField) -> &mut Self;

    fn scale_pub_group(base: G, scalar: &Self::FieldShare) -> Self;

    fn shift(&mut self, other: &G) -> &mut Self;

    fn scale<S: BeaverSource<Self, Self::FieldShare, Self>>(
        self,
        other: Self::FieldShare,
        source: &mut S,
    ) -> Self {
        let timer = start_timer!(|| "SS scalar multiplication");
        let (mut x, y, z) = source.triple();
        let s = self;
        let o = other;
        // output: z - open(s + x)y - x*open(o + y) + open(s + x)open(o + y)
        //         xy - sy - xy - ox - yx + so + sy + xo + xy
        //         so
        let mut sx = {
            let mut t = s;
            t.add(&x).open()
        };
        let oy = {
            let mut t = o;
            t.add(&y).open()
        };
        let mut out = z.clone();
        out.sub(&Self::scale_pub_group(sx.clone(), &y));
        out.sub(x.scale_pub_scalar(&oy));
        sx *= oy;
        out.shift(&sx);
        #[cfg(debug_assertions)]
        {
            let a = s.reveal();
            let b = o.reveal();
            let mut acp = a.clone();
            acp *= b;
            let r = out.reveal();
            if acp != r {
                println!("Bad multiplication!.\n{}\n*\n{}\n=\n{}", a, b, r);
                panic!("Bad multiplication");
            }
        }
        end_timer!(timer);
        out
    }

    /// Compute \sum_i (s_i * g_i)
    /// where the s_i are shared and the g_i are public.
    fn multi_scale_pub_group(bases: &[G], scalars: &[Self::FieldShare]) -> Self {
        bases
            .into_iter()
            .zip(scalars.into_iter())
            .map(|(g, s)| Self::scale_pub_group(g.clone(), &s))
            .fold(Self::from_public(G::zero()), |mut acc, n| {
                acc.add(&n);
                acc
            })
    }
}
