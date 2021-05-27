use ark_ff::bytes::{FromBytes, ToBytes};
use ark_ff::prelude::*;
use ark_serialize::{
    CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize,
    CanonicalSerializeWithFlags,
};
use core::ops::*;
use std::cmp::Ord;
use std::fmt::{Debug, Display};
use std::hash::Hash;

use super::BeaverSource;

pub trait ScalarShare<F: Field>:
    Clone
    + Copy
    + Display
    + Debug
    + Send
    + Sync
    + Eq
    + Hash
    + Ord
    + CanonicalSerialize
    + CanonicalDeserialize
    + CanonicalSerializeWithFlags
    + CanonicalDeserializeWithFlags
    + UniformRand
    + ToBytes
    + FromBytes
    + 'static
{
    fn open(&self) -> F;

    fn from_public(f: F) -> Self;

    fn unwrap_as_public(self) -> F;

    fn wrap_as_shared(g: F) -> Self;

    fn map_homo<FF: Field, SS: ScalarShare<FF>, Fun: Fn(F) -> FF>(self, f: Fun) -> SS {
        SS::wrap_as_shared(f(self.unwrap_as_public()))
    }

    fn batch_open(selfs: impl IntoIterator<Item = Self>) -> Vec<F> {
        selfs.into_iter().map(|s| s.open()).collect()
    }


    fn add(self, other: &Self) -> Self;

    fn scale(self, scalar: &F) -> Self;

    fn shift(self, other: &F) -> Self;

    fn sub(&self, other: Self) -> Self {
        other.neg().add(self)
    }

    fn neg(self) -> Self {
        self.scale(&-F::one())
    }

    fn mul<S: BeaverSource<Self, Self, Self>>(self, other: Self, source: &mut S) -> Self {
        let (x, y, z) = source.triple();
        let s = self;
        let o = other;
        // output: z - open(s + x)y - open(o + y)x + open(s + x)open(o + y)
        //         xy - sy - xy - ox - yx + so + sy + xo + xy
        //         so
        let sx = s.add(&x).open();
        let oy = o.add(&y).open();
        z.sub(y.scale(&sx)).sub(x.scale(&oy)).shift(&(sx * oy))
    }

    fn batch_mul<S: BeaverSource<Self, Self, Self>>(
        xs: Vec<Self>,
        ys: Vec<Self>,
        source: &mut S,
    ) -> Vec<Self> {
        let ss = xs;
        let os = ys;
        let (xs, ys, zs) = source.triples(ss.len());
        // output: z - open(s + x)y - open(o + y)x + open(s + x)open(o + y)
        //         xy - sy - xy - ox - yx + so + sy + xo + xy
        //         so
        let sxs = Self::batch_open(ss.into_iter().zip(xs.iter()).map(|(s, x)| s.add(x)));
        let oys = Self::batch_open(os.into_iter().zip(ys.iter()).map(|(o, y)| o.add(y)));
        zs.into_iter()
            .zip(ys.into_iter())
            .zip(xs.into_iter())
            .enumerate()
            .map(|(i, ((z, y), x))| {
                z.sub(y.scale(&sxs[i]))
                    .sub(x.scale(&oys[i]))
                    .shift(&(sxs[i] * oys[i]))
            })
            .collect()
    }

    fn inv<S: BeaverSource<Self, Self, Self>>(self, source: &mut S) -> Self {
        let (x, y) = source.inv_pair();
        let xa = x.mul(self, source).open().inverse().unwrap();
        y.scale(&xa)
    }

    fn batch_inv<S: BeaverSource<Self, Self, Self>>(xs: Vec<Self>, source: &mut S) -> Vec<Self> {
        let (bs, cs) = source.inv_pairs(xs.len());
        cs.into_iter()
            .zip(
                Self::batch_open(Self::batch_mul(xs, bs, source))
                    .into_iter()
                    .map(|i| i.inverse().unwrap()),
            )
            .map(|(c, i)| c.scale(&i))
            .collect()
    }

    fn div<S: BeaverSource<Self, Self, Self>>(self, other: Self, source: &mut S) -> Self {
        let o_inv = other.inv(source);
        self.mul(o_inv, source)
    }

    fn batch_div<S: BeaverSource<Self, Self, Self>>(
        xs: Vec<Self>,
        ys: Vec<Self>,
        source: &mut S,
    ) -> Vec<Self> {
        Self::batch_mul(xs, Self::batch_inv(ys, source), source)
    }
}

pub trait ExtFieldShare<F: Field>:
    Clone + Copy + Debug + 'static + Send + Sync + PartialEq + Eq
{
    type Base: ScalarShare<F::BasePrimeField>;
    type Ext: ScalarShare<F>;
}

