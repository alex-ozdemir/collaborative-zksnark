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
use mpc_trait::Reveal;

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
    + Reveal<Base = F>
{
    fn open(&self) -> F {
        <Self as Reveal>::reveal(*self)
    }

    fn unwrap_as_public(self) -> F;

    fn wrap_as_shared(g: F) -> Self;

    fn map_homo<FF: Field, SS: ScalarShare<FF>, Fun: Fn(F) -> FF>(self, f: Fun) -> SS {
        SS::wrap_as_shared(f(self.unwrap_as_public()))
    }

    fn batch_open(selfs: impl IntoIterator<Item = Self>) -> Vec<F> {
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
        self.scale(&-<F as ark_ff::One>::one())
    }

    fn shift(&mut self, other: &F) -> &mut Self;

    fn scale(&mut self, other: &F) -> &mut Self;

    fn mul<S: BeaverSource<Self, Self, Self>>(self, other: Self, source: &mut S) -> Self {
        let (mut x, mut y, z) = source.triple();
        //println!("Triple:\n *{}\n *{}\n *{}", x, y, z);
        let s = self;
        let o = other;
        // output: z - open(s + x)y - open(o + y)x + open(s + x)open(o + y)
        //         xy - sy - xy - ox - yx + so + sy + xo + xy
        //         so
        let sx = {
            let mut t = s;
            t.add(&x).open()
        };
        let oy = {
            let mut t = o;
            t.add(&y).open()
        };
        let mut result = z;
        result.sub(y.scale(&sx)).sub(x.scale(&oy)).shift(&(sx * oy));
        #[cfg(debug_assertions)]
        {
            let a = s.reveal();
            let b = o.reveal();
            let r = result.reveal();
            if a * b != r {
                println!("Bad multiplication!.\n{}\n*\n{}\n=\n{}", a, b, r);
                panic!("Bad multiplication");
            }
        }
        result
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
        let sxs = Self::batch_open(ss.into_iter().zip(xs.iter()).map(|(mut s, x)| {
            s.add(x);
            s
        }));
        let oys = Self::batch_open(os.into_iter().zip(ys.iter()).map(|(mut o, y)| {
            o.add(y);
            o
        }));
        zs.into_iter()
            .zip(ys.into_iter())
            .zip(xs.into_iter())
            .enumerate()
            .map(|(i, ((mut z, mut y), mut x))| {
                z.sub(y.scale(&sxs[i]))
                    .sub(x.scale(&oys[i]))
                    .shift(&(sxs[i] * oys[i]));
                z
            })
            .collect()
    }

    fn inv<S: BeaverSource<Self, Self, Self>>(self, source: &mut S) -> Self {
        let (x, mut y) = source.inv_pair();
        let xa = x.mul(self, source).open().inverse().unwrap();
        *y.scale(&xa)
    }

    fn batch_inv<S: BeaverSource<Self, Self, Self>>(xs: Vec<Self>, source: &mut S) -> Vec<Self> {
        let (bs, cs) = source.inv_pairs(xs.len());
        cs.into_iter()
            .zip(
                Self::batch_open(Self::batch_mul(xs, bs, source))
                    .into_iter()
                    .map(|i| i.inverse().unwrap()),
            )
            .map(|(mut c, i)| {
                c.scale(&i);
                c
            })
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

    fn partial_products<S: BeaverSource<Self, Self, Self>>(x: Vec<Self>, src: &mut S) -> Vec<Self> {
        let n = x.len();
        let (m, m_inv): (Vec<Self>, Vec<Self>) = (0..(n + 1)).map(|_| src.inv_pair()).unzip();
        debug_reveal("m", &m);
        debug_reveal("m", &m_inv);
        let mx = Self::batch_mul(m[..n].iter().cloned().collect(), x, src);
        let mxm = Self::batch_mul(mx, m_inv[1..].iter().cloned().collect(), src);
        debug_reveal("mxm", &mxm);
        let mut mxm_pub = Self::batch_open(mxm);
        for i in 1..mxm_pub.len() {
            let last = mxm_pub[i - 1];
            mxm_pub[i] *= &last;
        }
        debug_list("mxm_pub", &mxm_pub);
        let m0 = vec![m[0]; n];
        let mms = Self::batch_mul(m0, m_inv[1..].iter().cloned().collect(), src);
        debug_reveal("mms", &mms);
        let mut mms_inv = Self::batch_inv(mms, src);
        debug_reveal("mms_inv", &mms_inv);
        //let mms_pub = Self::batch_open(mms);
        for i in 0..mxm_pub.len() {
            mms_inv[i].scale(&mxm_pub[i]);
        }
        debug_reveal("mms_inv_scale", &mms_inv);
        debug_assert!(mxm_pub.len() == n);
        mms_inv
    }
}

fn debug_reveal<R: Reveal + Clone + Display>(t: &str, r: &[R])
where
    R::Base: Display,
{
    #[cfg(debug_assertions)]
    {
        debug_list(t, &r);
        let rs: Vec<_> = r.iter().map(|r| r.clone().reveal()).collect();
        debug_list(t, &rs);
    }
}
fn debug_list<R: Display>(t: &str, r: &[R])
{
    #[cfg(debug_assertions)]
    {
        println!("{}:", t);
        for (i, r) in r.iter().enumerate() {
            println!("{}: {}", i, r);
        }
    }
}

pub trait ExtFieldShare<F: Field>:
    Clone + Copy + Debug + 'static + Send + Sync + PartialEq + Eq
{
    type Base: ScalarShare<F::BasePrimeField>;
    type Ext: ScalarShare<F>;
}
