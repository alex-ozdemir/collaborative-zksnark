//! Implementation based on ["Malicious Security Comes Free in Honest-Majority
//! MPC"](https://ia.cr/2020/134) by Goyal and Song.

use ark_ff::{
    bytes::{FromBytes, ToBytes},
    prelude::*,
    FftField,
};
use ark_poly::{
    domain::{EvaluationDomain, GeneralEvaluationDomain},
    univariate::DensePolynomial,
    Polynomial, UVPolynomial,
};
use ark_serialize::{
    CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize,
    CanonicalSerializeWithFlags, Flags, SerializationError,
};
use mpc_net::multi as net;

use std::cmp::Ord;
use std::fmt::{self, Debug, Display, Formatter};
use std::hash::Hash;
use std::io::{self, Read, Write};

use rand::Rng;

use super::field::ScalarShare;
use super::BeaverSource;
use crate::channel::multi as alg_net;
use crate::Reveal;

/// Malicious degree
pub fn t() -> usize {
    (net::n_parties() - 1) / 2
}

pub fn domain<F: FftField>() -> GeneralEvaluationDomain<F> {
    let d = GeneralEvaluationDomain::new(net::n_parties()).unwrap();
    assert_eq!(d.size(), net::n_parties());
    d
}

/// A Goyal-Song '20 share.
///
/// This is an evaluation of a polynomial at the party-number's position in the multiplicative
/// subgroup of order equal to the number of parties.
#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct GszFieldShare<F: Field> {
    pub val: F,
    pub degree: usize,
}

impl_basics!(GszFieldShare, FftField);

impl<F: FftField> Reveal for GszFieldShare<F> {
    type Base = F;

    fn reveal(self) -> F {
        open(&self)
    }
    fn from_public(f: F) -> Self {
        Self { val: f, degree: 0 }
    }
    fn from_add_shared(_f: F) -> Self {
        unimplemented!()
    }
    fn unwrap_as_public(self) -> F {
        self.val
    }
}

impl<F: FftField> ScalarShare<F> for GszFieldShare<F> {
    fn add(&mut self, other: &Self) -> &mut Self {
        self.val += other.val;
        self
    }

    fn shift(&mut self, other: &F) -> &mut Self {
        self.val += other;
        self
    }

    fn scale(&mut self, other: &F) -> &mut Self {
        self.val *= other;
        self
    }

    fn sub(&mut self, other: &Self) -> &mut Self {
        self.val -= other.val;
        self
    }

    fn neg(&mut self) -> &mut Self {
        self.val = -self.val;
        self
    }

    /// Multiply two t-shares, consuming a double-share.
    ///
    /// Protocol 8.
    fn mul<S: BeaverSource<Self, Self, Self>>(self, other: Self, _source: &mut S) -> Self {
        mult(self, &other)
    }

    fn inv<S: super::BeaverSource<Self, Self, Self>>(self, _source: &mut S) -> Self {
        todo!()
    }
}

/// Yields a t-share of a random r.
///
/// Stubbed b/c it can be pre-processed.
///
/// Protocol 3.
pub fn rand<F: Field>() -> GszFieldShare<F> {
    GszFieldShare {
        val: F::one(),
        degree: t(),
    }
}

/// Yields two shares of a random `r`, one of degree t, one of degree 2t
///
/// Stubbed b/c it can be pre-processed.
///
/// Protocol 4.
pub fn double_rand<F: Field>() -> (GszFieldShare<F>, GszFieldShare<F>) {
    (
        GszFieldShare {
            val: F::one(),
            degree: t(),
        },
        GszFieldShare {
            val: F::one(),
            degree: 2 * t(),
        },
    )
}

/// Open a t-share.
pub fn open<F: FftField>(s: &GszFieldShare<F>) -> F {
    let shares = alg_net::broadcast(&s.val);
    open_degree_vec(shares, s.degree)
}

fn open_degree_vec<F: FftField>(mut shares: Vec<F>, d: usize) -> F {
    let domain = domain::<F>();
    domain.ifft_in_place(&mut shares);
    let p = DensePolynomial::from_coefficients_vec(shares);
    assert!(
        p.degree() <= d,
        "Polynomial\n{:?}\nhas degree {} (> degree bound {})",
        p,
        p.degree(),
        d
    );
    p.evaluate(&F::zero())
}

/// Given
/// * A share `share`
/// * A function over plain data, `f`
///   * which also outputs a sharing degree.
///
/// 1. Opens the share to King.
/// 2. King performs the function.
/// 3. King reshares the result.
pub fn king_compute<F: FftField, Func: FnOnce(F) -> F>(
    share: &GszFieldShare<F>,
    new_degree: usize,
    f: Func,
) -> GszFieldShare<F> {
    let king_answer = alg_net::send_to_king(&share.val).map(|shares| {
        let n = shares.len();
        let value = open_degree_vec(shares, share.degree);
        let output = f(value);
        // TODO: randomize
        vec![output; n]
    });
    let from_king = alg_net::recv_from_king(king_answer.as_ref());
    GszFieldShare {
        degree: new_degree,
        val: from_king,
    }
}

/// Generate a random coin, unknown to all parties until now.
///
/// Protocol 6.
pub fn coin<F: FftField>() -> F {
    open(&rand())
}

/// Multiply shares, using king
///
/// Protocol 8.
pub fn mult<F: FftField>(mut x: GszFieldShare<F>, y: &GszFieldShare<F>) -> GszFieldShare<F> {
    let (r, r2) = double_rand::<F>();
    x.val *= y.val;
    x.degree *= 2;
    x.val += r2.val;
    // king just reduces the sharing degree
    let mut shift_res = king_compute(&x, x.degree / 2, |r| r);
    // TODO: record triple
    shift_res.val -= r.val;
    shift_res
}
