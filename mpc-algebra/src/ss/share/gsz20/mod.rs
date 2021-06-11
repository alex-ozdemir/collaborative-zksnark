//! Implementation based on ["Malicious Security Comes Free in Honest-Majority
//! MPC"](https://ia.cr/2020/134) by Goyal and Song.

use ark_ff::{prelude::*, FftField};
use ark_poly::{
    domain::{EvaluationDomain, GeneralEvaluationDomain},
    univariate::DensePolynomial,
    Polynomial, UVPolynomial,
};
use mpc_net::multi as net;

use crate::channel::multi as alg_net;

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
pub struct GsFieldShare<F: Field> {
    pub val: F,
    #[cfg(debug_assertions)]
    pub degree: usize,
}

/// Yields a t-share of a random r.
///
/// Stubbed b/c it can be pre-processed.
///
/// Protocol 3.
pub fn rand<F: Field>() -> GsFieldShare<F> {
    GsFieldShare {
        val: F::one(),
        #[cfg(debug_assertions)]
        degree: t(),
    }
}

/// Yields two shares of a random `r`, one of degree t, one of degree 2t
///
/// Stubbed b/c it can be pre-processed.
///
/// Protocol 4.
pub fn double_rand<F: Field>() -> (GsFieldShare<F>, GsFieldShare<F>) {
    (
        GsFieldShare {
            val: F::one(),
            #[cfg(debug_assertions)]
            degree: t(),
        },
        GsFieldShare {
            val: F::one(),
            #[cfg(debug_assertions)]
            degree: 2 * t(),
        },
    )
}

/// Open a t-share.
pub fn open<F: FftField>(s: &GsFieldShare<F>) -> F {
    open_degree(s, t())
}

/// Open a d-share.
pub fn open_degree<F: FftField>(s: &GsFieldShare<F>, d: usize) -> F {
    debug_assert_eq!(s.degree, d);
    let mut shares = alg_net::broadcast(&s.val);
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
