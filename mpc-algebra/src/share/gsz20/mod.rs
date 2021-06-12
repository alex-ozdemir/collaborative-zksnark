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

use derivative::Derivative;
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

pub mod field {
    use super::*;

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
}

pub use field::GszFieldShare;

pub mod group {
    use super::super::group::GroupShare;
    use super::*;
    use crate::msm::Msm;
    use ark_ec::group::Group;
    use std::marker::PhantomData;

    #[derive(Derivative)]
    #[derivative(
        Clone(bound = "T: Clone"),
        Copy(bound = "T: Copy"),
        PartialEq(bound = "T: PartialEq"),
        Eq(bound = "T: Eq"),
        PartialOrd(bound = "T: PartialOrd"),
        Ord(bound = "T: Ord"),
        Hash(bound = "T: Hash")
    )]
    pub struct GszGroupShare<T, M> {
        pub val: T,
        pub degree: usize,
        pub _phants: PhantomData<M>,
    }
    impl_basics_2_param!(GszGroupShare, Group);

    impl<G: Group, M> Reveal for GszGroupShare<G, M> {
        type Base = G;

        fn reveal(self) -> G {
            open(&self)
        }
        fn from_public(f: G) -> Self {
            Self {
                val: f,
                degree: t(),
                _phants: PhantomData::default(),
            }
        }
        fn from_add_shared(_f: G) -> Self {
            unimplemented!("from_add_shared")
        }
        fn unwrap_as_public(self) -> G {
            self.val
        }
    }

    impl<G: Group, M: Msm<G, G::ScalarField>> GroupShare<G> for GszGroupShare<G, M> {
        type ScalarShare = GszFieldShare<G::ScalarField>;

        fn add(&mut self, other: &Self) -> &mut Self {
            self.val += &other.val;
            self
        }

        fn sub(&mut self, other: &Self) -> &mut Self {
            self.val -= &other.val;
            self
        }

        fn scale_pub_scalar(&mut self, scalar: &G::ScalarField) -> &mut Self {
            self.val *= *scalar;
            self
        }

        fn scale_pub_group(mut base: G, scalar: &Self::ScalarShare) -> Self {
            base *= scalar.val;
            Self {
                val: base,
                degree: scalar.degree,
                _phants: PhantomData::default(),
            }
        }

        fn shift(&mut self, other: &G) -> &mut Self {
            self.val += other;
            self
        }

        fn multi_scale_pub_group(bases: &[G], scalars: &[Self::ScalarShare]) -> Self {
            let scalars: Vec<G::ScalarField> = scalars.into_iter().map(|s| s.val.clone()).collect();
            Self::from_add_shared(M::msm(bases, &scalars))
        }
    }

    /// Yields a t-share of a random r.
    ///
    /// Stubbed b/c it can be pre-processed.
    ///
    /// Protocol 3.
    pub fn rand<G: Group, M>() -> GszGroupShare<G, M> {
        GszGroupShare {
            val: G::zero(),
            degree: t(),
            _phants: Default::default(),
        }
    }

    /// Yields two shares of a random `r`, one of degree t, one of degree 2t
    ///
    /// Stubbed b/c it can be pre-processed.
    ///
    /// Protocol 4.
    pub fn double_rand<G: Group, M>() -> (GszGroupShare<G, M>, GszGroupShare<G, M>) {
        (
            GszGroupShare {
                val: G::zero(),
                degree: t(),
                _phants: Default::default(),
            },
            GszGroupShare {
                val: G::zero(),
                degree: 2 * t(),
                _phants: Default::default(),
            },
        )
    }

    /// Open a t-share.
    pub fn open<G: Group, M>(s: &GszGroupShare<G, M>) -> G {
        let shares = alg_net::broadcast(&s.val);
        open_degree_vec(shares, s.degree)
    }

    fn open_degree_vec<G: Group>(shares: Vec<G>, d: usize) -> G {
        let domain = domain::<G::ScalarField>();
        let n = net::n_parties();
        let n_inv = G::ScalarField::from(n as u32).inverse().unwrap();
        let w = domain.element(1);
        let w_inv = w.inverse().unwrap();
        // w^{-i}
        let mut w_inv_i = G::ScalarField::one();
        let coeffs: Vec<G> = (0..n)
            .map(|i| {
                let mut coeff = G::zero();
                // 1/N * w^{-ij}
                let mut w_inv_ij = n_inv;
                for _j in 0..n {
                    coeff += shares[i].mul(&w_inv_ij);
                    w_inv_ij *= &w_inv_i;
                }
                w_inv_i *= &w_inv;
                coeff
            })
            .collect();
        assert_eq!(coeffs.len(), n);
        for i in d + 1..n {
            assert!(
                coeffs[i].is_zero(),
                "Non-one coeffs {} ({}), when expecting a degree <= {} poly",
                i,
                coeffs[i],
                d
            );
        }
        coeffs[0]
    }
}
