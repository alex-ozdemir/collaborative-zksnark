//! Implementation based on ["Malicious Security Comes Free in Honest-Majority
//! MPC"](https://ia.cr/2020/134) by Goyal and Song.

use ark_ff::{
    bytes::{FromBytes, ToBytes},
    prelude::*,
    FftField,
};
use ark_ec::{ProjectiveCurve, AffineCurve, PairingEngine};
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
use std::marker::PhantomData;

use derivative::Derivative;
use rand::Rng;

use super::field::FieldShare;
use super::BeaverSource;
use crate::share::pairing::{PairingShare, AffProjShare};
use crate::share::group::GroupShare;
use crate::msm::Msm;
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

    impl<F: FftField> FieldShare<F> for GszFieldShare<F> {
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

        /// Multiply many pairs of shares, consuming many double-shares.
        fn batch_mul<S: BeaverSource<Self, Self, Self>>(
            xs: Vec<Self>,
            ys: Vec<Self>,
            _source: &mut S,
        ) -> Vec<Self> {
            batch_mult(xs, &ys)
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

    pub fn batch_double_rand<F: Field>(n: usize) -> (Vec<GszFieldShare<F>>, Vec<GszFieldShare<F>>) {
        (0..n).map(|_| double_rand()).unzip()
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

    /// Given
    /// * Shares `share`
    /// * A function over plain data, `f`
    ///
    /// 1. Opens the share to King.
    /// 2. King performs the function.
    /// 3. King reshares the result.
    pub fn batch_king_compute<F: FftField, Func: Fn(F) -> F>(
        shares: &[GszFieldShare<F>],
        new_degree: usize,
        f: Func,
    ) -> Vec<GszFieldShare<F>> {
        let values: Vec<F> = shares.iter().map(|s| s.val).collect();
        let king_answer = alg_net::send_to_king(&values).map(|all_shares| {
            let n = all_shares.len();
            let mut outputs = vec![Vec::new(); n];
            for i in 0..all_shares[0].len() {
                let these_shares: Vec<F> = all_shares.iter().map(|s| s[i]).collect();
                let value = open_degree_vec(these_shares, shares[i].degree);
                let output = f(value);
                // TODO: randomize
                outputs.iter_mut().for_each(|o| o.push(output));
            }
            assert_eq!(outputs.len(), all_shares.len());
            assert_eq!(outputs[0].len(), all_shares[0].len());
            outputs
        });
        let from_king = alg_net::recv_from_king(king_answer.as_ref());
        from_king
            .into_iter()
            .map(|from_king| GszFieldShare {
                degree: new_degree,
                val: from_king,
            })
            .collect()
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

    /// Multiply shares, using king
    ///
    /// Protocol 8.
    pub fn batch_mult<F: FftField>(
        mut x: Vec<GszFieldShare<F>>,
        y: &[GszFieldShare<F>],
    ) -> Vec<GszFieldShare<F>> {
        let n = x.len();
        let d = x[0].degree;
        assert_eq!(x.len(), y.len());
        let (r, r2) = batch_double_rand::<F>(n);
        for ((x, y), r2) in x.iter_mut().zip(y).zip(r2) {
            assert_eq!(x.degree, d);
            x.val *= y.val;
            x.degree *= 2;
            x.val += r2.val;
        }
        // king just reduces the sharing degree
        let mut shift_res = batch_king_compute(&x, x[0].degree / 2, |r| r);
        for (shift_res, r) in shift_res.iter_mut().zip(r) {
            // TODO: record triple
            shift_res.val -= r.val;
        }
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
        type FieldShare = GszFieldShare<G::ScalarField>;

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

        fn scale_pub_group(mut base: G, scalar: &Self::FieldShare) -> Self {
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

        fn multi_scale_pub_group(bases: &[G], scalars: &[Self::FieldShare]) -> Self {
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

    /// Given
    /// * A share `share`
    /// * A function over plain data, `f`
    ///   * which also outputs a sharing degree.
    ///
    /// 1. Opens the share to King.
    /// 2. King performs the function.
    /// 3. King reshares the result.
    pub fn king_compute<G: Group, M, Func: FnOnce(G) -> G>(
        share: &GszGroupShare<G, M>,
        new_degree: usize,
        f: Func,
    ) -> GszGroupShare<G, M> {
        let king_answer = alg_net::send_to_king(&share.val).map(|shares| {
            let n = shares.len();
            let value = open_degree_vec(shares, share.degree);
            let output = f(value);
            // TODO: randomize
            vec![output; n]
        });
        let from_king = alg_net::recv_from_king(king_answer.as_ref());
        GszGroupShare {
            degree: new_degree,
            val: from_king,
            _phants: Default::default(),
        }
    }
    /// Multiply shares, using king
    ///
    /// Protocol 8.
    pub fn mult<G: Group, M>(
        x: &GszFieldShare<G::ScalarField>,
        mut y: GszGroupShare<G, M>,
    ) -> GszGroupShare<G, M> {
        let (r, r2) = double_rand::<G, M>();
        y.val *= x.val;
        y.degree *= 2;
        y.val += r2.val;
        // king just reduces the sharing degree
        let mut shift_res = king_compute(&y, x.degree / 2, |r| r);
        // TODO: record triple
        shift_res.val -= r.val;
        shift_res
    }
}

pub use group::GszGroupShare;

// #[derive(Debug, Derivative)]
// #[derivative(Default(bound = ""), Clone(bound = ""), Copy(bound = ""))]
// pub struct AdditiveAffineMsm<G: AffineCurve>(pub PhantomData<G>);
// 
// impl<G: AffineCurve> Msm<G, G::ScalarField> for AdditiveAffineMsm<G> {
//     fn msm(bases: &[G], scalars: &[G::ScalarField]) -> G {
//         G::multi_scalar_mul(bases, scalars).into()
//     }
// }
// 
// #[derive(Debug, Derivative)]
// #[derivative(Default(bound = ""), Clone(bound = ""), Copy(bound = ""))]
// pub struct AdditiveProjectiveMsm<G: ProjectiveCurve>(pub PhantomData<G>);
// 
// impl<G: ProjectiveCurve> Msm<G, G::ScalarField> for AdditiveProjectiveMsm<G> {
//     fn msm(bases: &[G], scalars: &[G::ScalarField]) -> G {
//         let bases: Vec<G::Affine> = bases.iter().map(|s| s.clone().into()).collect();
//         <G::Affine as AffineCurve>::multi_scalar_mul(&bases, scalars)
//     }
// }

macro_rules! groups_share {
    ($struct_name:ident, $affine:ident, $proj:ident) => {
        pub struct $struct_name<E: PairingEngine>(pub PhantomData<E>);

        impl<E: PairingEngine> AffProjShare<E::Fr, E::$affine, E::$proj> for $struct_name<E> {
            type FrShare = GszFieldShare<E::Fr>;
            type AffineShare = GszGroupShare<E::$affine, super::add::AdditiveAffineMsm<E::$affine>>;
            type ProjectiveShare = GszGroupShare<E::$proj, super::add::AdditiveProjectiveMsm<E::$proj>>;

            fn sh_aff_to_proj(g: Self::AffineShare) -> Self::ProjectiveShare {
                g.map_homo(|s| s.into())
            }

            fn sh_proj_to_aff(g: Self::ProjectiveShare) -> Self::AffineShare {
                g.map_homo(|s| s.into())
            }

            fn add_sh_proj_sh_aff(
                mut a: Self::ProjectiveShare,
                o: &Self::AffineShare,
            ) -> Self::ProjectiveShare {
                a.val.add_assign_mixed(&o.val);
                a
            }
            fn add_sh_proj_pub_aff(mut a: Self::ProjectiveShare, o: &E::$affine) -> Self::ProjectiveShare {
                if mpc_net::am_first() {
                    a.val.add_assign_mixed(&o);
                }
                a
            }
            fn add_pub_proj_sh_aff(_a: &E::$proj, _o: Self::AffineShare) -> Self::ProjectiveShare {
                unimplemented!()
            }
        }
    };
}

groups_share!(GszG1Share, G1Affine, G1Projective);
groups_share!(GszG2Share, G2Affine, G2Projective);
