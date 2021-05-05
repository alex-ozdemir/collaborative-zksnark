//! Implementation of the PLONK proof system.
//!
//! PLONK is originally described [here](https://eprint.iacr.org/2019/953.pdf).
//!
//! This implementation is based on Dan Boneh's [lecture
//! 17](https://cs251.stanford.edu/lectures/lecture17.pdf) for CS 251 (Spring 20) at Stanford.
//!
//! You should look at those notes for the notation used here.

pub mod data_structures;
use data_structures::*;
pub mod relations;
pub mod rng;
mod util;

use blake2::Blake2s;
use rng::FiatShamirRng;

use ark_ff::{FftField, Field};

use ark_poly_commit::{LabeledCommitment, LabeledPolynomial, PolynomialCommitment, UVPolynomial};

use ark_poly::{domain::EvaluationDomain, univariate::DensePolynomial, Polynomial};

use ark_std::rand::RngCore;
use std::iter::once;
use std::marker::PhantomData;
use thiserror::Error;

use mpc_trait::MpcWire;

#[allow(dead_code)]
pub struct Prover<'r, F: FftField, PC: PolynomialCommitment<F, DensePolynomial<F>>> {
    _field: PhantomData<F>,
    _pc: PhantomData<PC>,
    pc_vk: PC::VerifierKey,
    pc_ck: PC::CommitterKey,
    zk_rng: &'r mut dyn RngCore,
    fs_rng: &'r mut FiatShamirRng<Blake2s>,
}

impl<'r, F: FftField, PC: PolynomialCommitment<F, DensePolynomial<F>>> Prover<'r, F, PC> {
    pub fn new(
        pc_vk: PC::VerifierKey,
        pc_ck: PC::CommitterKey,
        fs_rng: &'r mut FiatShamirRng<Blake2s>,
        zk_rng: &'r mut dyn RngCore,
    ) -> Self {
        Self {
            _field: PhantomData::default(),
            _pc: PhantomData::default(),
            pc_vk,
            pc_ck,
            zk_rng,
            fs_rng,
        }
    }
}

/// Replace `[x1, x2, ... , xn]` with `[x1, x1*x2, ... , x1*x2*...*xn]`
fn partial_products_in_place<F: Field>(xs: &mut [F]) {
    for i in 1..xs.len() {
        let last = xs[i - 1];
        xs[i] *= &last;
    }
}

#[allow(dead_code)]
impl<'r, F: FftField, PC: PolynomialCommitment<F, DensePolynomial<F>>> Prover<'r, F, PC>
where
    PC::Commitment: mpc_trait::MpcWire,
    PC::Error: 'static,
{
    fn prove_unit_product<D: EvaluationDomain<F>>(
        &mut self,
        f: &LabeledPolynomial<F, DensePolynomial<F>>,
        f_cmt: &LabeledCommitment<PC::Commitment>,
        f_rand: &PC::Randomness,
        domain: D,
    ) -> ProductProof<F, PC::Commitment, (F, PC::Proof)> {
        let t_evals = {
            let mut t = f.evaluate_over_domain_by_ref(domain);
            partial_products_in_place(&mut t.evals);
            t
        };
        debug_assert_eq!(t_evals.evals[f.coeffs.len() - 1], F::one());
        debug_assert_eq!(
            t_evals.evals[f.coeffs.len() - 1] * t_evals.evals[0],
            t_evals[0]
        );
        let t = t_evals.interpolate();
        let (t_cmt, t, t_rand) = self.commit("t".to_owned(), t.clone(), None, None).unwrap();
        let w = domain.element(1);
        // let q = {
        //     let d = &shift(t.clone(), w) - &t.naive_mul(&shift(f.clone(), w));
        //     let (q,r) = d.divide_by_vanishing_poly(domain).unwrap();
        //     assert!(r.is_zero());
        //     q
        // };
        let q = {
            // get f(wX) over coset
            let mut f_evals = f.coeffs.clone();
            D::distribute_powers(&mut f_evals, w);
            domain.coset_fft_in_place(&mut f_evals);
            // get t(X) over coset
            let mut t_evals = t.coeffs.clone();
            domain.coset_fft_in_place(&mut t_evals);
            // get f(wX)t(X) over coset
            let fwt_evals = domain.mul_polynomials_in_evaluation_domain(&f_evals, &t_evals);
            // get t(wX) over coset
            let mut tw_evals = t.coeffs.clone();
            D::distribute_powers(&mut tw_evals, w);
            domain.coset_fft_in_place(&mut tw_evals);
            // get t(wX) - f(wX)t(X) over coset
            ark_std::cfg_iter_mut!(tw_evals)
                .zip(fwt_evals)
                .for_each(|(a, b)| *a -= b);
            domain.divide_by_vanishing_poly_on_coset_in_place(&mut tw_evals);
            domain.coset_ifft_in_place(&mut tw_evals);
            DensePolynomial::from_coefficients_vec(tw_evals)
        };
        // assert_eq!(q, qq);
        let (q_cmt, q, q_rand) = self.commit("q".to_owned(), q.clone(), None, None).unwrap();
        let k = domain.size();
        debug_assert_eq!(t.evaluate(&domain.element(k - 1)), F::one());
        for i in 0..k {
            let r = domain.element(i);
            debug_assert_eq!(t.evaluate(&(w * r)), t.evaluate(&r) * f.evaluate(&(w * r)));
        }
        let r = F::rand(self.fs_rng);
        debug_assert_eq!(
            t.evaluate(&(w * r)) - t.evaluate(&r) * f.evaluate(&(w * r)),
            domain.evaluate_vanishing_polynomial(r) * q.evaluate(&r)
        );
        let t_wr_open = self.eval(&t, &t_rand, &t_cmt, w * r).unwrap();
        let t_r_open = self.eval(&t, &t_rand, &t_cmt, r).unwrap();
        let t_wk_open = self
            .eval(&t, &t_rand, &t_cmt, domain.element(k - 1))
            .unwrap();
        let f_wr_open = self.eval(&f, &f_rand, &f_cmt, w * r).unwrap();
        let q_r_open = self.eval(&q, &q_rand, &q_cmt, r).unwrap();
        debug_assert_eq!(
            t_wr_open.0 - t_r_open.0 * f_wr_open.0,
            domain.evaluate_vanishing_polynomial(r) * q_r_open.0
        );
        debug_assert_eq!(t_wk_open.0, F::one());
        ProductProof {
            t_cmt: t_cmt.commitment,
            q_cmt: q_cmt.commitment,
            r,
            t_wk_open,
            t_r_open,
            t_wr_open,
            f_wr_open,
            q_r_open,
        }
    }

    /// Evaluate polynomial `p` at `x`, producing a proof of the evaluation as well.
    ///
    /// With respect to a commitment `p_c` under randomness `p_r`.
    fn eval(
        &mut self,
        p: &LabeledPolynomial<F, DensePolynomial<F>>,
        p_r: &PC::Randomness,
        p_c: &LabeledCommitment<PC::Commitment>,
        x: F,
    ) -> Result<(F, PC::Proof), Error<PC::Error>> {
        let pf_p = PC::open(
            &self.pc_ck,
            once(p),
            once(p_c),
            &x,
            F::one(), // acceptable b/c this is just one commitment.
            once(p_r),
            Some(self.zk_rng),
        )?;
        let mut y = p.polynomial().evaluate(&x);
        y.publicize();
        Ok((y, pf_p))
    }

    /// Commit to a polynomial `p`.
    ///
    /// Produces a (commitment, labeled_poly, randomness) triple.
    fn commit(
        &mut self,
        label: String,
        p: DensePolynomial<F>,
        degree: Option<usize>,
        hiding_bound: Option<usize>,
    ) -> Result<
        (
            LabeledCommitment<PC::Commitment>,
            LabeledPolynomial<F, DensePolynomial<F>>,
            PC::Randomness,
        ),
        Error<PC::Error>,
    > {
        let label_p = LabeledPolynomial::new(label, p, degree, hiding_bound);
        let (mut cs, mut rs) = PC::commit(&self.pc_ck, once(&label_p), Some(self.zk_rng))?;
        assert_eq!(cs.len(), 1);
        assert_eq!(rs.len(), 1);
        let mut c = cs.pop().unwrap();
        c.commitment.publicize();
        self.fs_rng
            .absorb(&ark_ff::to_bytes![c].expect("failed serialization"));
        Ok((c, label_p, rs.pop().unwrap()))
    }
}

pub struct Verifier<'r, F: FftField, PC: PolynomialCommitment<F, DensePolynomial<F>>> {
    _field: PhantomData<F>,
    _pc: PhantomData<PC>,
    pc_vk: PC::VerifierKey,
    fs_rng: &'r mut FiatShamirRng<Blake2s>,
    rng: &'r mut dyn RngCore,
}
#[allow(dead_code)]
impl<'r, F: FftField, PC: PolynomialCommitment<F, DensePolynomial<F>>> Verifier<'r, F, PC>
where
    PC::Commitment: mpc_trait::MpcWire,
    PC::Error: 'static,
{
    fn verify_unit_product<D: EvaluationDomain<F>>(
        &mut self,
        f_cmt: &LabeledCommitment<PC::Commitment>,
        pf: ProductProof<F, PC::Commitment, (F, PC::Proof)>,
        domain: D,
    ) {
        let k = domain.size();
        let w = domain.element(1);
        let t_cmt = self.recv_commit("t".into(), pf.t_cmt, None);
        let q_cmt = self.recv_commit("q".into(), pf.q_cmt, None);
        let r = F::rand(self.fs_rng);
        assert_eq!(r, pf.r, "Difference challenge");
        // Check commitments
        assert!(PC::check(
            &self.pc_vk,
            once(f_cmt),
            &(w * r),
            once(pf.f_wr_open.0),
            &pf.f_wr_open.1,
            F::one(), // Okay b/c a single commit
            Some(self.rng),
        )
        .unwrap(), "Verification failed: f(wr)");
        assert!(PC::check(
            &self.pc_vk,
            once(&q_cmt),
            &r,
            once(pf.q_r_open.0),
            &pf.q_r_open.1,
            F::one(), // Okay b/c a single commit
            Some(self.rng),
        )
        .unwrap(), "Verification failed: q(r)");
        assert!(PC::check(
            &self.pc_vk,
            once(&t_cmt),
            &r,
            once(pf.t_r_open.0),
            &pf.t_r_open.1,
            F::one(), // Okay b/c a single commit
            Some(self.rng),
        )
        .unwrap(), "Verification failed: t(r)");
        assert!(PC::check(
            &self.pc_vk,
            once(&t_cmt),
            &(w * r),
            once(pf.t_wr_open.0),
            &pf.t_wr_open.1,
            F::one(), // Okay b/c a single commit
            Some(self.rng),
        )
        .unwrap(), "Verification failed: t(wr)");
        assert!(PC::check(
            &self.pc_vk,
            once(&t_cmt),
            &domain.element(k-1),
            once(pf.t_wk_open.0),
            &pf.t_wk_open.1,
            F::one(), // Okay b/c a single commit
            Some(self.rng),
        )
        .unwrap(), "Verification failed: t(w^(k-1))");
        assert_eq!(
            pf.t_wr_open.0 - pf.t_r_open.0 * pf.f_wr_open.0,
            domain.evaluate_vanishing_polynomial(r) * pf.q_r_open.0
        );
        assert_eq!(pf.t_wk_open.0, F::one());
    }
    /// Receive a commitment
    ///
    /// Produces a (commitment, labeled_poly, randomness) triple.
    fn recv_commit(
        &mut self,
        label: String,
        c: PC::Commitment,
        degree: Option<usize>,
    ) -> LabeledCommitment<PC::Commitment> {
        let label_c = LabeledCommitment::new(label, c, degree);
        self.fs_rng
            .absorb(&ark_ff::to_bytes![label_c].expect("failed serialization"));
        label_c
    }
}

impl<'r, F: FftField, PC: PolynomialCommitment<F, DensePolynomial<F>>> Verifier<'r, F, PC> {
    pub fn new(
        pc_vk: PC::VerifierKey,
        fs_rng: &'r mut FiatShamirRng<Blake2s>,
        rng: &'r mut dyn RngCore,
    ) -> Self {
        Self {
            _field: PhantomData::default(),
            _pc: PhantomData::default(),
            pc_vk,
            fs_rng,
            rng,
        }
    }
}

pub struct Plonk<'r, F: FftField, PC: PolynomialCommitment<F, DensePolynomial<F>>> {
    _field: PhantomData<F>,
    _pc: PhantomData<PC>,
    pc_vk: PC::VerifierKey,
    pc_ck: PC::CommitterKey,
    zk_rng: &'r mut dyn RngCore,
    fs_rng: &'r mut FiatShamirRng<Blake2s>,
}

impl<'r, F: FftField, PC: PolynomialCommitment<F, DensePolynomial<F>>> Plonk<'r, F, PC> {
    pub fn new(
        pc_vk: PC::VerifierKey,
        pc_ck: PC::CommitterKey,
        fs_rng: &'r mut FiatShamirRng<Blake2s>,
        zk_rng: &'r mut dyn RngCore,
    ) -> Self {
        Self {
            _field: PhantomData::default(),
            _pc: PhantomData::default(),
            pc_vk,
            pc_ck,
            zk_rng,
            fs_rng,
        }
    }
}

#[derive(Error, Debug)]
pub enum Error<PCE: 'static + std::error::Error> {
    #[error("Sub error: {0}")]
    Sub(#[from] PCE),
    #[error("The zero-test failed b/c PC.check failed")]
    ZeroTestPcCheckFailure,
    #[error("Division by vanishing poly on domain failed")]
    DomainDivisionFailed,
    #[error("Eq check for domain division failed")]
    DomainCheckFailed,
}

pub type Result<T, PCE> = std::result::Result<T, PCE>;

#[allow(dead_code)]
impl<'r, F: FftField, PC: PolynomialCommitment<F, DensePolynomial<F>>> Plonk<'r, F, PC>
where
    PC::Commitment: mpc_trait::MpcWire,
{
    /// Check that `c` commits to `p` (with `r`) which is zero everywhere.
    fn zero_test(
        &mut self,
        p: &LabeledPolynomial<F, DensePolynomial<F>>,
        r: &PC::Randomness,
        c: &LabeledCommitment<PC::Commitment>,
    ) -> Result<(), Error<PC::Error>> {
        let mut x = F::rand(self.fs_rng);
        x.cast_to_public();
        let y = self.eval(p, r, c, x)?;
        if y.is_zero() {
            Ok(())
        } else {
            Err(Error::ZeroTestPcCheckFailure)
        }
    }

    /// Check that `c` commits to `p` (with `r`) which is zero on `dom`.
    fn domain_zero_test<D: EvaluationDomain<F>>(
        &mut self,
        p: &LabeledPolynomial<F, DensePolynomial<F>>,
        p_r: &PC::Randomness,
        p_c: &LabeledCommitment<PC::Commitment>,
        dom: D,
    ) -> Result<(), Error<PC::Error>> {
        let (q, _r) = p
            .polynomial()
            .divide_by_vanishing_poly(dom)
            .ok_or(Error::DomainDivisionFailed)?;
        let (q_c, q, q_r) = self.commit("q".into(), q, None, Some(1))?;
        let mut x = F::rand(self.fs_rng);
        x.cast_to_public();
        let p_y = self.eval(p, p_r, p_c, x)?;
        let q_y = self.eval(&q, &q_r, &q_c, x)?;
        let vanish_y = dom.evaluate_vanishing_polynomial(x);
        assert!(!vanish_y.is_shared());
        if vanish_y * &q_y == p_y {
            Ok(())
        } else {
            Err(Error::DomainCheckFailed)
        }
    }

    fn eval(
        &mut self,
        p: &LabeledPolynomial<F, DensePolynomial<F>>,
        p_r: &PC::Randomness,
        p_c: &LabeledCommitment<PC::Commitment>,
        x: F,
    ) -> Result<F, Error<PC::Error>> {
        let mut chal_p = F::rand(self.fs_rng);
        chal_p.cast_to_public();
        let pf_p = PC::open(
            &self.pc_ck,
            once(p),
            once(p_c),
            &x,
            chal_p,
            once(p_r),
            Some(self.zk_rng),
        )?;
        let mut y = p.polynomial().evaluate(&x);
        y.publicize();
        if !PC::check(
            &self.pc_vk,
            once(p_c),
            &x,
            once(y),
            &pf_p,
            chal_p,
            Some(self.fs_rng),
        )? {
            Err(Error::ZeroTestPcCheckFailure)?;
        }
        Ok(y)
    }

    /// Commit to a polynomial
    fn commit(
        &mut self,
        label: String,
        p: DensePolynomial<F>,
        degree: Option<usize>,
        hiding_bound: Option<usize>,
    ) -> Result<
        (
            LabeledCommitment<PC::Commitment>,
            LabeledPolynomial<F, DensePolynomial<F>>,
            PC::Randomness,
        ),
        Error<PC::Error>,
    > {
        let label_p = LabeledPolynomial::new(label, p, degree, hiding_bound);
        let (mut cs, mut rs) = PC::commit(&self.pc_ck, once(&label_p), Some(self.zk_rng))?;
        assert_eq!(cs.len(), 1);
        assert_eq!(rs.len(), 1);
        let mut c = cs.pop().unwrap();
        c.commitment.publicize();
        self.fs_rng
            .absorb(&ark_ff::to_bytes![c].expect("failed serialization"));
        Ok((c, label_p, rs.pop().unwrap()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use ark_poly::{domain::GeneralEvaluationDomain, UVPolynomial};

    type E = ark_bls12_377::Bls12_377;
    type F = ark_bls12_377::Fr;
    type P = DensePolynomial<F>;
    type PC = ark_poly_commit::marlin::marlin_pc::MarlinKZG10<E, P>;

    #[test]
    fn zero_test() {
        let rng = &mut ark_std::test_rng();
        let srs = PC::setup(100, Some(1), rng).unwrap();
        let (ck, vk) = PC::trim(&srs, 40, 10, Some(&[10])).unwrap();
        let fs_rng = &mut FiatShamirRng::from_seed(&0u64);
        let zk_rng = &mut ark_std::test_rng();
        for _i in 0..10 {
            let mut plk: Plonk<F, PC> = Plonk::new(vk.clone(), ck.clone(), fs_rng, zk_rng);
            let poly = P::from_coefficients_vec(vec![F::from(0u64); 10]);
            let (c, p, r) = plk.commit("a".into(), poly, Some(10), Some(2)).unwrap();
            plk.zero_test(&p, &r, &c).unwrap();
        }
    }

    #[test]
    fn eval_test() {
        let rng = &mut ark_std::test_rng();
        let srs = PC::setup(100, Some(1), rng).unwrap();
        let (ck, vk) = PC::trim(&srs, 40, 10, Some(&[10])).unwrap();
        let fs_rng = &mut FiatShamirRng::from_seed(&0u64);
        let zk_rng = &mut ark_std::test_rng();
        for _i in 0..10 {
            let mut plk: Plonk<F, PC> = Plonk::new(vk.clone(), ck.clone(), fs_rng, zk_rng);
            let poly = P::rand(10, rng);
            let (c, p, r) = plk
                .commit("a".into(), poly.clone(), Some(10), Some(2))
                .unwrap();
            let mut x = F::rand(rng);
            x.cast_to_public();
            let y = plk.eval(&p, &r, &c, x).unwrap();
            let mut yy = poly.evaluate(&x);
            yy.publicize();
            assert_eq!(y, yy);
        }
    }

    #[test]
    fn domain_zero_test() {
        let dom = GeneralEvaluationDomain::new(4).unwrap();
        assert_eq!(dom.size(), 4);
        let dom_vanish_poly: P = dom.vanishing_polynomial().into();
        let rng = &mut ark_std::test_rng();
        let srs = PC::setup(100, Some(1), rng).unwrap();
        let (ck, vk) = PC::trim(&srs, 40, 10, Some(&[10])).unwrap();
        let fs_rng = &mut FiatShamirRng::from_seed(&0u64);
        let zk_rng = &mut ark_std::test_rng();
        for _i in 0..10 {
            let mut plk: Plonk<F, PC> = Plonk::new(vk.clone(), ck.clone(), fs_rng, zk_rng);
            let poly = P::rand(6, rng).naive_mul(&dom_vanish_poly);
            let (c, p, r) = plk.commit("a".into(), poly, Some(10), Some(2)).unwrap();
            plk.domain_zero_test(&p, &r, &c, dom).unwrap();
        }
    }

    #[test]
    fn prod_test() {
        let dom_size = 4;
        let dom = GeneralEvaluationDomain::new(dom_size).unwrap();
        assert_eq!(dom.size(), dom_size);
        let rng = &mut ark_std::test_rng();
        let srs = PC::setup(100, Some(1), rng).unwrap();
        let (ck, vk) = PC::trim(&srs, 40, 10, Some(&[dom_size])).unwrap();
        let fs_rng = &mut FiatShamirRng::from_seed(&0u64);
        let zk_rng = &mut ark_std::test_rng();
        let v_fs_rng = &mut FiatShamirRng::from_seed(&0u64);
        let v_rng = &mut ark_std::test_rng();
        for _i in 0..10 {
            let mut prv: Prover<F, PC> = Prover::new(vk.clone(), ck.clone(), fs_rng, zk_rng);
            let poly = {
                let mut poly = P::rand(dom_size - 1, rng);
                // Fix product to 1.
                let prod: F = poly.coeffs.iter().product();
                poly.coeffs[dom_size - 1] /= prod;
                // treat our coeffs as evals, and get real coeffs
                dom.ifft_in_place(&mut poly.coeffs);
                poly
            };
            println!("{}", poly.degree());
            let (c, p, r) = prv
                .commit("base".into(), poly, Some(dom_size), None)
                .unwrap();
            let pf = prv.prove_unit_product(&p, &c, &r, dom);
            let mut ver: Verifier<F, PC> = Verifier::new(vk.clone(), v_fs_rng, v_rng);
            let c = ver.recv_commit("base".to_owned(), c.commitment, Some(dom_size));
            ver.verify_unit_product(&c, pf, dom);
        }
    }
}
