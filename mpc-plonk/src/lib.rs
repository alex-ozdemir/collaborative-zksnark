pub mod data_structures;
pub mod rng;

use blake2::Blake2s;
use rng::FiatShamirRng;

use ark_ff::{FftField, UniformRand};

use ark_poly_commit::{LabeledCommitment, LabeledPolynomial, PolynomialCommitment};

use ark_poly::{domain::EvaluationDomain, univariate::DensePolynomial, Polynomial};

use ark_std::rand::RngCore;
use std::iter::once;
use std::marker::PhantomData;
use thiserror::Error;

use mpc_trait::MpcWire;

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
    use ark_poly::{UVPolynomial, domain::GeneralEvaluationDomain};

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
            let (c, p, r) = plk.commit("a".into(), poly.clone(), Some(10), Some(2)).unwrap();
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
}
