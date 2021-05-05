//! Implementation of the PLONK proof system.
//!
//! PLONK is originally described [here](https://eprint.iacr.org/2019/953.pdf).
//!
//! This implementation is based on Dan Boneh's [lecture
//! 17](https://cs251.stanford.edu/lectures/lecture17.pdf) for CS 251 (Spring 20) at Stanford.
//!
//! You should look at those notes for the notation used here.

pub mod data_structures;
pub mod rng;

use blake2::Blake2s;
use rng::FiatShamirRng;

use ark_ff::{FftField, FftParameters, Field};

use ark_poly_commit::{LabeledCommitment, LabeledPolynomial, PolynomialCommitment};

use ark_poly::{
    domain::{EvaluationDomain, MixedRadixEvaluationDomain, Radix2EvaluationDomain},
    evaluations::univariate::Evaluations,
    univariate::DensePolynomial,
    Polynomial,
};

use ark_std::rand::RngCore;
use std::iter::{self, once};
use std::marker::PhantomData;
use thiserror::Error;

use mpc_trait::MpcWire;
use std::collections::HashMap;

pub struct PlonkCircuit<F: Field> {
    n_vars: u32,
    pub_vars: HashMap<Var, String>,
    prods: Vec<(Var, Var, Var)>,
    sums: Vec<(Var, Var, Var)>,
    values: Option<Vec<F>>,
}

type Var = u32;

impl<F: Field> PlonkCircuit<F> {
    pub fn new(values: bool) -> Self {
        Self {
            n_vars: 0,
            pub_vars: HashMap::new(),
            prods: Vec::new(),
            sums: Vec::new(),
            values: if values { Some(Vec::new()) } else { None },
        }
    }
    pub fn new_var(&mut self, value: impl FnOnce() -> F) -> Var {
        self.n_vars += 1;
        self.values.as_mut().map(|v| v.push(value()));
        self.n_vars - 1
    }
    pub fn publicize_var(&mut self, v: Var, name: String) {
        if let Some(old_name) = self.pub_vars.insert(v, name) {
            panic!(
                "Variable {} was already public as {:?}, but is now being bound to {:?}",
                v, old_name, self.pub_vars[&v]
            );
        }
    }
    pub fn new_sum(&mut self, a: Var, b: Var) -> Var {
        self.values.as_mut().map(|v| {
            let o = v[a as usize] + v[b as usize];
            v.push(o);
        });
        self.sums.push((a, b, self.n_vars));
        self.n_vars += 1;
        self.n_vars - 1
    }
    pub fn new_prod(&mut self, a: Var, b: Var) -> Var {
        self.values.as_mut().map(|v| {
            let o = v[a as usize] * v[b as usize];
            v.push(o);
        });
        self.prods.push((a, b, self.n_vars));
        self.n_vars += 1;
        self.n_vars - 1
    }
    pub fn new_pub_var(&mut self, value: impl FnOnce() -> F, name: String) -> Var {
        let v = self.new_var(value);
        self.publicize_var(v, name);
        v
    }
    pub fn n_gates(&self) -> usize {
        self.prods.len() + self.sums.len()
    }
    pub fn pad_to_power_of_2(&mut self) {
        let n = self.n_gates().next_power_of_two();
        assert!(self.n_vars > 0, "Cannot pad an empty circuit!");
        for _ in self.n_gates()..n {
            let v = self.n_vars - 1;
            self.new_sum(v, v);
        }
        assert!(self.n_gates().is_power_of_two());
    }
    pub fn new_squaring_circuit(steps: usize, start: Option<F>) -> Self {
        let mut self_ = PlonkCircuit::new(start.is_some());
        let mut v = self_.new_var(|| start.unwrap());
        for _ in 0..steps {
            v = self_.new_prod(v, v);
        }
        self_.pad_to_power_of_2();
        self_.publicize_var(v, "out".to_owned());
        self_
    }
}

pub struct CircuitLayout<F: FftField> {
    /// Wiring permutation polynomial
    w: DensePolynomial<F>,
    /// Gate selection polynomial
    s: DensePolynomial<F>,
    /// Map from variables to indices in the layout
    vars_to_indices: HashMap<u32, Vec<usize>>,
    /// Public variables
    public_indices: HashMap<String, usize>,
    /// Wire value polynomial
    p: Option<DensePolynomial<F>>,
    /// Domains over which the polynomials have meaning
    domains: Domains<F>,
}

impl<F: FftField> CircuitLayout<F> {
    pub fn from_circuit(c: &PlonkCircuit<F>, domains: &Domains<F>) -> Self {
        // Our layout is products followed by sums

        // Start with gate selector polynomial
        let gate_selector_evals = Evaluations::<F, Radix2EvaluationDomain<F>>::from_vec_and_domain(
            iter::repeat(F::zero())
                .take(c.prods.len())
                .chain(iter::repeat(F::one()).take(c.sums.len()))
                .collect(),
            domains.gates.clone(),
        );

        // Get powers of w for wire permuation poly
        let n_wires = c.n_gates() * 3;
        let wire_g = domains.wires.group_gen;
        let wire_g_pows: Vec<F> = iter::successors(Some(F::one()), |f| Some(wire_g * f))
            .take(n_wires)
            .collect();
        // Manifest layout
        let var_layout: Vec<u32> = c
            .prods
            .iter()
            .chain(c.sums.iter())
            .flat_map(|(in0, in1, out)| vec![*in0, *in1, *out])
            .collect();
        // Assemble cycles
        let vars_to_indices = {
            let mut vars_to_indices: HashMap<u32, Vec<usize>> =
                (0..c.n_vars).map(|i| (i, Vec::new())).collect();
            for (i, v) in var_layout.iter().enumerate() {
                vars_to_indices.get_mut(v).unwrap().push(i);
            }
            vars_to_indices
        };
        // Write cycles into evaluations
        let mut wire_evals = Evaluations::<F, MixedRadixEvaluationDomain<F>>::from_vec_and_domain(
            vec![F::zero(); n_wires],
            domains.wires.clone(),
        );
        for (_var, indices) in &vars_to_indices {
            for i in 0..indices.len() {
                let i_next = (i + 1) % indices.len();
                wire_evals.evals[indices[i]] = wire_g_pows[indices[i_next]];
            }
        }

        // Compute P polynomial if needed
        let p = c.values.as_ref().map(|vals| {
            let mut p_evals = Evaluations::<F, MixedRadixEvaluationDomain<F>>::from_vec_and_domain(
                vec![F::zero(); n_wires],
                domains.wires.clone(),
            );
            for (var, indices) in &vars_to_indices {
                for i in indices {
                    p_evals.evals[*i] = vals[*var as usize];
                }
            }
            p_evals.interpolate()
        });
        CircuitLayout {
            w: wire_evals.interpolate(),
            s: gate_selector_evals.interpolate(),
            domains: domains.clone(),
            p,
            public_indices: c
                .pub_vars
                .iter()
                .filter_map(|(v, name)| {
                    vars_to_indices
                        .get(v)
                        .and_then(|is| is.first().map(|i| (name.clone(), *i)))
                })
                .collect(),
            vars_to_indices,
        }
    }

    /// Check that no wire is in more than `d` connections
    ///
    /// Used in testing
    pub fn check_connection_degree(&self, d: usize) {
        let n_wires = self.domains.wires.size();
        let wire_g = self.domains.wires.group_gen;
        let wire_g_pows: Vec<F> = iter::successors(Some(F::one()), |f| Some(wire_g * f))
            .take(n_wires)
            .collect();
        for (v, indices) in &self.vars_to_indices {
            let start = wire_g_pows[indices[0]];
            let mut cur = start;
            let mut cycle = false;
            for _ in 0..d {
                cur = self.w.evaluate(&cur);
                if cur == start {
                    cycle = true;
                    break;
                }
            }
            if !cycle {
                panic!(
                    "variable {} at {:?} did not cycle in {} steps",
                    v, indices, d
                )
            }
        }
    }

    fn evaluate_over_gates(
        &self,
        p: &DensePolynomial<F>,
    ) -> Evaluations<F, Radix2EvaluationDomain<F>> {
        let cs = p.coeffs.len();
        if cs <= self.domains.gates.size() {
            p.evaluate_over_domain_by_ref(self.domains.gates)
        } else if cs <= self.domains.wires.size() {
            Evaluations::from_vec_and_domain(
                p.evaluate_over_domain_by_ref(self.domains.wires)
                    .evals
                    .into_iter()
                    .enumerate()
                    .filter(|(i, _)| i % 3 == 0)
                    .map(|(_, v)| v)
                    .collect(),
                self.domains.gates,
            )
        } else {
            panic!(
                "Cannot evaluate polynomial with {} coefficients over gates domain",
                cs
            )
        }
    }

    fn check_inputs(&self, public_wires: &HashMap<String, F>) {
        if let Some(p) = &self.p {
            let wire_g = self.domains.wires.group_gen;
            for (variable, value) in public_wires {
                let idx = self
                    .public_indices
                    .get(variable)
                    .unwrap_or_else(|| panic!("Missing public wire {:?}", variable));
                assert_eq!(&p.evaluate(&wire_g.pow(&[*idx as u64])), value);
            }
        }
    }

    fn check_gates(&self) {
        let wire_g = self.domains.wires.group_gen;
        if let Some(p) = &self.p {
            let p_x_evals = self.evaluate_over_gates(p);
            let p_wx_evals = self.evaluate_over_gates(&shift(p.clone(), wire_g));
            let p_wwx_evals = self.evaluate_over_gates(&shift(p.clone(), wire_g * wire_g));
            let s_evals = self.evaluate_over_gates(&self.s);
            let a = &s_evals * &(&p_x_evals + &p_wx_evals);
            let b = &(&(&s_evals * &-F::one()) + &F::one()) * &(&p_x_evals * &p_wx_evals);
            let c = &a + &b;
            assert_eq!(c, p_wwx_evals);
        }
    }

    fn check_wiring(&self) {
        let n_wires = self.domains.wires.size();
        let wire_g = self.domains.wires.group_gen;
        let wire_g_pows: Vec<F> = iter::successors(Some(F::one()), |f| Some(wire_g * f))
            .take(self.domains.wires.size())
            .collect();
        if let Some(p) = &self.p {
            for i in 0..n_wires {
                let x = wire_g_pows[i];
                let p_of_x = p.evaluate(&x);
                let p_of_w_of_x = p.evaluate(&self.w.evaluate(&x));
                assert_eq!(
                    p_of_x, p_of_w_of_x,
                    "p(x) != p(w(x)) for x = {}, pin {}\n{} vs \n{}",
                    x, i, p_of_x, p_of_w_of_x
                );
            }
        }
    }

    pub fn check(&self, public_wires: &HashMap<String, F>) {
        self.check_gates();
        self.check_wiring();
        self.check_inputs(public_wires);
    }
}

/// Computes f(a*X) from a and f(X)
fn shift<F: FftField>(mut f: DensePolynomial<F>, a: F) -> DensePolynomial<F> {
    let mut s = F::one();
    for c in &mut f.coeffs {
        *c *= s;
        s *= a;
    }
    f
}

/// We assume a power-of-two number of gates.
/// We use a 2^r*3-sized domain for wires and a 2^r-sized domain for gates.
#[derive(Clone, Debug)]
pub struct Domains<F: FftField> {
    wires: MixedRadixEvaluationDomain<F>,
    gates: Radix2EvaluationDomain<F>,
}

impl<F: FftField> Domains<F> {
    pub fn from_circuit(c: &PlonkCircuit<F>) -> Self {
        assert_eq!(
            F::FftParams::SMALL_SUBGROUP_BASE,
            Some(3),
            "We require the scalar field's multiplicative group to have a subgroup of order 3"
        );
        let n = c.n_gates();
        let gates = Radix2EvaluationDomain::new(n).expect("gate domain");
        let wires = MixedRadixEvaluationDomain::new(3 * n).expect("wire domain");
        assert!(3 * gates.size() == wires.size());
        let wire_g = wires.group_gen;
        assert_eq!(wire_g * wire_g * wire_g, gates.group_gen);
        Domains { gates, wires }
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
    fn domains() {
        for steps in &[1, 15, 1024, 12341] {
            let c = PlonkCircuit::<F>::new_squaring_circuit(*steps, None);
            let _d = Domains::from_circuit(&c);
        }

        // should still work, even with witness
        for steps in &[1, 15, 1024, 12341] {
            let c = PlonkCircuit::<F>::new_squaring_circuit(*steps, Some(F::from(0u64)));
            let _d = Domains::from_circuit(&c);
        }
    }

    #[test]
    fn circuit_polys() {
        for steps in &[1, 3] {
            let c = PlonkCircuit::<F>::new_squaring_circuit(*steps, None);
            let d = Domains::from_circuit(&c);
            let polys = CircuitLayout::from_circuit(&c, &d);
            polys.check_connection_degree(3);
        }
    }
    #[test]
    fn circuit_check() {
        for steps in &[1, 3] {
            let start = F::from(2u64);
            let c = PlonkCircuit::<F>::new_squaring_circuit(*steps, Some(start));
            let res = (0..*steps).fold(start, |a, _| a * a);
            let public: HashMap<String, F> = vec![("out".to_owned(), res)].into_iter().collect();
            let d = Domains::from_circuit(&c);
            let polys = CircuitLayout::from_circuit(&c, &d);
            polys.check_connection_degree(3);
            polys.check(&public);
        }
    }
}
