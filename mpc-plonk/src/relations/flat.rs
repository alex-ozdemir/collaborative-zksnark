use ark_ff::{FftField, FftParameters};
use std::collections::HashMap;

use ark_poly::{
    domain::{EvaluationDomain, MixedRadixEvaluationDomain, Radix2EvaluationDomain},
    evaluations::univariate::Evaluations,
    univariate::DensePolynomial,
    Polynomial,
    UVPolynomial,
};

use std::iter;

use crate::util::shift;

use super::structured::PlonkCircuit;

#[derive(Clone)]
pub struct CircuitLayout<F: FftField> {
    /// Wiring permutation polynomial
    pub w: DensePolynomial<F>,
    /// Gate selection polynomial
    pub s: DensePolynomial<F>,
    /// Map from variables to indices in the layout
    pub vars_to_indices: HashMap<u32, Vec<usize>>,
    /// Public variables
    pub public_indices: HashMap<String, usize>,
    /// Wire value polynomial
    pub p: Option<DensePolynomial<F>>,
    /// Domains over which the polynomials have meaning
    pub domains: Domains<F>,
}

impl<F: FftField> CircuitLayout<F> {
    pub fn from_circuit(c: &PlonkCircuit<F>) -> Self {
        let domains = Domains::from_circuit(c);
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
            #[cfg(debug_assertions)]
            {
                println!("Plonk W evals:");
                let mut p = wire_evals.clone();
                for (i, e) in p.evals.iter_mut().enumerate() {
                    println!("{}: {}", i, e);
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
            #[cfg(debug_assertions)]
            {
                println!("Plonk P evals:");
                let mut p = p_evals.clone();
                for (i, e) in p.evals.iter_mut().enumerate() {
                    e.publicize();
                    println!("{}: {}", i, e);
                }
            }
            p_evals.interpolate()
        });
        let w = wire_evals.interpolate();
            #[cfg(debug_assertions)]
            {
                println!("Plonk w coeffs:");
                let mut p = w.clone();
                for (i, e) in p.coeffs.iter_mut().enumerate() {
                    println!("{}: {}", i, e);
                }
            }
        CircuitLayout {
            w,
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

    pub fn degree_bound(&self) -> usize {
        self.domains.wires.size() * 2 - 1
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

    pub fn evaluate_over_gates(
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

    /// Returns the monic polynomial which vanishes at the input pins
    pub fn vanishing_poly_on_inputs(&self) -> DensePolynomial<F> {
        let roots: Vec<F> = self
            .public_indices
            .iter()
            .map(|(_, i)| self.domains.wires.element(*i))
            .collect();
        poly_from_roots(&roots)
    }

    pub fn inputs_poly(
        &self,
        inputs: &HashMap<String, F>,
    ) -> DensePolynomial<F> {
        assert!(inputs.len() > 0);
        let points: Vec<(F, F)> = inputs
            .iter()
            .map(|(var, val)| {
                let idx = self.public_indices[var];
                let x = self.domains.wires.element(idx);
                (x, *val)
            })
            .collect();
        crate::util::interpolate(&points)
    }


    pub fn check(&self, public_wires: &HashMap<String, F>) {
        self.check_gates();
        self.check_wiring();
        self.check_inputs(public_wires);
    }
}

/// We assume a power-of-two number of gates.
/// We use a 2^r*3-sized domain for wires and a 2^r-sized domain for gates.
#[derive(Clone, Debug)]
pub struct Domains<F: FftField> {
    pub wires: MixedRadixEvaluationDomain<F>,
    pub gates: Radix2EvaluationDomain<F>,
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

fn poly_from_roots<F: FftField>(roots: &[F]) -> DensePolynomial<F> {
    roots.iter().fold(
        DensePolynomial::from_coefficients_vec(vec![F::one()]),
        |acc, r| acc.naive_mul(&DensePolynomial::from_coefficients_vec(vec![-*r, F::one()])),
    )
}



#[cfg(test)]
mod tests {
    use super::*;
    type F = ark_bls12_377::Fr;

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
            let polys = CircuitLayout::from_circuit(&c);
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
            let polys = CircuitLayout::from_circuit(&c);
            polys.check_connection_degree(3);
            polys.check(&public);
        }
    }
}
