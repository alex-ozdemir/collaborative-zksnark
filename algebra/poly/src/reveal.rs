use crate::domain::{EvaluationDomain, GeneralEvaluationDomain};
use crate::evaluations::univariate::Evaluations;
use crate::univariate::DensePolynomial;
use ark_ff::{Field, PrimeField};
use mpc_algebra::ss::*;
use mpc_trait::{struct_reveal_simp_impl, struct_mpc_wire_simp_impl, Reveal, MpcWire};

impl<E: PrimeField, S: ScalarShare<E>> Reveal for DensePolynomial<MpcField<E, S>> {
    type Base = DensePolynomial<E>;
    struct_reveal_simp_impl!(DensePolynomial; coeffs);
}

impl<F: PrimeField, S: ScalarShare<F>> Reveal for Evaluations<MpcField<F, S>> {
    type Base = Evaluations<F>;

    fn reveal(self) -> Self::Base {
        Evaluations::from_vec_and_domain(
            self.evals.reveal(),
            GeneralEvaluationDomain::new(self.domain.size()).unwrap(),
        )
    }

    fn from_add_shared(b: Self::Base) -> Self {
        Evaluations::from_vec_and_domain(
            Reveal::from_add_shared(b.evals),
            GeneralEvaluationDomain::new(b.domain.size()).unwrap(),
        )
    }

    fn from_public(b: Self::Base) -> Self {
        Evaluations::from_vec_and_domain(
            Reveal::from_public(b.evals),
            GeneralEvaluationDomain::new(b.domain.size()).unwrap(),
        )
    }
}

impl<E: Field> MpcWire for DensePolynomial<E> {
    struct_mpc_wire_simp_impl!(DensePolynomial; coeffs);
}
