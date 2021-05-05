///! Extra algebra utils

use ark_ff::FftField;
use ark_poly::univariate::DensePolynomial;

/// Computes f(a*X) from a and f(X)
pub fn shift<F: FftField>(mut f: DensePolynomial<F>, a: F) -> DensePolynomial<F> {
    let mut s = F::one();
    for c in &mut f.coeffs {
        *c *= s;
        s *= a;
    }
    f
}

