use ark_ff::{Field};
use crate::univariate::DensePolynomial;
use mpc_trait::{struct_mpc_wire_simp_impl, MpcWire};

impl<E: Field> MpcWire for DensePolynomial<E> {
    struct_mpc_wire_simp_impl!(DensePolynomial; coeffs);
}
