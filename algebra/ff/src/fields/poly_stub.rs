use super::Field;
use ark_std::{borrow::Cow, vec::Vec};

/// Represents either a sparse polynomial or a dense one.
#[derive(Clone, Debug)]
pub enum DenseOrSparsePolynomial<'a, F: Field> {
    /// Represents the case where `self` is a sparse polynomial
    SPolynomial(Cow<'a, SparsePolynomial<F>>),
    /// Represents the case where `self` is a dense polynomial
    DPolynomial(Cow<'a, DensePolynomial<F>>),
}

/// Stores a polynomial in coefficient form.
#[derive(Clone, Default, Debug)]
pub struct DensePolynomial<F: Field> {
    /// The coefficient of `x^i` is stored at location `i` in `self.coeffs`.
    pub coeffs: Vec<F>,
}

/// Stores a sparse polynomial in coefficient form.
#[derive(Clone, Default, Debug)]
pub struct SparsePolynomial<F: Field> {
    /// The coefficient a_i of `x^i` is stored as (i, a_i) in `self.coeffs`.
    /// the entries in `self.coeffs` *must*  be sorted in increasing order of
    /// `i`.
    pub coeffs: Vec<(usize, F)>,
}
