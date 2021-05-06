//! Data structures for the plonk proof system
#![allow(dead_code)]

use ark_poly_commit::{PolynomialCommitment, LabeledCommitment, LabeledPolynomial};
use ark_poly::univariate::DensePolynomial;
use ark_ff::FftField;
use std::marker::PhantomData;

/// Check that S(X)*(P(X) + P(wX)) + (1-S(X))*P(X)*P(WX) - P(WWX) = Q(X)*Z(X)
/// where Z vanishes on the gate domain, and Q is existential
pub struct GateProof<F, C, O> {
    /// Q commitment
    pub q_cmt: C,
    /// Verifier query point
    pub x: F,
    /// S(x) proof
    pub s_open: O,
    /// Q(x) proof
    pub q_open: O,
    /// P(x) proof
    pub p_open: O,
    /// P(w*x) proof
    pub p_w_open: O,
    /// P(w*w*x) proof
    pub p_w2_open: O,
}

/// Check that P(X) agree with v(X) for the public wires
/// via P(X) - v(X) = Q(X)*Z(X)
/// where Z vanishes on the public wires
pub struct PublicProof<C, O> {
    /// Q commitment
    pub q_cmt: C,
    /// Q(x) proof
    pub q_open: O,
    /// P(x) proof
    pub p_open: O,
}

/// Proof that some polynomial f has a product pi over a domain
pub struct ProductProof<C, O> {
    /// t (partial products) commitment
    pub t_cmt: C,
    /// quotient commitment
    pub q_cmt: C,
    /// t(w^{k-1}) opening
    pub t_wk_open: O,
    /// t(r) opening
    pub t_r_open: O,
    /// t(w*r) opening
    pub t_wr_open: O,
    /// f(w*r) opening
    pub f_wr_open: O,
    /// q(r) opening
    pub q_r_open: O,
}

/// Check that P(X) = P(W(X)) on the wires
/// via P(X) - v(X) = Q(X)*Z(X)
/// where Z vanishes on the public wires
pub struct WiringProof<C, O> {
    /// commitment to L_1
    pub l1_cmt: C,
    /// proof that L_1 multiplies to 1
    /// over the wire wire domain
    pub l1_prod_pf: ProductProof<C, O>,
    /// commitment to L_2's quotient over the wire domain
    pub l2_q_cmt: C,
    /// p(x) openning
    pub p_x_open: O,
    /// w(x) openning
    pub w_x_open: O,
    /// L_1(x) openning
    pub l1_x_open: O,
    /// L_2(x) openning
    pub l2_q_x_open: O,
}

/// Plonk proof
pub struct Proof<F: FftField, PC: PolynomialCommitment<F, DensePolynomial<F>>> {
    /// Commitment to P
    pub p_cmt: PC::Commitment,
    /// Proof of wiring
    pub wiring: WiringProof<PC::Commitment, (F, PC::Proof)>,
    /// Proof of gates
    pub gates: GateProof<F, PC::Commitment, (F, PC::Proof)>,
    /// Proof of gates
    pub public: PublicProof<PC::Commitment, (F, PC::Proof)>,
    /// Phantom polynomial commitment
    pub _pc: PhantomData<PC>,
}

pub struct PubParams<F: FftField, PC: PolynomialCommitment<F, DensePolynomial<F>>> {
    pub w: LabeledPolynomial<F, DensePolynomial<F>>,
    pub w_cmt: LabeledCommitment<PC::Commitment>,
    pub w_rand: PC::Randomness,
    pub s: LabeledPolynomial<F, DensePolynomial<F>>,
    pub s_cmt: LabeledCommitment<PC::Commitment>,
    pub s_rand: PC::Randomness,
    pub _pc: PhantomData<PC>,
}
