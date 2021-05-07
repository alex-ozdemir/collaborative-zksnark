//! Data structures for the plonk proof system
#![allow(dead_code)]

use ark_ff::Field;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::{LabeledCommitment, LabeledPolynomial, PCCommitment};
use mpc_trait::{struct_mpc_wire_impl, MpcWire};

/// Check that S(X)*(P(X) + P(wX)) + (1-S(X))*P(X)*P(WX) - P(WWX) = Q(X)*Z(X)
/// where Z vanishes on the gate domain, and Q is existential
#[derive(Clone)]
pub struct GateProof<C, O> {
    /// Q commitment
    pub q_cmt: C,
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
#[derive(Clone)]
pub struct PublicProof<C, O> {
    /// Q commitment
    pub q_cmt: C,
    /// Q(x) proof
    pub q_open: O,
    /// P(x) proof
    pub p_open: O,
}

/// Proof that some polynomial f has a product pi over a domain
#[derive(Clone)]
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
#[derive(Clone)]
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
#[derive(Clone)]
pub struct Proof<F, C, O> {
    /// Commitment to P
    pub p_cmt: C,
    /// Proof of wiring
    pub wiring: WiringProof<C, (F, O)>,
    /// Proof of gates
    pub gates: GateProof<C, (F, O)>,
    /// Proof of gates
    pub public: PublicProof<C, (F, O)>,
}

#[derive(Clone)]
pub struct ProverKey<F: Field, C: PCCommitment, PcCk> {
    pub w: LabeledPolynomial<F, DensePolynomial<F>>,
    pub w_cmt: LabeledCommitment<C>,
    pub s: LabeledPolynomial<F, DensePolynomial<F>>,
    pub s_cmt: LabeledCommitment<C>,
    pub pc_ck: PcCk,
}

#[derive(Clone)]
pub struct VerifierKey<C: PCCommitment, PcVk> {
    pub w_cmt: LabeledCommitment<C>,
    pub s_cmt: LabeledCommitment<C>,
    pub pc_vk: PcVk,
}

impl<C: MpcWire, O: MpcWire> MpcWire for GateProof<C, O> {
    struct_mpc_wire_impl!(GateProof<C, O>;
        (C, q_cmt), (O, s_open), (O, q_open), (O, p_open), (O, p_w_open), (O, p_w2_open));
}

impl<C: MpcWire, O: MpcWire> MpcWire for PublicProof<C, O> {
    struct_mpc_wire_impl!(PublicProof<C, O>;
        (C, q_cmt), (O, q_open), (O, p_open));
}
impl<C: MpcWire, O: MpcWire> MpcWire for ProductProof<C, O> {
    struct_mpc_wire_impl!(ProductProof<C, O>;
        (C, q_cmt), (C, t_cmt), (O, t_wk_open), (O, t_r_open), (O, t_wr_open), (O, f_wr_open), (O, q_r_open));
}

impl<C: MpcWire, O: MpcWire> MpcWire for WiringProof<C, O> {
    struct_mpc_wire_impl!(WiringProof<C, O>;
        (C, l1_cmt), (ProductProof<C, O>, l1_prod_pf), (C, l2_q_cmt), (O, p_x_open), (O, w_x_open), (O, l1_x_open), (O, l2_q_x_open));
}

impl<F: MpcWire, C: MpcWire, O: MpcWire> MpcWire for Proof<F, C, O> {
    struct_mpc_wire_impl!(Proof<F, PC>;
        (C, p_cmt),
        (WiringProof<C, (F, O)>, wiring),
        (GateProof<C, (F, O)>, gates),
        (PublicProof<C, (F, O)>, public)
    );
}

// impl<F: MpcWire, C: MpcWire, PcCk: MpcWire> MpcWire for ProverKey<F, C, PcCk> {
//     struct_mpc_wire_impl!(ProverKey<F, C, PcCk>;
//         (C, p_cmt),
//         (WiringProof<C, (F, O)>, wiring),
//         (GateProof<C, (F, O)>, gates),
//         (PublicProof<C, (F, O)>, public)
//     );
// }
// 
// impl<F: Reveal, C: Reveal, O: Reveal> Reveal for Proof<F, C, O> {
//     type Base = Proof<F::Base, C::Base, O::Base>;
//     struct_reveal_impl!(Proof<F, PC>, Proof;
//         (C, p_cmt),
//         (WiringProof<C, (F, O)>, wiring),
//         (GateProof<C, (F, O)>, gates),
//         (PublicProof<C, (F, O)>, public)
//     );
// }

