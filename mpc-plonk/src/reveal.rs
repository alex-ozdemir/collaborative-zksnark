use ark_ec::PairingEngine;
use ark_poly_commit::marlin_pc;
use mpc_algebra::*;

use crate::*;

impl<C: Reveal, O: Reveal> Reveal for GateProof<C, O> {
    type Base = GateProof<C::Base, O::Base>;
    struct_reveal_impl!(GateProof<C, O>, GateProof;
        (C, q_cmt), (O, s_open), (O, q_open), (O, p_open), (O, p_w_open), (O, p_w2_open));
}

impl<C: Reveal, O: Reveal> Reveal for PublicProof<C, O> {
    type Base = PublicProof<C::Base, O::Base>;
    struct_reveal_impl!(PublicProof<C, O>, PublicProof;
        (C, q_cmt), (O, q_open), (O, p_open));
}

impl<C: Reveal, O: Reveal> Reveal for ProductProof<C, O> {
    type Base = ProductProof<C::Base, O::Base>;
    struct_reveal_impl!(ProductProof<C, O>, ProductProof;
        (C, q_cmt), (C, t_cmt), (O, t_wk_open), (O, t_r_open), (O, t_wr_open), (O, f_wr_open), (O, q_r_open));
}

impl<C: Reveal, O: Reveal> Reveal for WiringProof<C, O> {
    type Base = WiringProof<C::Base, O::Base>;
    struct_reveal_impl!(WiringProof<C, O>, WiringProof;
        (C, l1_cmt), (ProductProof<C, O>, l1_prod_pf), (C, l2_q_cmt), (O, p_x_open), (O, w_x_open), (O, l1_x_open), (O, l2_q_x_open));
}

impl<F: Reveal, C: Reveal, O: Reveal> Reveal for Proof<F, C, O> {
    type Base = Proof<F::Base, C::Base, O::Base>;
    struct_reveal_impl!(Proof<F, PC>, Proof;
        (C, p_cmt),
        (WiringProof<C, (F, O)>, wiring),
        (GateProof<C, (F, O)>, gates),
        (PublicProof<C, (F, O)>, public)
    );
}

impl<E: PairingEngine, S: PairingShare<E>> Reveal
    for ProverKey<
        <MpcPairingEngine<E, S> as PairingEngine>::Fr,
        marlin_pc::Commitment<MpcPairingEngine<E, S>>,
        marlin_pc::CommitterKey<MpcPairingEngine<E, S>>,
    >
{
    type Base = ProverKey<
        <E as PairingEngine>::Fr,
        marlin_pc::Commitment<E>,
        marlin_pc::CommitterKey<E>,
    >;
    struct_reveal_simp_impl!(ProverKey; w, s, w_cmt, s_cmt, pc_ck);
}
