use mpc_algebra::ss::*;
use ark_ec::PairingEngine;
use mpc_trait::{struct_reveal_impl, struct_reveal_simp_impl, Reveal};
use ark_poly_commit::marlin_pc;

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

//type C = ark_poly_commit::marlin_pc::Commitment<E>;
//type CK = ark_poly_commit::marlin_pc::CommitterKey<E>;
//type MC = ark_poly_commit::marlin_pc::Commitment<ME>;
//type MCK = ark_poly_commit::marlin_pc::CommitterKey<ME>;
//type P = ark_poly_commit::kzg10::Proof<E>;
//type MP = ark_poly_commit::kzg10::Proof<ME>;
//type O = (Fr, P);
//type MO = (MFr, MP);
//pub fn pub_open(o: MO) -> O {
//    (o.0.reveal(), pc_reveal::pf_from_mpc(o.1))
//}
//pub fn pub_gate_pf(pf: GateProof<MC, MO>) -> GateProof<C, O> {
//    GateProof {
//        q_cmt: pc_reveal::comm_publicize(pf.q_cmt),
//        s_open: pub_open(pf.s_open),
//        q_open: pub_open(pf.q_open),
//        p_open: pub_open(pf.p_open),
//        p_w_open: pub_open(pf.p_w_open),
//        p_w2_open: pub_open(pf.p_w2_open),
//    }
//}
//pub fn pub_public_pf(pf: PublicProof<MC, MO>) -> PublicProof<C, O> {
//    PublicProof {
//        q_cmt: pc_reveal::comm_publicize(pf.q_cmt),
//        q_open: pub_open(pf.q_open),
//        p_open: pub_open(pf.p_open),
//    }
//}
//pub fn pub_prod_pf(pf: ProductProof<MC, MO>) -> ProductProof<C, O> {
//    ProductProof {
//        t_cmt: pc_reveal::comm_publicize(pf.t_cmt),
//        q_cmt: pc_reveal::comm_publicize(pf.q_cmt),
//        t_wk_open: pub_open(pf.t_wk_open),
//        t_r_open: pub_open(pf.t_r_open),
//        t_wr_open: pub_open(pf.t_wr_open),
//        f_wr_open: pub_open(pf.f_wr_open),
//        q_r_open: pub_open(pf.q_r_open),
//    }
//}
//pub fn pub_wiring_pf(pf: WiringProof<MC, MO>) -> WiringProof<C, O> {
//    WiringProof {
//        l1_cmt: pc_reveal::comm_publicize(pf.l1_cmt),
//        l1_prod_pf: pub_prod_pf(pf.l1_prod_pf),
//        l2_q_cmt: pc_reveal::comm_publicize(pf.l2_q_cmt),
//        p_x_open: pub_open(pf.p_x_open),
//        w_x_open: pub_open(pf.w_x_open),
//        l1_x_open: pub_open(pf.l1_x_open),
//        l2_q_x_open: pub_open(pf.l2_q_x_open),
//    }
//}
//pub fn pub_pf(pf: Proof<MFr, MC, MP>) -> Proof<Fr, C, P> {
//    Proof {
//        p_cmt: pc_reveal::comm_publicize(pf.p_cmt),
//        wiring: pub_wiring_pf(pf.wiring),
//        gates: pub_gate_pf(pf.gates),
//        public: pub_public_pf(pf.public),
//    }
//}
//pub fn obs_pk(pk: ProverKey<Fr, C, CK>) -> ProverKey<MFr, MC, MCK> {
//    ProverKey {
//        w: pc_reveal::obs_labeled_poly(pk.w),
//        s: pc_reveal::obs_labeled_poly(pk.s),
//        w_cmt: pc_reveal::obs_labeled_commitment(pk.w_cmt),
//        s_cmt: pc_reveal::obs_labeled_commitment(pk.s_cmt),
//        pc_ck: pc_reveal::obs_ck(pk.pc_ck),
//    }
//}
