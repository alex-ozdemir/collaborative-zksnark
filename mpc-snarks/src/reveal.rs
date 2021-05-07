use ark_marlin::Marlin;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::marlin_pc::MarlinKZG10;
use blake2::Blake2s;
use mpc_algebra::{
    MpcCurve, MpcCurve2, MpcMulVal, MpcPairingEngine, MpcPrepCurve, MpcPrepCurve2, MpcVal,
};
use mpc_trait::MpcWire;

pub trait Reveal {
    type Base;
    fn reveal(self) -> Self::Base;
    fn obscure(b: Self::Base) -> Self;
}

impl<T: Reveal> Reveal for Vec<T> {
    type Base = Vec<T::Base>;
    fn reveal(self) -> Self::Base {
        self.into_iter().map(|x| x.reveal()).collect()
    }
    fn obscure(other: Self::Base) -> Self {
        other
            .into_iter()
            .map(|x| <T as Reveal>::obscure(x))
            .collect()
    }
}

impl<T: Reveal> Reveal for Option<T> {
    type Base = Option<T::Base>;
    fn reveal(self) -> Self::Base {
        self.map(|x| x.reveal())
    }
    fn obscure(other: Self::Base) -> Self {
        other.map(|x| <T as Reveal>::obscure(x))
    }
}

impl<A: Reveal, B: Reveal> Reveal for (A, B) {
    type Base = (A::Base, B::Base);
    fn reveal(self) -> Self::Base {
        (self.0.reveal(), self.1.reveal())
    }
    fn obscure(other: Self::Base) -> Self {
        (
            <A as Reveal>::obscure(other.0),
            <B as Reveal>::obscure(other.1),
        )
    }
}

#[macro_export]
macro_rules! struct_reveal_impl {
    ($s:ty, $con:tt ; $( ($x_ty:ty, $x:tt) ),*) => {
        fn reveal(self) -> Self::Base {
            $con {
                $(
                    $x: self.$x.reveal(),
                )*
            }
        }
        fn obscure(other: Self::Base) -> Self {
            $con {
                $(
                    $x: <$x_ty as Reveal>::obscure(other.$x),
                )*
            }
        }
    }
}

macro_rules! wrapper_reveal_impl {
    ($ty:ident) => {
        impl<
                F: for<'a> std::ops::AddAssign<&'a F>
                    + ark_serialize::CanonicalSerialize
                    + ark_serialize::CanonicalDeserialize
                    + Clone
                    + std::cmp::PartialEq,
            > Reveal for $ty<F>
        {
            type Base = F;
            fn reveal(self) -> Self::Base {
                self.publicize_unwrap()
            }
            fn obscure(b: Self::Base) -> Self {
                Self::from_public(b)
            }
        }
    };
}
macro_rules! mult_wrapper_reveal_impl {
    ($ty:ident) => {
        impl<
                F: for<'a> std::ops::MulAssign<&'a F>
                    + ark_serialize::CanonicalSerialize
                    + ark_serialize::CanonicalDeserialize
                    + Clone
                    + std::cmp::PartialEq,
            > Reveal for $ty<F>
        {
            type Base = F;
            fn reveal(self) -> Self::Base {
                self.publicize_unwrap()
            }
            fn obscure(b: Self::Base) -> Self {
                Self::from_public(b)
            }
        }
    };
}
wrapper_reveal_impl!(MpcVal);
wrapper_reveal_impl!(MpcCurve);
wrapper_reveal_impl!(MpcCurve2);
mult_wrapper_reveal_impl!(MpcMulVal);

type Fr = ark_bls12_377::Fr;
type E = ark_bls12_377::Bls12_377;
type ME = MpcPairingEngine<ark_bls12_377::Bls12_377>;
type MFr = MpcVal<Fr>;
type PC = MarlinKZG10<E, DensePolynomial<Fr>>;
type MpcMarlinKZG10 = MarlinKZG10<ME, DensePolynomial<MFr>>;
type LocalMarlinKZG10 = MarlinKZG10<E, DensePolynomial<Fr>>;
type LocalMarlin = Marlin<Fr, LocalMarlinKZG10, Blake2s>;
type MpcMarlin = Marlin<MFr, MpcMarlinKZG10, Blake2s>;

pub mod plonk {
    use super::*;
    use mpc_plonk::*;

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
    type C = ark_poly_commit::marlin_pc::Commitment<E>;
    type CK = ark_poly_commit::marlin_pc::CommitterKey<E>;
    type MC = ark_poly_commit::marlin_pc::Commitment<ME>;
    type MCK = ark_poly_commit::marlin_pc::CommitterKey<ME>;
    type P = ark_poly_commit::kzg10::Proof<E>;
    type MP = ark_poly_commit::kzg10::Proof<ME>;
    type O = (Fr, P);
    type MO = (MFr, MP);
    pub fn pub_open(o: MO) -> O {
        (o.0.publicize_unwrap(), super::pc::pf_from_mpc(o.1))
    }
    pub fn pub_gate_pf(pf: GateProof<MC, MO>) -> GateProof<C, O> {
        GateProof {
            q_cmt: super::pc::comm_publicize(pf.q_cmt),
            s_open: pub_open(pf.s_open),
            q_open: pub_open(pf.q_open),
            p_open: pub_open(pf.p_open),
            p_w_open: pub_open(pf.p_w_open),
            p_w2_open: pub_open(pf.p_w2_open),
        }
    }
    pub fn pub_public_pf(pf: PublicProof<MC, MO>) -> PublicProof<C, O> {
        PublicProof {
            q_cmt: super::pc::comm_publicize(pf.q_cmt),
            q_open: pub_open(pf.q_open),
            p_open: pub_open(pf.p_open),
        }
    }
    pub fn pub_prod_pf(pf: ProductProof<MC, MO>) -> ProductProof<C, O> {
        ProductProof {
            t_cmt: super::pc::comm_publicize(pf.t_cmt),
            q_cmt: super::pc::comm_publicize(pf.q_cmt),
            t_wk_open: pub_open(pf.t_wk_open),
            t_r_open: pub_open(pf.t_r_open),
            t_wr_open: pub_open(pf.t_wr_open),
            f_wr_open: pub_open(pf.f_wr_open),
            q_r_open: pub_open(pf.q_r_open),
        }
    }
    pub fn pub_wiring_pf(pf: WiringProof<MC, MO>) -> WiringProof<C, O> {
        WiringProof {
            l1_cmt: super::pc::comm_publicize(pf.l1_cmt),
            l1_prod_pf: pub_prod_pf(pf.l1_prod_pf),
            l2_q_cmt: super::pc::comm_publicize(pf.l2_q_cmt),
            p_x_open: pub_open(pf.p_x_open),
            w_x_open: pub_open(pf.w_x_open),
            l1_x_open: pub_open(pf.l1_x_open),
            l2_q_x_open: pub_open(pf.l2_q_x_open),
        }
    }
    pub fn pub_pf(pf: Proof<MFr, MC, MP>) -> Proof<Fr, C, P> {
        Proof {
            p_cmt: super::pc::comm_publicize(pf.p_cmt),
            wiring: pub_wiring_pf(pf.wiring),
            gates: pub_gate_pf(pf.gates),
            public: pub_public_pf(pf.public),
        }
    }
    pub fn obs_pk(pk: ProverKey<Fr, C, CK>) -> ProverKey<MFr, MC, MCK> {
        ProverKey {
            w: super::pc::obs_labeled_poly(pk.w),
            s: super::pc::obs_labeled_poly(pk.s),
            w_cmt: super::pc::obs_labeled_commit(pk.w_cmt),
            s_cmt: super::pc::obs_labeled_commit(pk.s_cmt),
            pc_ck: super::pc::obs_ck(pk.pc_ck),
        }
    }
}

pub mod pc {
    use super::*;
    use ark_poly::UVPolynomial;
    use ark_poly_commit::marlin_pc::*;
    use ark_poly_commit::{LabeledCommitment, LabeledPolynomial};
    pub fn comm_publicize(
        pf: ark_poly_commit::marlin_pc::Commitment<ME>,
    ) -> ark_poly_commit::marlin_pc::Commitment<E> {
        ark_poly_commit::marlin_pc::Commitment {
            comm: commit_from_mpc(pf.comm),
            shifted_comm: pf.shifted_comm.map(commit_from_mpc),
        }
    }

    pub fn commit_from_mpc<'a>(
        p: ark_poly_commit::kzg10::Commitment<MpcPairingEngine<ark_bls12_377::Bls12_377>>,
    ) -> ark_poly_commit::kzg10::Commitment<ark_bls12_377::Bls12_377> {
        ark_poly_commit::kzg10::Commitment(p.0.publicize_unwrap())
    }

    pub fn pf_from_mpc<'a>(
        pf: ark_poly_commit::kzg10::Proof<MpcPairingEngine<ark_bls12_377::Bls12_377>>,
    ) -> ark_poly_commit::kzg10::Proof<ark_bls12_377::Bls12_377> {
        ark_poly_commit::kzg10::Proof {
            w: pf.w.publicize_unwrap(),
            random_v: pf.random_v.map(MpcVal::publicize_unwrap),
        }
    }

    pub fn batch_pf_publicize(
        pf: ark_poly_commit::BatchLCProof<MFr, DensePolynomial<MFr>, MpcMarlinKZG10>,
    ) -> ark_poly_commit::BatchLCProof<Fr, DensePolynomial<Fr>, LocalMarlinKZG10> {
        ark_poly_commit::BatchLCProof {
            proof: pf.proof.into_iter().map(pf_from_mpc).collect(),
            evals: pf
                .evals
                .map(|e| e.into_iter().map(MpcVal::publicize_unwrap).collect()),
        }
    }

    pub use mpc_algebra::poly::pc::lift_ck as obs_ck;
    pub use mpc_algebra::poly::pc::lift_labeled_commitment as obs_labeled_commit;

    pub fn obs_poly(p: DensePolynomial<Fr>) -> DensePolynomial<MFr> {
        DensePolynomial::from_coefficients_vec(
            p.coeffs.into_iter().map(MpcVal::from_public).collect(),
        )
    }
    pub fn obs_labeled_poly(
        p: LabeledPolynomial<Fr, DensePolynomial<Fr>>,
    ) -> LabeledPolynomial<MFr, DensePolynomial<MFr>> {
        LabeledPolynomial::new(
            p.label().clone(),
            obs_poly(p.polynomial().clone()),
            p.degree_bound(),
            p.hiding_bound(),
        )
    }
}
pub mod marlin {
    use super::*;
    use ark_marlin::ahp::prover::*;
    use ark_marlin::ahp::*;
    use ark_marlin::*;
    use ark_poly::EvaluationDomain;
    use ark_std::{end_timer, start_timer};
    fn prover_message_publicize(
        p: ProverMsg<MpcVal<ark_bls12_377::Fr>>,
    ) -> ProverMsg<ark_bls12_377::Fr> {
        match p {
            ProverMsg::EmptyMessage => ProverMsg::EmptyMessage,
            ProverMsg::FieldElements(d) => {
                ProverMsg::FieldElements(d.into_iter().map(|e| e.publicize_unwrap()).collect())
            }
        }
    }

    pub fn pf_publicize(
        k: Proof<MpcVal<ark_bls12_377::Fr>, MpcMarlinKZG10>,
    ) -> Proof<ark_bls12_377::Fr, LocalMarlinKZG10> {
        let pf_timer = start_timer!(|| "publicize proof");
        let r = Proof::<ark_bls12_377::Fr, LocalMarlinKZG10> {
            commitments: k
                .commitments
                .into_iter()
                .map(|cs| cs.into_iter().map(super::pc::comm_publicize).collect())
                .collect(),
            evaluations: k
                .evaluations
                .into_iter()
                .map(|e| e.publicize_unwrap())
                .collect(),
            prover_messages: k
                .prover_messages
                .into_iter()
                .map(prover_message_publicize)
                .collect(),
            pc_proof: super::pc::batch_pf_publicize(k.pc_proof),
        };
        end_timer!(pf_timer);
        r
    }

    fn index_info_publicize<F: ark_ff::Field>(
        i: ahp::indexer::IndexInfo<MpcVal<F>>,
    ) -> ahp::indexer::IndexInfo<F> {
        ahp::indexer::IndexInfo {
            num_variables: i.num_variables,
            num_constraints: i.num_constraints,
            num_non_zero: i.num_non_zero,
            num_instance_variables: i.num_instance_variables,
            f: std::marker::PhantomData::default(),
        }
    }

    fn lift_index_info<F: ark_ff::Field>(
        i: ahp::indexer::IndexInfo<F>,
    ) -> ahp::indexer::IndexInfo<MpcVal<F>> {
        ahp::indexer::IndexInfo {
            num_variables: i.num_variables,
            num_constraints: i.num_constraints,
            num_non_zero: i.num_non_zero,
            num_instance_variables: i.num_instance_variables,
            f: std::marker::PhantomData::default(),
        }
    }

    fn lift_pp(
        pp: ark_poly_commit::kzg10::UniversalParams<E>,
    ) -> ark_poly_commit::kzg10::UniversalParams<ME> {
        ark_poly_commit::kzg10::UniversalParams {
            powers_of_g: pp
                .powers_of_g
                .into_iter()
                .map(MpcCurve::from_public)
                .collect(),
            powers_of_gamma_g: pp
                .powers_of_gamma_g
                .into_iter()
                .map(|(i, w)| (i, MpcCurve::from_public(w)))
                .collect(),
            h: MpcCurve2::from_public(pp.h),
            beta_h: MpcCurve2::from_public(pp.beta_h),
            neg_powers_of_h: pp
                .neg_powers_of_h
                .into_iter()
                .map(|(i, w)| (i, MpcCurve2::from_public(w)))
                .collect(),
            prepared_h: MpcPrepCurve2::from_public(pp.prepared_h),
            prepared_beta_h: MpcPrepCurve2::from_public(pp.prepared_beta_h),
        }
    }

    fn lift_index_vk(
        vk: ark_marlin::IndexVerifierKey<Fr, LocalMarlinKZG10>,
    ) -> ark_marlin::IndexVerifierKey<MFr, MpcMarlinKZG10> {
        ark_marlin::IndexVerifierKey {
            index_comms: vk
                .index_comms
                .into_iter()
                .map(mpc_algebra::poly::pc::lift_commitment)
                .collect(),
            verifier_key: lift_vk(vk.verifier_key),
            index_info: lift_index_info(vk.index_info),
        }
    }

    // Lift a locally computed commitent key to an MPC one.
    pub fn lift_kzg_vk(
        vk: ark_poly_commit::kzg10::VerifierKey<E>,
    ) -> ark_poly_commit::kzg10::VerifierKey<ME> {
        ark_poly_commit::kzg10::VerifierKey {
            g: MpcCurve::from_public(vk.g),
            gamma_g: MpcCurve::from_public(vk.gamma_g),
            h: MpcCurve2::from_public(vk.h),
            beta_h: MpcCurve2::from_public(vk.beta_h),
            prepared_h: MpcPrepCurve2::from_public(vk.prepared_h),
            prepared_beta_h: MpcPrepCurve2::from_public(vk.prepared_beta_h),
        }
    }
    pub fn lift_vk(
        vk: ark_poly_commit::marlin_pc::VerifierKey<E>,
    ) -> ark_poly_commit::marlin_pc::VerifierKey<ME> {
        ark_poly_commit::marlin_pc::VerifierKey {
            vk: lift_kzg_vk(vk.vk),
            degree_bounds_and_shift_powers: vk.degree_bounds_and_shift_powers.map(|v| {
                v.into_iter()
                    .map(|(i, g)| (i, MpcCurve::from_public(g)))
                    .collect()
            }),
            max_degree: vk.max_degree,
            supported_degree: vk.supported_degree,
        }
    }

    fn lift_index_matrix(
        mat: ark_marlin::ahp::indexer::Matrix<Fr>,
    ) -> ark_marlin::ahp::indexer::Matrix<MFr> {
        mat.into_iter()
            .map(|v| {
                v.into_iter()
                    .map(|(f, i)| (MpcVal::from_public(f), i))
                    .collect()
            })
            .collect()
    }
    fn lift_index(ii: ark_marlin::ahp::indexer::Index<Fr>) -> ark_marlin::ahp::indexer::Index<MFr> {
        ark_marlin::ahp::indexer::Index {
            index_info: lift_index_info(ii.index_info),
            a: lift_index_matrix(ii.a),
            b: lift_index_matrix(ii.b),
            c: lift_index_matrix(ii.c),
            a_star_arith: lift_matrix_arith(ii.a_star_arith),
            b_star_arith: lift_matrix_arith(ii.b_star_arith),
            c_star_arith: lift_matrix_arith(ii.c_star_arith),
        }
    }

    fn lift_labelled_poly(
        p: ark_poly_commit::data_structures::LabeledPolynomial<Fr, DensePolynomial<Fr>>,
    ) -> ark_poly_commit::data_structures::LabeledPolynomial<MFr, DensePolynomial<MFr>> {
        use ark_poly::UVPolynomial;
        ark_poly_commit::data_structures::LabeledPolynomial::new(
            p.label().clone(),
            DensePolynomial::from_coefficients_vec(
                p.polynomial()
                    .coeffs()
                    .into_iter()
                    .map(|c| MpcVal::from_public(c.clone()))
                    .collect(),
            ),
            p.degree_bound(),
            p.hiding_bound(),
        )
    }

    fn lift_evals(
        es: ark_poly::evaluations::univariate::Evaluations<Fr>,
    ) -> ark_poly::evaluations::univariate::Evaluations<MFr> {
        ark_poly::evaluations::univariate::Evaluations {
            evals: es.evals.into_iter().map(MpcVal::from_public).collect(),
            domain: ark_poly::GeneralEvaluationDomain::new(es.domain.size()).unwrap(),
        }
    }

    fn lift_matrix_evals(
        mat: ark_marlin::ahp::constraint_systems::MatrixEvals<Fr>,
    ) -> ark_marlin::ahp::constraint_systems::MatrixEvals<MFr> {
        ark_marlin::ahp::constraint_systems::MatrixEvals {
            row: lift_evals(mat.row),
            col: lift_evals(mat.col),
            val: lift_evals(mat.val),
        }
    }

    fn lift_matrix_arith(
        mat: ark_marlin::ahp::constraint_systems::MatrixArithmetization<Fr>,
    ) -> ark_marlin::ahp::constraint_systems::MatrixArithmetization<MFr> {
        ark_marlin::ahp::constraint_systems::MatrixArithmetization {
            row: lift_labelled_poly(mat.row),
            col: lift_labelled_poly(mat.col),
            val: lift_labelled_poly(mat.val),
            row_col: lift_labelled_poly(mat.row_col),
            evals_on_K: lift_matrix_evals(mat.evals_on_K),
            evals_on_B: lift_matrix_evals(mat.evals_on_B),
            row_col_evals_on_B: lift_evals(mat.row_col_evals_on_B),
        }
    }

    pub fn lift_index_pk(
        pk: ark_marlin::IndexProverKey<Fr, LocalMarlinKZG10>,
    ) -> ark_marlin::IndexProverKey<MFr, MpcMarlinKZG10> {
        ark_marlin::IndexProverKey {
            index_vk: lift_index_vk(pk.index_vk),
            index_comm_rands: pk
                .index_comm_rands
                .into_iter()
                .map(mpc_algebra::poly::pc::lift_randomness)
                .collect(),
            index: lift_index(pk.index),
            committer_key: mpc_algebra::poly::pc::lift_ck(pk.committer_key),
        }
    }
}
