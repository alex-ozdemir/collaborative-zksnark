#![allow(missing_docs)]
#![allow(dead_code)]
#![allow(unused_imports)]

use ark_ff::Field;
use ark_ec::PairingEngine;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::marlin_pc::MarlinKZG10;
use ark_poly_commit::reveal as pc_reveal;
use blake2::Blake2s;
use mpc_algebra::*;
use Marlin;

use super::*;
use crate::ahp::prover::*;
use ark_poly::EvaluationDomain;
use ark_std::{end_timer, start_timer};

impl<F: PrimeField, S: FieldShare<F>> Reveal for ProverMsg<MpcField<F, S>> {
    type Base = ProverMsg<F>;

    fn reveal(self) -> Self::Base {
        match self {
            ProverMsg::EmptyMessage => ProverMsg::EmptyMessage,
            ProverMsg::FieldElements(d) => ProverMsg::FieldElements(d.reveal()),
        }
    }

    fn from_add_shared(b: Self::Base) -> Self {
        match b {
            ProverMsg::EmptyMessage => ProverMsg::EmptyMessage,
            ProverMsg::FieldElements(d) => ProverMsg::FieldElements(Reveal::from_add_shared(d)),
        }
    }

    fn from_public(b: Self::Base) -> Self {
        match b {
            ProverMsg::EmptyMessage => ProverMsg::EmptyMessage,
            ProverMsg::FieldElements(d) => ProverMsg::FieldElements(Reveal::from_public(d)),
        }
    }
}

impl<F: Field> MpcWire for ProverMsg<F> {
    fn publicize(&mut self) {
        match self {
            ProverMsg::EmptyMessage => {},
            ProverMsg::FieldElements(d) => d.publicize(),
        }
    }

    fn is_shared(&self) -> bool {
        match self {
            ProverMsg::EmptyMessage => false,
            ProverMsg::FieldElements(d) => d.is_shared(),
        }
    }
}

impl<E: PairingEngine, S: PairingShare<E>> Reveal
    for Proof<
        <MpcPairingEngine<E, S> as PairingEngine>::Fr,
        MarlinKZG10<
            MpcPairingEngine<E, S>,
            DensePolynomial<<MpcPairingEngine<E, S> as PairingEngine>::Fr>,
        >,
    >
{
    type Base =
        Proof<<E as PairingEngine>::Fr, MarlinKZG10<E, DensePolynomial<<E as PairingEngine>::Fr>>>;
    struct_reveal_simp_impl!(Proof; commitments, evaluations, prover_messages, pc_proof);
}

impl<F: PrimeField, S: FieldShare<F>> Reveal for ahp::indexer::IndexInfo<MpcField<F, S>> {
    type Base = ahp::indexer::IndexInfo<F>;
    struct_reveal_simp_impl!(ahp::indexer::IndexInfo;
        num_variables,
        num_constraints,
        num_non_zero,
        num_instance_variables,
        f
    );
}

// fn lift_pp(
//     pp: ark_poly_commit::kzg10::UniversalParams<E>,
// ) -> ark_poly_commit::kzg10::UniversalParams<ME> {
//     ark_poly_commit::kzg10::UniversalParams {
//         powers_of_g: pp
//             .powers_of_g
//             .into_iter()
//             .map(HbcG1Affine::from_public)
//             .collect(),
//         powers_of_gamma_g: pp
//             .powers_of_gamma_g
//             .into_iter()
//             .map(|(i, w)| (i, HbcG1Affine::from_public(w)))
//             .collect(),
//         h: HbcG2Affine::from_public(pp.h),
//         beta_h: HbcG2Affine::from_public(pp.beta_h),
//         neg_powers_of_h: pp
//             .neg_powers_of_h
//             .into_iter()
//             .map(|(i, w)| (i, HbcG2Affine::from_public(w)))
//             .collect(),
//         prepared_h: HbcG2Prep::from_public(pp.prepared_h),
//         prepared_beta_h: HbcG2Prep::from_public(pp.prepared_beta_h),
//     }
// }
//
// fn lift_index_vk(
//     vk: IndexVerifierKey<Fr, LocalMarlinKZG10>,
// ) -> IndexVerifierKey<MFr, MpcMarlinKZG10> {
//     IndexVerifierKey {
//         index_comms: vk
//             .index_comms
//             .into_iter()
//             .map(pc_reveal::obs_commitment)
//             .collect(),
//         verifier_key: lift_vk(vk.verifier_key),
//         index_info: lift_index_info(vk.index_info),
//     }
// }
impl<E: PairingEngine, S: PairingShare<E>> Reveal
    for IndexVerifierKey<
        <MpcPairingEngine<E, S> as PairingEngine>::Fr,
        MarlinKZG10<
            MpcPairingEngine<E, S>,
            DensePolynomial<<MpcPairingEngine<E, S> as PairingEngine>::Fr>,
        >,
    >
{
    type Base = IndexVerifierKey<
        <E as PairingEngine>::Fr,
        MarlinKZG10<E, DensePolynomial<<E as PairingEngine>::Fr>>,
    >;
    struct_reveal_simp_impl!(IndexVerifierKey; index_comms, verifier_key, index_info);
}
//impl<F: PrimeField, S: FieldShare<F>> Reveal for ahp::indexer::Matrix<MpcField<F, S>> {
//    type Base = ahp::indexer::Matrix<F>;
//    struct_reveal_simp_impl!(ahp::indexer::Matrix;
//        num_variables,
//        num_constraints,
//        num_non_zero,
//        num_instance_variables,
//        f
//    );
//}
//
// fn lift_index_matrix(mat: ahp::indexer::Matrix<Fr>) -> ahp::indexer::Matrix<MFr> {
//     mat.into_iter()
//         .map(|v| {
//             v.into_iter()
//                 .map(|(f, i)| (HbcField::from_public(f), i))
//                 .collect()
//         })
//         .collect()
// }
impl<E: PrimeField, S: FieldShare<E>> Reveal for ahp::indexer::Index<MpcField<E, S>> {
    type Base = ahp::indexer::Index<E>;
    struct_reveal_simp_impl!(ahp::indexer::Index; index_info, a, b, c, a_star_arith, b_star_arith, c_star_arith);
}
// fn lift_index(ii: ahp::indexer::Index<Fr>) -> ahp::indexer::Index<MFr> {
//     ahp::indexer::Index {
//         index_info: lift_index_info(ii.index_info),
//         a: lift_index_matrix(ii.a),
//         b: lift_index_matrix(ii.b),
//         c: lift_index_matrix(ii.c),
//         a_star_arith: lift_matrix_arith(ii.a_star_arith),
//         b_star_arith: lift_matrix_arith(ii.b_star_arith),
//         c_star_arith: lift_matrix_arith(ii.c_star_arith),
//     }
// }
//
// fn lift_labelled_poly(
//     p: ark_poly_commit::data_structures::LabeledPolynomial<Fr, DensePolynomial<Fr>>,
// ) -> ark_poly_commit::data_structures::LabeledPolynomial<MFr, DensePolynomial<MFr>> {
//     use ark_poly::UVPolynomial;
//     ark_poly_commit::data_structures::LabeledPolynomial::new(
//         p.label().clone(),
//         DensePolynomial::from_coefficients_vec(
//             p.polynomial()
//                 .coeffs()
//                 .into_iter()
//                 .map(|c| HbcField::from_public(c.clone()))
//                 .collect(),
//         ),
//         p.degree_bound(),
//         p.hiding_bound(),
//     )
// }
//
// fn lift_evals(
//     es: ark_poly::evaluations::univariate::Evaluations<Fr>,
// ) -> ark_poly::evaluations::univariate::Evaluations<MFr> {
//     ark_poly::evaluations::univariate::Evaluations {
//         evals: es.evals.into_iter().map(HbcField::from_public).collect(),
//         domain: ark_poly::GeneralEvaluationDomain::new(es.domain.size()).unwrap(),
//     }
// }
//
// fn lift_matrix_evals(
//     mat: ahp::constraint_systems::MatrixEvals<Fr>,
// ) -> ahp::constraint_systems::MatrixEvals<MFr> {
//     ahp::constraint_systems::MatrixEvals {
//         row: lift_evals(mat.row),
//         col: lift_evals(mat.col),
//         val: lift_evals(mat.val),
//     }
// }
impl<E: PrimeField, S: FieldShare<E>> Reveal
    for ahp::constraint_systems::MatrixEvals<MpcField<E, S>>
{
    type Base = ahp::constraint_systems::MatrixEvals<E>;
    struct_reveal_simp_impl!(ahp::constraint_systems::MatrixEvals; row, col, val);
}
impl<E: PrimeField, S: FieldShare<E>> Reveal
    for ahp::constraint_systems::MatrixArithmetization<MpcField<E, S>>
{
    type Base = ahp::constraint_systems::MatrixArithmetization<E>;
    struct_reveal_simp_impl!(ahp::constraint_systems::MatrixArithmetization; row, col, val, row_col, evals_on_K, evals_on_B, row_col_evals_on_B);
}
//
// fn lift_matrix_arith(
//     mat: ahp::constraint_systems::MatrixArithmetization<Fr>,
// ) -> ahp::constraint_systems::MatrixArithmetization<MFr> {
//     ahp::constraint_systems::MatrixArithmetization {
//         row: lift_labelled_poly(mat.row),
//         col: lift_labelled_poly(mat.col),
//         val: lift_labelled_poly(mat.val),
//         row_col: lift_labelled_poly(mat.row_col),
//         evals_on_K: lift_matrix_evals(mat.evals_on_K),
//         evals_on_B: lift_matrix_evals(mat.evals_on_B),
//         row_col_evals_on_B: lift_evals(mat.row_col_evals_on_B),
//     }
// }
//
// pub fn lift_index_pk(
//     pk: IndexProverKey<Fr, LocalMarlinKZG10>,
// ) -> IndexProverKey<MFr, MpcMarlinKZG10> {
//     IndexProverKey {
//         index_vk: lift_index_vk(pk.index_vk),
//         index_comm_rands: pk
//             .index_comm_rands
//             .into_iter()
//             .map(pc_reveal::obs_randomness)
//             .collect(),
//         index: lift_index(pk.index),
//         committer_key: pc_reveal::obs_ck(pk.committer_key),
//     }
// }
impl<E: PairingEngine, S: PairingShare<E>> Reveal
    for IndexProverKey<
        <MpcPairingEngine<E, S> as PairingEngine>::Fr,
        MarlinKZG10<
            MpcPairingEngine<E, S>,
            DensePolynomial<<MpcPairingEngine<E, S> as PairingEngine>::Fr>,
        >,
    >
{
    type Base = IndexProverKey<
        <E as PairingEngine>::Fr,
        MarlinKZG10<E, DensePolynomial<<E as PairingEngine>::Fr>>,
    >;
    struct_reveal_simp_impl!(IndexProverKey; index_vk, index_comm_rands, index, committer_key);
}
