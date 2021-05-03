use super::silly::MySillyCircuit;
use mpc_trait::MpcWire;
use ark_ec::PairingEngine;
use ark_poly_commit::marlin_pc::MarlinKZG10;
use ark_std::{test_rng, start_timer, end_timer};
use blake2::Blake2s;
use ark_ff::{to_bytes, PrimeField, UniformRand};
use ark_poly::{univariate::DensePolynomial, EvaluationDomain, GeneralEvaluationDomain};
use ark_poly_commit::Evaluations;
use ark_poly_commit::{LabeledCommitment, PCUniversalParams, PolynomialCommitment};
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_std::rand::RngCore;
use digest::Digest;
use std::marker::PhantomData;
use ark_marlin::{*, rng::{FiatShamirRng}, ahp::prover::*};
use mpc_algebra::{MpcCurve, MpcCurve2, MpcVal, MpcPairingEngine, MpcPrepCurve2};
// pub use Vec;
// pub use ToString;
// pub use String;
// pub use std::collections::BTreeMap;

// mod error;
// use error::*;
// mod ahp;
// mod data_structures;
// use ahp::AHPForR1CS;
// use data_structures::*;
// use ahp::EvaluationsProvider;

// /// The compiled argument system.
// pub struct Marlin<F: PrimeField, PC: PolynomialCommitment<F, DensePolynomial<F>>, D: Digest>(
//     #[doc(hidden)] PhantomData<F>,
//     #[doc(hidden)] PhantomData<PC>,
//     #[doc(hidden)] PhantomData<D>,
// );
// 
// impl<F: PrimeField + MpcWire, PC: PolynomialCommitment<F, DensePolynomial<F>>, D: Digest> Marlin<F, PC, D> {
//     /// The personalization string for this protocol. Used to personalize the
//     /// Fiat-Shamir rng.
//     pub const PROTOCOL_NAME: &'static [u8] = b"MARLIN-2019";
// 
//     /// Generate the universal prover and verifier keys for the
//     /// argument system.
//     pub fn universal_setup<R: RngCore>(
//         num_constraints: usize,
//         num_variables: usize,
//         num_non_zero: usize,
//         rng: &mut R,
//     ) -> Result<UniversalSRS<F, PC>, Error<PC::Error>> {
//         let max_degree = AHPForR1CS::<F>::max_degree(num_constraints, num_variables, num_non_zero)?;
//         let setup_time = start_timer!(|| {
//             format!(
//             "Marlin::UniversalSetup with max_degree {}, computed for a maximum of {} constraints, {} vars, {} non_zero",
//             max_degree, num_constraints, num_variables, num_non_zero,
//         )
//         });
// 
//         let srs = PC::setup(max_degree, None, rng).map_err(Error::from_pc_err);
//         end_timer!(setup_time);
//         srs
//     }
// 
//     /// Generate the index-specific (i.e., circuit-specific) prover and verifier
//     /// keys. This is a deterministic algorithm that anyone can rerun.
//     pub fn index<C: ConstraintSynthesizer<F>>(
//         srs: &UniversalSRS<F, PC>,
//         c: C,
//     ) -> Result<(IndexProverKey<F, PC>, IndexVerifierKey<F, PC>), Error<PC::Error>> {
//         let index_time = start_timer!(|| "Marlin::Index");
// 
//         // TODO: Add check that c is in the correct mode.
//         let index = AHPForR1CS::index(c)?;
//         if srs.max_degree() < index.max_degree() {
//             Err(Error::IndexTooLarge)?;
//         }
// 
//         let coeff_support = AHPForR1CS::get_degree_bounds(&index.index_info);
//         // Marlin only needs degree 2 random polynomials
//         let supported_hiding_bound = 1;
//         let (committer_key, verifier_key) = PC::trim(
//             &srs,
//             index.max_degree(),
//             supported_hiding_bound,
//             Some(&coeff_support),
//         )
//         .map_err(Error::from_pc_err)?;
// 
//         let commit_time = start_timer!(|| "Commit to index polynomials");
//         let (index_comms, index_comm_rands): (_, _) =
//             PC::commit(&committer_key, index.iter(), None).map_err(Error::from_pc_err)?;
//         end_timer!(commit_time);
// 
//         let index_comms = index_comms
//             .into_iter()
//             .map(|c| c.commitment().clone())
//             .collect();
//         let index_vk = IndexVerifierKey {
//             index_info: index.index_info,
//             index_comms,
//             verifier_key,
//         };
// 
//         let index_pk = IndexProverKey {
//             index,
//             index_comm_rands,
//             index_vk: index_vk.clone(),
//             committer_key,
//         };
// 
//         end_timer!(index_time);
// 
//         Ok((index_pk, index_vk))
//     }
// 
//     /// Create a zkSNARK asserting that the constraint system is satisfied.
//     pub fn prove<C: ConstraintSynthesizer<F>, R: RngCore>(
//         index_pk: &IndexProverKey<F, PC>,
//         c: C,
//         zk_rng: &mut R,
//     ) -> Result<Proof<F, PC>, Error<PC::Error>> {
//         let prover_time = start_timer!(|| "Marlin::Prover");
//         // Add check that c is in the correct mode.
// 
//         let prover_init_state = AHPForR1CS::prover_init(&index_pk.index, c)?;
//         let public_input = prover_init_state.public_input();
//         let mut fs_rng = FiatShamirRng::<D>::from_seed(
//             &to_bytes![&Self::PROTOCOL_NAME, &index_pk.index_vk, &public_input].unwrap(),
//         );
// 
//         // --------------------------------------------------------------------
//         // First round
// 
//         let (prover_first_msg, prover_first_oracles, prover_state) =
//             AHPForR1CS::prover_first_round(prover_init_state, zk_rng)?;
// 
//         let first_round_comm_time = start_timer!(|| "Committing to first round polys");
//         let (first_comms, first_comm_rands) = PC::commit(
//             &index_pk.committer_key,
//             prover_first_oracles.iter(),
//             Some(zk_rng),
//         )
//         .map_err(Error::from_pc_err)?;
//         end_timer!(first_round_comm_time);
// 
//         fs_rng.absorb(&to_bytes![first_comms, prover_first_msg].unwrap());
// 
//         let (verifier_first_msg, verifier_state) =
//             AHPForR1CS::verifier_first_round(index_pk.index_vk.index_info, &mut fs_rng)?;
//         // --------------------------------------------------------------------
// 
//         // --------------------------------------------------------------------
//         // Second round
// 
//         let (prover_second_msg, prover_second_oracles, prover_state) =
//             AHPForR1CS::prover_second_round(&verifier_first_msg, prover_state, zk_rng);
// 
//         let second_round_comm_time = start_timer!(|| "Committing to second round polys");
//         let (second_comms, second_comm_rands) = PC::commit(
//             &index_pk.committer_key,
//             prover_second_oracles.iter(),
//             Some(zk_rng),
//         )
//         .map_err(Error::from_pc_err)?;
//         end_timer!(second_round_comm_time);
// 
//         fs_rng.absorb(&to_bytes![second_comms, prover_second_msg].unwrap());
// 
//         let (verifier_second_msg, verifier_state) =
//             AHPForR1CS::verifier_second_round(verifier_state, &mut fs_rng);
//         // --------------------------------------------------------------------
// 
//         // --------------------------------------------------------------------
//         // Third round
//         let (prover_third_msg, prover_third_oracles) =
//             AHPForR1CS::prover_third_round(&verifier_second_msg, prover_state, zk_rng)?;
// 
//         let third_round_comm_time = start_timer!(|| "Committing to third round polys");
//         let (third_comms, third_comm_rands) = PC::commit(
//             &index_pk.committer_key,
//             prover_third_oracles.iter(),
//             Some(zk_rng),
//         )
//         .map_err(Error::from_pc_err)?;
//         end_timer!(third_round_comm_time);
// 
//         fs_rng.absorb(&to_bytes![third_comms, prover_third_msg].unwrap());
// 
//         let verifier_state = AHPForR1CS::verifier_third_round(verifier_state, &mut fs_rng);
//         // --------------------------------------------------------------------
// 
//         // Gather prover polynomials in one vector.
//         let polynomials: Vec<_> = index_pk
//             .index
//             .iter()
//             .chain(prover_first_oracles.iter())
//             .chain(prover_second_oracles.iter())
//             .chain(prover_third_oracles.iter())
//             .collect();
// 
//         // Gather commitments in one vector.
//         #[rustfmt::skip]
//         let commitments = vec![
//             first_comms.iter().map(|p| p.commitment().clone()).collect(),
//             second_comms.iter().map(|p| p.commitment().clone()).collect(),
//             third_comms.iter().map(|p| p.commitment().clone()).collect(),
//         ];
//         let labeled_comms: Vec<_> = index_pk
//             .index_vk
//             .iter()
//             .cloned()
//             .zip(&AHPForR1CS::<F>::INDEXER_POLYNOMIALS)
//             .map(|(c, l)| LabeledCommitment::new(l.to_string(), c, None))
//             .chain(first_comms.iter().cloned())
//             .chain(second_comms.iter().cloned())
//             .chain(third_comms.iter().cloned())
//             .collect();
// 
//         // Gather commitment randomness together.
//         let comm_rands: Vec<PC::Randomness> = index_pk
//             .index_comm_rands
//             .clone()
//             .into_iter()
//             .chain(first_comm_rands)
//             .chain(second_comm_rands)
//             .chain(third_comm_rands)
//             .collect();
// 
//         // Compute the AHP verifier's query set.
//         let (query_set, verifier_state) =
//             AHPForR1CS::verifier_query_set(verifier_state, &mut fs_rng);
//         let lc_s = AHPForR1CS::construct_linear_combinations(
//             &public_input,
//             &polynomials,
//             &verifier_state,
//         )?;
// 
//         let eval_time = start_timer!(|| "Evaluating linear combinations over query set");
//         let mut evaluations = Vec::new();
//         for (label, (_, point)) in &query_set {
//             let lc = lc_s
//                 .iter()
//                 .find(|lc| &lc.label == label)
//                 .ok_or(ahp::Error::MissingEval(label.to_string()))?;
//             let eval = polynomials.get_lc_eval(&lc, *point)?;
//             if !AHPForR1CS::<F>::LC_WITH_ZERO_EVAL.contains(&lc.label.as_ref()) {
//                 evaluations.push((label.to_string(), eval));
//             }
//         }
// 
//         evaluations.sort_by(|a, b| a.0.cmp(&b.0));
//         let evaluations = evaluations.into_iter().map(|x| x.1).collect::<Vec<F>>();
//         end_timer!(eval_time);
// 
//         fs_rng.absorb(&evaluations);
//         let opening_challenge: F = u128::rand(&mut fs_rng).into();
// 
//         let pc_proof = PC::open_combinations(
//             &index_pk.committer_key,
//             &lc_s,
//             polynomials,
//             &labeled_comms,
//             &query_set,
//             opening_challenge,
//             &comm_rands,
//             Some(zk_rng),
//         )
//         .map_err(Error::from_pc_err)?;
// 
//         // Gather prover messages together.
//         let prover_messages = vec![prover_first_msg, prover_second_msg, prover_third_msg];
// 
//         let proof = Proof::new(commitments, evaluations, prover_messages, pc_proof);
//         proof.print_size_info();
//         end_timer!(prover_time);
//         Ok(proof)
//     }
// 
//     /// Verify that a proof for the constrain system defined by `C` asserts that
//     /// all constraints are satisfied.
//     pub fn verify<R: RngCore>(
//         index_vk: &IndexVerifierKey<F, PC>,
//         public_input: &[F],
//         proof: &Proof<F, PC>,
//         rng: &mut R,
//     ) -> Result<bool, Error<PC::Error>> {
//         let verifier_time = start_timer!(|| "Marlin::Verify");
// 
//         let public_input = {
//             let domain_x = GeneralEvaluationDomain::<F>::new(public_input.len() + 1).unwrap();
// 
//             let mut unpadded_input = public_input.to_vec();
//             unpadded_input.resize(
//                 core::cmp::max(public_input.len(), domain_x.size() - 1),
//                 F::zero(),
//             );
// 
//             unpadded_input
//         };
// 
//         let mut fs_rng = FiatShamirRng::<D>::from_seed(
//             &to_bytes![&Self::PROTOCOL_NAME, &index_vk, &public_input].unwrap(),
//         );
// 
//         // --------------------------------------------------------------------
//         // First round
// 
//         let first_comms = &proof.commitments[0];
//         fs_rng.absorb(&to_bytes![first_comms, proof.prover_messages[0]].unwrap());
// 
//         let (_, verifier_state) =
//             AHPForR1CS::verifier_first_round(index_vk.index_info, &mut fs_rng)?;
//         // --------------------------------------------------------------------
// 
//         // --------------------------------------------------------------------
//         // Second round
//         let second_comms = &proof.commitments[1];
//         fs_rng.absorb(&to_bytes![second_comms, proof.prover_messages[1]].unwrap());
// 
//         let (_, verifier_state) = AHPForR1CS::verifier_second_round(verifier_state, &mut fs_rng);
//         // --------------------------------------------------------------------
// 
//         // --------------------------------------------------------------------
//         // Third round
//         let third_comms = &proof.commitments[2];
//         fs_rng.absorb(&to_bytes![third_comms, proof.prover_messages[2]].unwrap());
// 
//         let verifier_state = AHPForR1CS::verifier_third_round(verifier_state, &mut fs_rng);
//         // --------------------------------------------------------------------
// 
//         // Collect degree bounds for commitments. Indexed polynomials have *no*
//         // degree bounds because we know the committed index polynomial has the
//         // correct degree.
//         let index_info = index_vk.index_info;
//         let degree_bounds = vec![None; index_vk.index_comms.len()]
//             .into_iter()
//             .chain(AHPForR1CS::prover_first_round_degree_bounds(&index_info))
//             .chain(AHPForR1CS::prover_second_round_degree_bounds(&index_info))
//             .chain(AHPForR1CS::prover_third_round_degree_bounds(&index_info))
//             .collect::<Vec<_>>();
// 
//         // Gather commitments in one vector.
//         let commitments: Vec<_> = index_vk
//             .iter()
//             .chain(first_comms)
//             .chain(second_comms)
//             .chain(third_comms)
//             .cloned()
//             .zip(AHPForR1CS::<F>::polynomial_labels())
//             .zip(degree_bounds)
//             .map(|((c, l), d)| LabeledCommitment::new(l, c, d))
//             .collect();
// 
//         let (query_set, verifier_state) =
//             AHPForR1CS::verifier_query_set(verifier_state, &mut fs_rng);
// 
//         fs_rng.absorb(&proof.evaluations);
//         let opening_challenge: F = u128::rand(&mut fs_rng).into();
// 
//         let mut evaluations = Evaluations::new();
//         let mut evaluation_labels = Vec::new();
//         for (poly_label, (_, point)) in query_set.iter().cloned() {
//             if AHPForR1CS::<F>::LC_WITH_ZERO_EVAL.contains(&poly_label.as_ref()) {
//                 evaluations.insert((poly_label, point), F::zero());
//             } else {
//                 evaluation_labels.push((poly_label, point));
//             }
//         }
//         evaluation_labels.sort_by(|a, b| a.0.cmp(&b.0));
//         for (q, eval) in evaluation_labels.into_iter().zip(&proof.evaluations) {
//             evaluations.insert(q, *eval);
//         }
// 
//         let lc_s = AHPForR1CS::construct_linear_combinations(
//             &public_input,
//             &evaluations,
//             &verifier_state,
//         )?;
// 
//         let evaluations_are_correct = PC::check_combinations(
//             &index_vk.verifier_key,
//             &lc_s,
//             &commitments,
//             &query_set,
//             &evaluations,
//             &proof.pc_proof,
//             opening_challenge,
//             rng,
//         )
//         .map_err(Error::from_pc_err)?;
// 
//         if !evaluations_are_correct {
//             eprintln!("PC::Check failed");
//         }
//         end_timer!(verifier_time, || format!(
//             " PC::Check for AHP Verifier linear equations: {}",
//             evaluations_are_correct
//         ));
//         Ok(evaluations_are_correct)
//     }
// }

// pub fn local_test_prove_and_verify<E: PairingEngine>(n_iters: usize) where E::Fr: MpcWire {
//     let rng = &mut test_rng();
// 
//     let srs = &MarlinPair::<E, E::Fr>::universal_setup(100, 50, 100, rng).unwrap();
// 
//     for _ in 0..n_iters {
//         let a = E::Fr::rand(rng);
//         let b = E::Fr::rand(rng);
//         let circ = MySillyCircuit {
//             a: Some(a),
//             b: Some(b),
//         };
//         let mut c = a;
//         c *= &b;
//         let inputs = vec![c];
//         let (index_pk, index_vk) = MarlinPair::<E, E::Fr>::index(srs, circ.clone()).unwrap();
//         let proof = MarlinPair::<E, E::Fr>::prove(&index_pk, circ, rng).unwrap();
//         let is_valid = MarlinPair::<E, E::Fr>::verify(&index_vk, &inputs, &proof, rng).unwrap();
//         assert!(is_valid);
//         let is_valid = MarlinPair::<E, E::Fr>::verify(&index_vk, &[a], &proof, rng).unwrap();
//         assert!(!is_valid);
//     }
// }
// 
fn prover_message_publicize(p: ProverMsg<MpcVal<ark_bls12_377::Fr>>) -> ProverMsg<ark_bls12_377::Fr> {
    match p {
        ProverMsg::EmptyMessage => ProverMsg::EmptyMessage,
        ProverMsg::FieldElements(d) => ProverMsg::FieldElements(d.into_iter().map(|e| e.publicize_unwrap()).collect()),
    }
}

fn comm_publicize(pf: ark_poly_commit::marlin_pc::Commitment::<ME>) -> ark_poly_commit::marlin_pc::Commitment::<E> {
  ark_poly_commit::marlin_pc::Commitment {
    comm: commit_from_mpc(pf.comm),
    shifted_comm: pf.shifted_comm.map(commit_from_mpc),
  }
}

fn commit_from_mpc<'a>(
    p: ark_poly_commit::kzg10::Commitment<MpcPairingEngine<ark_bls12_377::Bls12_377>>,
) -> ark_poly_commit::kzg10::Commitment<ark_bls12_377::Bls12_377> {
    ark_poly_commit::kzg10::Commitment(p.0.publicize_unwrap())
}
fn pf_from_mpc<'a>(
    pf: ark_poly_commit::kzg10::Proof<MpcPairingEngine<ark_bls12_377::Bls12_377>>,
) -> ark_poly_commit::kzg10::Proof<ark_bls12_377::Bls12_377> {
    ark_poly_commit::kzg10::Proof {
        w: pf.w.publicize_unwrap(),
        random_v: pf.random_v.map(MpcVal::publicize_unwrap),
    }
}

fn batch_pf_publicize(pf: ark_poly_commit::BatchLCProof<MFr, DensePolynomial<MFr>, MpcMarlinKZG10>) -> ark_poly_commit::BatchLCProof<Fr, DensePolynomial<Fr>, LocalMarlinKZG10> {
  ark_poly_commit::BatchLCProof {
    proof: pf.proof.into_iter().map(pf_from_mpc).collect(),
    evals: pf.evals.map(|e| e.into_iter().map(MpcVal::publicize_unwrap).collect()),
  }
}

pub fn pf_publicize(k: Proof<MpcVal<ark_bls12_377::Fr>, MpcMarlinKZG10>) -> Proof<ark_bls12_377::Fr, LocalMarlinKZG10> {
    let pf_timer = start_timer!(|| "publicize proof");
    let r = Proof::<ark_bls12_377::Fr, LocalMarlinKZG10> {
        commitments: k.commitments.into_iter().map(|cs| cs.into_iter().map(comm_publicize).collect()).collect(),
        evaluations: k.evaluations.into_iter().map(|e| e.publicize_unwrap()).collect(),
        prover_messages: k.prover_messages.into_iter().map(prover_message_publicize).collect(),
        pc_proof: batch_pf_publicize(k.pc_proof),
    };
    end_timer!(pf_timer);
    r
}


type Fr = ark_bls12_377::Fr;
type E = ark_bls12_377::Bls12_377;
type ME = MpcPairingEngine<ark_bls12_377::Bls12_377>;
type MFr = MpcVal<Fr>;
type PC = MarlinKZG10<E, DensePolynomial<Fr>>;
type MpcMarlinKZG10 = MarlinKZG10::<ME, DensePolynomial<MFr>>;
type LocalMarlinKZG10 = MarlinKZG10::<E, DensePolynomial<Fr>>;
type LocalMarlin = Marlin<Fr, LocalMarlinKZG10, Blake2s>;
type MpcMarlin = Marlin<MFr, MpcMarlinKZG10, Blake2s>;
//type LocalBlsMarlin = MarlinPair<ark_bls12_377::Bls12_377, ark_bls12_377::Fr>;
//type MpcBlsMarlin = Marlin<MpcVal<ark_bls12_377::Fr>, MpcMarlinKZG10, Blake2s>;
//type MpcBlsMarlin = Marlin<MpcVal<ark_bls12_377::Fr>, MpcMarlinKZG10, Blake2s>;
 
fn index_info_publicize<F: ark_ff::Field>(i: ahp::indexer::IndexInfo<MpcVal<F>>) -> ahp::indexer::IndexInfo<F> {
    ahp::indexer::IndexInfo {
        num_variables: i.num_variables,
        num_constraints: i.num_constraints,
        num_non_zero: i.num_non_zero,
        num_instance_variables: i.num_instance_variables,
        f: std::marker::PhantomData::default(),
    }
}

fn lift_index_info<F: ark_ff::Field>(i: ahp::indexer::IndexInfo<F>) -> ahp::indexer::IndexInfo<MpcVal<F>> {
    ahp::indexer::IndexInfo {
        num_variables: i.num_variables,
        num_constraints: i.num_constraints,
        num_non_zero: i.num_non_zero,
        num_instance_variables: i.num_instance_variables,
        f: std::marker::PhantomData::default(),
    }
}

fn lift_pp(pp: ark_poly_commit::kzg10::UniversalParams<E>) -> ark_poly_commit::kzg10::UniversalParams<ME> {
  ark_poly_commit::kzg10::UniversalParams {
    powers_of_g: pp.powers_of_g.into_iter().map(MpcCurve::from_public).collect(),
    powers_of_gamma_g: pp.powers_of_gamma_g.into_iter().map(|(i, w)| (i, MpcCurve::from_public(w))).collect(),
    h: MpcCurve2::from_public(pp.h),
    beta_h: MpcCurve2::from_public(pp.beta_h),
    neg_powers_of_h: pp.neg_powers_of_h.into_iter().map(|(i, w)| (i, MpcCurve2::from_public(w))).collect(),
    prepared_h: MpcPrepCurve2::from_public(pp.prepared_h),
    prepared_beta_h: MpcPrepCurve2::from_public(pp.prepared_beta_h),
  }
}

fn lift_index_vk(vk: ark_marlin::IndexVerifierKey<Fr, LocalMarlinKZG10>) -> ark_marlin::IndexVerifierKey<MFr, MpcMarlinKZG10> {
  ark_marlin::IndexVerifierKey {
    index_comms: vk.index_comms.into_iter().map(mpc_algebra::poly::pc::lift_commitment).collect(),
    verifier_key: lift_vk(vk.verifier_key),
    index_info: lift_index_info(vk.index_info),
  }
}

// Lift a locally computed commitent key to an MPC one.
pub fn lift_kzg_vk(vk: ark_poly_commit::kzg10::VerifierKey<E>) -> ark_poly_commit::kzg10::VerifierKey<ME> {
  ark_poly_commit::kzg10::VerifierKey {
    g: MpcCurve::from_public(vk.g),
    gamma_g: MpcCurve::from_public(vk.gamma_g),
    h: MpcCurve2::from_public(vk.h),
    beta_h: MpcCurve2::from_public(vk.beta_h),
    prepared_h: MpcPrepCurve2::from_public(vk.prepared_h),
    prepared_beta_h: MpcPrepCurve2::from_public(vk.prepared_beta_h),
  }

}
pub fn lift_vk(vk: ark_poly_commit::marlin_pc::VerifierKey<E>) -> ark_poly_commit::marlin_pc::VerifierKey<ME> {
    ark_poly_commit::marlin_pc::VerifierKey {
      vk: lift_kzg_vk(vk.vk),
      degree_bounds_and_shift_powers: vk.degree_bounds_and_shift_powers.map(|v| v.into_iter().map(|(i, g)| (i, MpcCurve::from_public(g))).collect()),
      max_degree: vk.max_degree,
      supported_degree: vk.supported_degree,
    }
}

fn lift_index_matrix(mat: ark_marlin::ahp::indexer::Matrix<Fr>) -> ark_marlin::ahp::indexer::Matrix<MFr> {
  mat.into_iter().map(|v| v.into_iter().map(|(f, i)| (MpcVal::from_public(f), i)).collect()).collect()
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

fn lift_labelled_poly(p: ark_poly_commit::data_structures::LabeledPolynomial<Fr, DensePolynomial<Fr>>) -> ark_poly_commit::data_structures::LabeledPolynomial<MFr, DensePolynomial<MFr>> {
  use ark_poly::UVPolynomial;
  ark_poly_commit::data_structures::LabeledPolynomial::new(p.label().clone(), DensePolynomial::from_coefficients_vec(p.polynomial().coeffs().into_iter().map(|c| MpcVal::from_public(c.clone())).collect()), p.degree_bound(), p.hiding_bound())
}

fn lift_evals(es: ark_poly::evaluations::univariate::Evaluations<Fr>) -> ark_poly::evaluations::univariate::Evaluations<MFr> {
  ark_poly::evaluations::univariate::Evaluations {
    evals: es.evals.into_iter().map(MpcVal::from_public).collect(),
    domain: ark_poly::GeneralEvaluationDomain::new(es.domain.size()).unwrap(),
  }
}

fn lift_matrix_evals(mat: ark_marlin::ahp::constraint_systems::MatrixEvals<Fr>) -> ark_marlin::ahp::constraint_systems::MatrixEvals<MFr> {
  ark_marlin::ahp::constraint_systems::MatrixEvals {
    row: lift_evals(mat.row),
    col: lift_evals(mat.col),
    val: lift_evals(mat.val),
  }
}

fn lift_matrix_arith(mat: ark_marlin::ahp::constraint_systems::MatrixArithmetization<Fr>) -> ark_marlin::ahp::constraint_systems::MatrixArithmetization<MFr> {
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


fn lift_index_pk(pk: ark_marlin::IndexProverKey<Fr, LocalMarlinKZG10>) -> ark_marlin::IndexProverKey<MFr, MpcMarlinKZG10> {
  ark_marlin::IndexProverKey {
    index_vk: lift_index_vk(pk.index_vk),
    index_comm_rands: pk.index_comm_rands.into_iter().map(mpc_algebra::poly::pc::lift_randomness).collect(),
    index: lift_index(pk.index),
    committer_key: mpc_algebra::poly::pc::lift_ck(pk.committer_key),
  }
}

pub fn mpc_test_prove_and_verify(n_iters: usize) {
    let rng = &mut test_rng();

    let srs = LocalMarlin::universal_setup(100, 50, 100, rng).unwrap();
    let mpc_srs = lift_pp(srs.clone());
    let empty_circuit: MySillyCircuit<Fr> = MySillyCircuit { a: None, b: None };
    let (index_pk, index_vk) = LocalMarlin::index(&srs, empty_circuit.clone()).unwrap();
    let mpc_index_pk = lift_index_pk(index_pk);

    for _ in 0..n_iters {
        let a = MpcVal::<ark_bls12_377::Fr>::rand(rng);
        let b = MpcVal::<ark_bls12_377::Fr>::rand(rng);
        let circ = MySillyCircuit {
            a: Some(a),
            b: Some(b),
        };
        let mut c = a;
        c *= &b;
        let inputs = vec![c.publicize_unwrap()];
        let mpc_proof = MpcMarlin::prove(&mpc_index_pk, circ, rng).unwrap();
        let proof = pf_publicize(mpc_proof);
        let public_a = a.publicize_unwrap();
        let is_valid = LocalMarlin::verify(&index_vk, &inputs, &proof, rng).unwrap();
        assert!(is_valid);
        let is_valid = LocalMarlin::verify(&index_vk, &[public_a], &proof, rng).unwrap();
        assert!(!is_valid);
    }
}

//struct MpcPolyCommit<F: Field, P: Polynomial<F>, PC: PolynomialCommitment<F, P>>(PC, PhantomData<F>, PhantomData<P>);
//
//type Fr = ark_bls12_377::Fr;
//type P = DensePolynomial<Fr>;
//impl<P: Polynomial<Fr>, PC: PolynomialCommitment<Fr, P>>
//    PolynomialCommitment<MpcVal<Fr>, DensePolynomial<MpcVal<Fr>>> for MpcPolyCommit<Fr, PC>
//{
//    type UniversalParams = PC::UniversalParams;
//    type CommitterKey = Type;
//    type VerifierKey = Type;
//    type PreparedVerifierKey = Type;
//    type Commitment = Type;
//    type PreparedCommitment = Type;
//    type Randomness = Type;
//    type Proof = Type;
//    type BatchProof = Type;
//    type Error = Type;
//    fn setup<R: RngCore>(
//        max_degree: usize,
//        num_vars: Option<usize>,
//        rng: &mut R,
//    ) -> Result<Self::UniversalParams, Self::Error> {
//        todo!()
//    }
//
//    /// Specializes the public parameters for polynomials up to the given `supported_degree`
//    /// and for enforcing degree bounds in the range `1..=supported_degree`.
//    fn trim(
//        pp: &Self::UniversalParams,
//        supported_degree: usize,
//        supported_hiding_bound: usize,
//        enforced_degree_bounds: Option<&[usize]>,
//    ) -> Result<(Self::CommitterKey, Self::VerifierKey), Self::Error> {
//        todo!()
//    }
//
//    /// Outputs a commitments to `polynomials`. If `polynomials[i].is_hiding()`,
//    /// then the `i`-th commitment is hiding up to `polynomials.hiding_bound()` queries.
//    /// `rng` should not be `None` if `polynomials[i].is_hiding() == true` for any `i`.
//    ///
//    /// If for some `i`, `polynomials[i].is_hiding() == false`, then the
//    /// corresponding randomness is `Self::Randomness::empty()`.
//    ///
//    /// If for some `i`, `polynomials[i].degree_bound().is_some()`, then that
//    /// polynomial will have the corresponding degree bound enforced.
//    fn commit<'a>(
//        ck: &Self::CommitterKey,
//        polynomials: impl IntoIterator<Item = &'a LabeledPolynomial<F, P>>,
//        rng: Option<&mut dyn RngCore>,
//    ) -> Result<
//        (
//            Vec<LabeledCommitment<Self::Commitment>>,
//            Vec<Self::Randomness>,
//        ),
//        Self::Error,
//    >
//    where
//        P: 'a,
//    {
//        todo!()
//    }
//    /// open but with individual challenges
//    fn open_individual_opening_challenges<'a>(
//        ck: &Self::CommitterKey,
//        labeled_polynomials: impl IntoIterator<Item = &'a LabeledPolynomial<F, P>>,
//        commitments: impl IntoIterator<Item = &'a LabeledCommitment<Self::Commitment>>,
//        point: &'a P::Point,
//        opening_challenges: &dyn Fn(u64) -> F,
//        rands: impl IntoIterator<Item = &'a Self::Randomness>,
//        rng: Option<&mut dyn RngCore>,
//    ) -> Result<Self::Proof, Self::Error>
//    where
//        P: 'a,
//        Self::Randomness: 'a,
//        Self::Commitment: 'a,
//    {
//        todo!()
//    }
//
//    /// check but with individual challenges
//    fn check_individual_opening_challenges<'a>(
//        vk: &Self::VerifierKey,
//        commitments: impl IntoIterator<Item = &'a LabeledCommitment<Self::Commitment>>,
//        point: &'a P::Point,
//        values: impl IntoIterator<Item = F>,
//        proof: &Self::Proof,
//        opening_challenges: &dyn Fn(u64) -> F,
//        rng: Option<&mut dyn RngCore>,
//    ) -> Result<bool, Self::Error>
//    where
//        Self::Commitment: 'a,
//    {
//        todo!()
//    }
//}
