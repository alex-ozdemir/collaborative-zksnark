#![allow(dead_code)]
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{Field, UniformRand, Zero};
use super::r1cs_to_qap::R1CStoQAP;
use ark_groth16::{Proof, ProvingKey, VerifyingKey};
use ark_poly::GeneralEvaluationDomain;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, Result as R1CSResult,
};
use ark_std::rand::Rng;
use ark_std::{end_timer, start_timer, vec::Vec};
use log::debug;

// Changelog:
// 1. Specialized to Bls12_377 (our MPC lifting machinery cannot be written fully generically b/c
//    of Rust type system/ ark design limitations).
// 2. Lift to MsmCurve.
// 3. Remove zero-check for prover randomness r.

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Create a Groth16 proof that is zero-knowledge.
/// This method samples randomness for zero knowledges via `rng`.
#[inline]
pub fn create_random_proof<E, C, R>(
    circuit: C,
    pk: &ProvingKey<E>,
    rng: &mut R,
) -> R1CSResult<Proof<E>>
where
    E: PairingEngine,
    //E::Fr: BatchProd,
    C: ConstraintSynthesizer<<E as PairingEngine>::Fr>,
    R: Rng,
{
    //use ark_ff::One;
    //let r = <E as PairingEngine>::Fr::one();
    //let s = <E as PairingEngine>::Fr::one();
    let t = start_timer!(|| "zk sampling");
    let r = <E as PairingEngine>::Fr::rand(rng);
    let s = <E as PairingEngine>::Fr::rand(rng);
    end_timer!(t);

    create_proof::<E, C>(circuit, pk, r, s)
}

/// Create a Groth16 proof that is *not* zero-knowledge.
#[inline]
pub fn create_proof_no_zk<E, C>(circuit: C, pk: &ProvingKey<E>) -> R1CSResult<Proof<E>>
where
    E: PairingEngine,
    //E::Fr: BatchProd,
    C: ConstraintSynthesizer<<E as PairingEngine>::Fr>,
{
    create_proof::<E, C>(
        circuit,
        pk,
        <E as PairingEngine>::Fr::zero(),
        <E as PairingEngine>::Fr::zero(),
    )
}

/// Create a Groth16 proof using randomness `r` and `s`.
#[inline]
pub fn create_proof<E, C>(
    circuit: C,
    pk: &ProvingKey<E>,
    r: <E as PairingEngine>::Fr,
    s: <E as PairingEngine>::Fr,
) -> R1CSResult<Proof<E>>
where
    E: PairingEngine,
    //E::Fr: BatchProd,
    C: ConstraintSynthesizer<<E as PairingEngine>::Fr>,
{
    debug!("r: {}", r);
    debug!("s: {}", s);
    type D<F> = GeneralEvaluationDomain<F>;

    let prover_time = start_timer!(|| "Groth16::Prover");
    let cs = ConstraintSystem::new_ref();

    // Set the optimization goal
    cs.set_optimization_goal(OptimizationGoal::Constraints);

    // Synthesize the circuit.
    let synthesis_time = start_timer!(|| "Constraint synthesis");
    circuit.generate_constraints(cs.clone())?;
    //debug_assert!(cs.is_satisfied().unwrap());
    end_timer!(synthesis_time);

    let lc_time = start_timer!(|| "Inlining LCs");
    cs.finalize();
    end_timer!(lc_time);

    let witness_map_time = start_timer!(|| "R1CS to QAP witness map");
    let h = R1CStoQAP::witness_map::<<E as PairingEngine>::Fr, D<<E as PairingEngine>::Fr>>(
        cs.clone(),
    )?;
    end_timer!(witness_map_time);
    let prover_crypto_time = start_timer!(|| "crypto");
    let c_acc_time = start_timer!(|| "Compute C");
    let h_acc = <<E as PairingEngine>::G1Affine as AffineCurve>::multi_scalar_mul(&pk.h_query, &h);
    debug!("h_acc: {}", h_acc);
    // Compute C
    let prover = cs.borrow().unwrap();
    let l_aux_acc = <<E as PairingEngine>::G1Affine as AffineCurve>::multi_scalar_mul(&pk.l_query, &prover.witness_assignment);

    let r_s_delta_g1 = pk
        .delta_g1
        .into_projective()
        .scalar_mul(&r)
        .scalar_mul(&s);
    debug!("r_s_delta_g1: {}", r_s_delta_g1);

    end_timer!(c_acc_time);

    let assignment: Vec<<E as PairingEngine>::Fr> = prover.instance_assignment[1..].iter().chain(prover.witness_assignment.iter()).cloned().collect();
    drop(prover);
    drop(cs);

    // Compute A
    let a_acc_time = start_timer!(|| "Compute A");
    let r_g1 = pk.delta_g1.scalar_mul(r);
    debug!("r_g1: {}", r_g1);
    // debug!("Assignment:");
    // for (i, a) in assignment.iter().enumerate() {
    //     debug!("  a[{}]: {}", i, a);
    // }

    let g_a = calculate_coeff(r_g1, &pk.a_query, pk.vk.alpha_g1, &assignment);
    debug!("g_a: {}", g_a);

    let s_g_a = g_a.scalar_mul(&s);
    debug!("s_g_a: {}", s_g_a);
    end_timer!(a_acc_time);

    // Compute B in G1 if needed
//    let g1_b = if !r.is_zero() {
        let b_g1_acc_time = start_timer!(|| "Compute B in G1");
        let s_g1 = pk.delta_g1.scalar_mul(s);
        let g1_b = calculate_coeff(s_g1, &pk.b_g1_query, pk.beta_g1, &assignment);

        end_timer!(b_g1_acc_time);
//
//        g1_b
//    } else {
//        <E as PairingEngine>::G1Projective::zero()
//    };

    // Compute B in G2
    let b_g2_acc_time = start_timer!(|| "Compute B in G2");
    let s_g2 = pk.vk.delta_g2.scalar_mul(s);
    let g2_b = calculate_coeff(s_g2, &pk.b_g2_query, pk.vk.beta_g2, &assignment);
    let r_g1_b = g1_b.scalar_mul(&r);
    debug!("r_g1_b: {}", r_g1_b);
    drop(assignment);

    end_timer!(b_g2_acc_time);

    let c_time = start_timer!(|| "Finish C");
    let mut g_c = s_g_a;
    g_c += &r_g1_b;
    g_c -= &r_s_delta_g1;
    g_c += &l_aux_acc;
    g_c += &h_acc;
    end_timer!(c_time);
    end_timer!(prover_crypto_time);

    end_timer!(prover_time);

    Ok(Proof {
        a: g_a.into_affine(),
        b: g2_b.into_affine(),
        c: g_c.into_affine(),
    })
}

/// Given a Groth16 proof, returns a fresh proof of the same statement. For a proof π of a
/// statement S, the output of the non-deterministic procedure `rerandomize_proof(π)` is
/// statistically indistinguishable from a fresh honest proof of S. For more info, see theorem 3 of
/// [\[BKSV20\]](https://eprint.iacr.org/2020/811)
pub fn rerandomize_proof<E, R>(rng: &mut R, vk: &VerifyingKey<E>, proof: &Proof<E>) -> Proof<E>
where
    E: PairingEngine,
    R: Rng,
{
    // These are our rerandomization factors. They must be nonzero and uniformly sampled.
    let (mut r1, mut r2) = (
        <E as PairingEngine>::Fr::zero(),
        <E as PairingEngine>::Fr::zero(),
    );
    while r1.is_zero() || r2.is_zero() {
        r1 = <E as PairingEngine>::Fr::rand(rng);
        r2 = <E as PairingEngine>::Fr::rand(rng);
    }

    // See figure 1 in the paper referenced above:
    //   A' = (1/r₁)A
    //   B' = r₁B + r₁r₂(δG₂)
    //   C' = C + r₂A

    // We can unwrap() this because r₁ is guaranteed to be nonzero
    let new_a = proof.a.scalar_mul(r1.inverse().unwrap());
    let new_b = proof.b.scalar_mul(r1) + &vk.delta_g2.scalar_mul(r1 * &r2);
    let new_c = proof.c + proof.a.scalar_mul(r2).into_affine();

    Proof {
        a: new_a.into_affine(),
        b: new_b.into_affine(),
        c: new_c,
    }
}

fn calculate_coeff<G: AffineCurve>(
    initial: G::Projective,
    query: &[G],
    vk_param: G,
    assignment: &[G::ScalarField],
) -> G::Projective where {
    let el = query[0];
    let t = start_timer!(|| format!("MSM size {} {}", query.len() - 1, assignment.len()));
    let acc = G::multi_scalar_mul(&query[1..], assignment);
    end_timer!(t);
    let mut res = initial;
    res.add_assign_mixed(&el);
    res += &acc;
    res.add_assign_mixed(&vk_param);

    res
}
