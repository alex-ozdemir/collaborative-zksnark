use mpc_algebra::*;
use ark_bls12_377::Bls12_377;
use ark_std::{test_rng, start_timer, end_timer, UniformRand};
use ark_groth16::{
    generate_random_parameters, prepare_verifying_key, verify_proof, Proof,
    ProvingKey, VerifyingKey,
};
use super::silly::MySillyCircuit;

pub mod prover;
pub mod r1cs_to_qap;

pub fn vk_to_mpc(k: VerifyingKey<Bls12_377>) -> VerifyingKey<MpcPairingEngine<Bls12_377>> {
    VerifyingKey {
        alpha_g1: MpcCurve::from_public(k.alpha_g1),
        beta_g2: MpcCurve2::from_public(k.beta_g2),
        gamma_g2: MpcCurve2::from_public(k.gamma_g2),
        delta_g2: MpcCurve2::from_public(k.delta_g2),
        gamma_abc_g1: k
            .gamma_abc_g1
            .into_iter()
            .map(MpcCurve::from_public)
            .collect(),
    }
}

pub fn pk_to_mpc(k: ProvingKey<Bls12_377>) -> ProvingKey<MpcPairingEngine<Bls12_377>> {
    ProvingKey {
        vk: vk_to_mpc(k.vk),
        beta_g1: MpcCurve::from_public(k.beta_g1),
        delta_g1: MpcCurve::from_public(k.delta_g1),
        a_query: k.a_query.into_iter().map(MpcCurve::from_public).collect(),
        b_g1_query: k
            .b_g1_query
            .into_iter()
            .map(MpcCurve::from_public)
            .collect(),
        b_g2_query: k
            .b_g2_query
            .into_iter()
            .map(MpcCurve2::from_public)
            .collect(),
        h_query: k.h_query.into_iter().map(MpcCurve::from_public).collect(),
        l_query: k.l_query.into_iter().map(MpcCurve::from_public).collect(),
    }
}

pub fn pf_publicize(k: Proof<MpcPairingEngine<Bls12_377>>) -> Proof<Bls12_377> {
    let pf_timer = start_timer!(|| "publicize proof");
    let r = Proof {
        a: k.a.publicize_unwrap(),
        b: k.b.publicize_unwrap(),
        c: k.c.publicize_unwrap(),
    };
    end_timer!(pf_timer);
    r
}

pub fn mpc_test_prove_and_verify(n_iters: usize) {
    let rng = &mut test_rng();

    let params =
        generate_random_parameters::<Bls12_377, _, _>(MySillyCircuit { a: None, b: None }, rng)
            .unwrap();

    let pvk = prepare_verifying_key::<Bls12_377>(&params.vk);
    let mpc_params = pk_to_mpc(params);

    for _ in 0..n_iters {
        let a = MpcVal::<ark_bls12_377::Fr>::rand(rng);
        let b = MpcVal::<ark_bls12_377::Fr>::rand(rng);
        let mut c = a;
        c *= &b;

        let mpc_proof = prover::create_random_proof::<MpcPairingEngine<Bls12_377>, _, _>(
            MySillyCircuit {
                a: Some(a),
                b: Some(b),
            },
            &mpc_params,
            rng
        )
        .unwrap();
        let proof = pf_publicize(mpc_proof);
        let pub_a = a.publicize_unwrap();
        let pub_c = c.publicize_unwrap();

        assert!(verify_proof(&pvk, &proof, &[pub_c]).unwrap());
        assert!(!verify_proof(&pvk, &proof, &[pub_a]).unwrap());
    }
}
