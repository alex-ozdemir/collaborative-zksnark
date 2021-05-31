use ark_ff::UniformRand;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::marlin_pc::MarlinKZG10;
use ark_std::{end_timer, start_timer, test_rng};
use mpc_algebra::ss::honest_but_curious::*;
use mpc_plonk::*;
use mpc_trait::Reveal;
use std::collections::HashMap;

type F = ark_bls12_377::Fr;
type E = ark_bls12_377::Bls12_377;
type ME = MpcPairingEngine<ark_bls12_377::Bls12_377>;
type MF = MpcField<F>;
type MpcMarlinKZG10 = MarlinKZG10<ME, DensePolynomial<MF>>;
type LocalMarlinKZG10 = MarlinKZG10<E, DensePolynomial<F>>;
type LocalPlonk = mpc_plonk::Plonk<F, LocalMarlinKZG10>;
type MpcPlonk = mpc_plonk::Plonk<MF, MpcMarlinKZG10>;

pub fn local_test_prove_and_verify(n_iters: usize) {
    use relations::{flat::*, structured::*};
    let steps = n_iters;
    let start = F::from(2u64);
    let c = PlonkCircuit::<F>::new_squaring_circuit(steps, Some(start));
    let res = (0..steps).fold(start, |a, _| a * a);
    let public: HashMap<String, F> = vec![("out".to_owned(), res)].into_iter().collect();
    let circ = CircuitLayout::from_circuit(&c);

    let setup_rng = &mut test_rng();
    let zk_rng = &mut test_rng();

    let v_circ = {
        let mut t = circ.clone();
        t.p = None;
        t
    };

    let srs = LocalPlonk::universal_setup(steps.next_power_of_two(), setup_rng);
    let (pk, vk) = LocalPlonk::circuit_setup(&srs, &v_circ);
    let pf = LocalPlonk::prove(&pk, &circ, zk_rng);
    LocalPlonk::verify(&vk, &v_circ, pf, &public);
}

pub fn mpc_test_prove_and_verify(n_iters: usize) {
    use relations::{flat::*, structured::*};
    let steps = n_iters;

    // empty circuit
    let v_c = PlonkCircuit::<F>::new_squaring_circuit(steps, None);
    let v_circ = CircuitLayout::from_circuit(&v_c);
    // setup
    let setup_rng = &mut test_rng();
    let srs = LocalPlonk::universal_setup(steps.next_power_of_two(), setup_rng);
    let (pk, vk) = LocalPlonk::circuit_setup(&srs, &v_circ);

    // data circuit
    let data_rng = &mut test_rng();
    let start = MF::from_add_shared(F::rand(data_rng));
    let res = (0..steps).fold(start, |a, _| a * a);
    let public: HashMap<String, F> = vec![("out".to_owned(), res.reveal())]
        .into_iter()
        .collect();
    let c = PlonkCircuit::<MF>::new_squaring_circuit(steps, Some(start));
    let circ = CircuitLayout::from_circuit(&c);

    let t = start_timer!(|| "timed section");
    let mpc_pk = ProverKey::from_public(pk);
    let mpc_pf = MpcPlonk::prove(&mpc_pk, &circ, &mut test_rng());
    let pf = mpc_pf.reveal();
    end_timer!(t);
    LocalPlonk::verify(&vk, &v_circ, pf, &public);
}
