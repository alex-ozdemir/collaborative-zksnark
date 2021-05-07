use ark_ff::UniformRand;
use ark_poly::{univariate::DensePolynomial};
use ark_poly_commit::{marlin_pc::MarlinKZG10};
use mpc_algebra::{MpcPairingEngine, MpcVal};
use mpc_plonk::*;
use ark_std::{start_timer, end_timer, test_rng};
use std::collections::HashMap;

type F = ark_bls12_377::Fr;
type E = ark_bls12_377::Bls12_377;
type ME = MpcPairingEngine<ark_bls12_377::Bls12_377>;
type MF = MpcVal<F>;
type PC = MarlinKZG10<E, DensePolynomial<F>>;
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
    let d = Domains::from_circuit(&c);
    let circ = CircuitLayout::from_circuit(&c, &d);

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
    let d = Domains::from_circuit(&v_c);
    let v_circ = CircuitLayout::from_circuit(&v_c, &d);
    // setup
    let setup_rng = &mut test_rng();
    let srs = LocalPlonk::universal_setup(steps.next_power_of_two(), setup_rng);
    let (pk, vk) = LocalPlonk::circuit_setup(&srs, &v_circ);
    let mpc_pk = super::reveal::plonk::obs_pk(pk);

    // data circuit
    let data_rng = &mut test_rng();
    let start = MF::rand(data_rng);
    let res = (0..steps).fold(start, |a, _| a * a);
    let public: HashMap<String, F> = vec![("out".to_owned(), res.publicize_unwrap())].into_iter().collect();
    let c = PlonkCircuit::<MF>::new_squaring_circuit(steps, Some(start));
    let d = Domains::from_circuit(&c);
    let circ = CircuitLayout::from_circuit(&c, &d);

    let t = start_timer!(|| "timed section");
    let mpc_pf = MpcPlonk::prove(&mpc_pk, &circ, &mut test_rng());
    let pf = crate::reveal::plonk::pub_pf(mpc_pf);
    end_timer!(t);
    LocalPlonk::verify(&vk, &v_circ, pf, &public);
}
