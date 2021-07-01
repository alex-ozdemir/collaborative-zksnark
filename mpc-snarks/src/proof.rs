#![allow(dead_code)]
#![allow(unused_imports)]
use ark_ec::PairingEngine;
use ark_ff::{Field, UniformRand};
use ark_groth16;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable},
};
use ark_std::test_rng;
use ark_std::{end_timer, start_timer};
use blake2::Blake2s;
use clap::arg_enum;
use log::debug;
use mpc_algebra::{channel, MpcPairingEngine, PairingShare, Reveal};
use mpc_net::{MpcMultiNet, MpcNet, MpcTwoNet};
use structopt::StructOpt;

use std::path::PathBuf;

mod groth;
mod marlin;
mod silly;

const TIMED_SECTION_LABEL: &str = "timed section";

trait SnarkBench {
    fn local<E: PairingEngine>(n: usize, timer_label: &str);
    fn ark_local<E: PairingEngine>(_n: usize, _timer_label: &str) {
        unimplemented!("ark benchmark for {}", std::any::type_name::<Self>())
    }
    fn mpc<E: PairingEngine, S: PairingShare<E>>(n: usize, timer_label: &str);
}

mod squarings {
    use super::*;
    #[derive(Clone)]
    struct RepeatedSquaringCircuit<F: Field> {
        chain: Vec<Option<F>>,
    }

    impl<F: Field> RepeatedSquaringCircuit<F> {
        fn without_data(squarings: usize) -> Self {
            Self {
                chain: vec![None; squarings + 1],
            }
        }
        fn from_start(f: F, squarings: usize) -> Self {
            let mut chain = vec![Some(f)];
            for _ in 0..squarings {
                let mut last = chain.last().unwrap().as_ref().unwrap().clone();
                last.square_in_place();
                chain.push(Some(last));
            }
            Self { chain }
        }
        fn from_chain(f: Vec<F>) -> Self {
            Self {
                chain: f.into_iter().map(Some).collect(),
            }
        }
        fn squarings(&self) -> usize {
            self.chain.len() - 1
        }
    }

    pub mod groth {
        use super::*;
        use crate::ark_groth16::{generate_random_parameters, prepare_verifying_key, verify_proof};
        use crate::groth::prover::create_random_proof;

        pub struct Groth16Bench;

        impl SnarkBench for Groth16Bench {
            fn local<E: PairingEngine>(n: usize, timer_label: &str) {
                let rng = &mut test_rng();
                let circ_no_data = RepeatedSquaringCircuit::without_data(n);

                let params = generate_random_parameters::<E, _, _>(circ_no_data, rng).unwrap();

                let pvk = prepare_verifying_key::<E>(&params.vk);

                let a = E::Fr::rand(rng);
                let circ_data = RepeatedSquaringCircuit::from_start(a, n);
                let public_inputs = vec![circ_data.chain.last().unwrap().unwrap()];
                let timer = start_timer!(|| timer_label);
                let proof = create_random_proof::<E, _, _>(circ_data, &params, rng).unwrap();
                end_timer!(timer);

                assert!(verify_proof(&pvk, &proof, &public_inputs).unwrap());
            }

            fn ark_local<E: PairingEngine>(n: usize, timer_label: &str) {
                let rng = &mut test_rng();
                let circ_no_data = RepeatedSquaringCircuit::without_data(n);

                let params = generate_random_parameters::<E, _, _>(circ_no_data, rng).unwrap();

                let pvk = prepare_verifying_key::<E>(&params.vk);

                let a = E::Fr::rand(rng);
                let circ_data = RepeatedSquaringCircuit::from_start(a, n);
                let public_inputs = vec![circ_data.chain.last().unwrap().unwrap()];
                let timer = start_timer!(|| timer_label);
                let proof =
                    ark_groth16::create_random_proof::<E, _, _>(circ_data, &params, rng).unwrap();
                end_timer!(timer);

                assert!(verify_proof(&pvk, &proof, &public_inputs).unwrap());
            }

            fn mpc<E: PairingEngine, S: PairingShare<E>>(n: usize, timer_label: &str) {
                let rng = &mut test_rng();
                let circ_no_data = RepeatedSquaringCircuit::without_data(n);

                let params = generate_random_parameters::<E, _, _>(circ_no_data, rng).unwrap();

                let pvk = prepare_verifying_key::<E>(&params.vk);
                let mpc_params = Reveal::from_public(params);

                let a = E::Fr::rand(rng);
                let computation_timer = start_timer!(|| "do the mpc (cheat)");
                let circ_data = mpc_squaring_circuit::<
                    E::Fr,
                    <MpcPairingEngine<E, S> as PairingEngine>::Fr,
                >(a, n);
                let public_inputs = vec![circ_data.chain.last().unwrap().unwrap().reveal()];
                end_timer!(computation_timer);
                MpcMultiNet::reset_stats();
                let timer = start_timer!(|| timer_label);
                let proof = channel::without_cheating(|| {
                    let pf = create_random_proof::<MpcPairingEngine<E, S>, _, _>(circ_data, &mpc_params, rng)
                        .unwrap();
                    let reveal_timer = start_timer!(|| "reveal");
                    let pf = pf.reveal();
                    end_timer!(reveal_timer);
                    pf
                });
                end_timer!(timer);

                assert!(verify_proof(&pvk, &proof, &public_inputs).unwrap());
            }
        }
    }

    pub mod marlin {
        use super::*;
        use ark_marlin::Marlin;
        use ark_marlin::*;
        use ark_poly::univariate::DensePolynomial;
        use ark_poly_commit::marlin::marlin_pc::MarlinKZG10;

        type KzgMarlin<Fr, E> = Marlin<Fr, MarlinKZG10<E, DensePolynomial<Fr>>, Blake2s>;

        pub struct MarlinBench;

        impl SnarkBench for MarlinBench {
            fn local<E: PairingEngine>(n: usize, timer_label: &str) {
                let rng = &mut test_rng();
                let circ_no_data = RepeatedSquaringCircuit::without_data(n);

                let srs = KzgMarlin::<E::Fr, E>::universal_setup(n, n + 2, 3 * n, rng).unwrap();

                let (pk, vk) = KzgMarlin::<E::Fr, E>::index(&srs, circ_no_data).unwrap();

                let a = E::Fr::rand(rng);
                let circ_data = RepeatedSquaringCircuit::from_start(a, n);
                let public_inputs = vec![circ_data.chain.last().unwrap().unwrap()];
                let timer = start_timer!(|| timer_label);
                let zk_rng = &mut test_rng();
                let proof = KzgMarlin::<E::Fr, E>::prove(&pk, circ_data, zk_rng).unwrap();
                end_timer!(timer);
                assert!(KzgMarlin::<E::Fr, E>::verify(&vk, &public_inputs, &proof, rng).unwrap());
            }

            fn mpc<E: PairingEngine, S: PairingShare<E>>(n: usize, timer_label: &str) {
                let rng = &mut test_rng();
                let circ_no_data = RepeatedSquaringCircuit::without_data(n);

                let srs = KzgMarlin::<E::Fr, E>::universal_setup(n, n + 2, 3 * n, rng).unwrap();

                let (pk, vk) = KzgMarlin::<E::Fr, E>::index(&srs, circ_no_data).unwrap();
                let mpc_pk = IndexProverKey::from_public(pk);

                let a = E::Fr::rand(rng);
                let computation_timer = start_timer!(|| "do the mpc (cheat)");
                let circ_data = mpc_squaring_circuit::<
                    E::Fr,
                    <MpcPairingEngine<E, S> as PairingEngine>::Fr,
                >(a, n);
                let public_inputs = vec![circ_data.chain.last().unwrap().unwrap().reveal()];
                end_timer!(computation_timer);

                MpcMultiNet::reset_stats();
                let timer = start_timer!(|| timer_label);
                let zk_rng = &mut test_rng();
                let proof = channel::without_cheating(|| {
                    KzgMarlin::<
                        <MpcPairingEngine<E, S> as PairingEngine>::Fr,
                        MpcPairingEngine<E, S>,
                    >::prove(&mpc_pk, circ_data, zk_rng)
                    .unwrap()
                    .reveal()
                });
                end_timer!(timer);
                assert!(KzgMarlin::<E::Fr, E>::verify(&vk, &public_inputs, &proof, rng).unwrap());
            }
        }
    }

    pub mod plonk {
        use super::*;
        use ark_poly::univariate::DensePolynomial;
        use ark_poly_commit::marlin::marlin_pc::MarlinKZG10;
        use mpc_algebra::Reveal;
        use mpc_plonk::relations::flat::CircuitLayout;
        use mpc_plonk::relations::structured::PlonkCircuit;
        use mpc_plonk::*;

        fn plonk_squaring_circuit<F: Field>(c: RepeatedSquaringCircuit<F>) -> PlonkCircuit<F> {
            let n_gates = c.chain.len() as u32 - 1;
            let n_vars = n_gates + 1;
            let last_var = n_vars as u32 - 1;
            let mut this = PlonkCircuit {
                n_vars,
                pub_vars: std::iter::once((last_var, "out".to_owned())).collect(),
                prods: (0..(n_vars - 1)).map(|i| (i, i, i + 1)).collect(),
                sums: Vec::new(),
                values: c.chain.into_iter().collect(),
            };
            this.pad_to_power_of_2();
            this
        }
        type MarlinPcPlonk<Fr, E> = mpc_plonk::Plonk<Fr, MarlinKZG10<E, DensePolynomial<Fr>>>;

        pub struct PlonkBench;

        impl SnarkBench for PlonkBench {
            fn local<E: PairingEngine>(n: usize, timer_label: &str) {
                let rng = &mut test_rng();
                let circ_no_data = plonk_squaring_circuit(RepeatedSquaringCircuit::without_data(n));
                let circ_no_data = CircuitLayout::from_circuit(&circ_no_data);

                let a = E::Fr::rand(rng);
                let circ_data = RepeatedSquaringCircuit::from_start(a, n);
                let plonk_circ_data = plonk_squaring_circuit(circ_data.clone());
                let plonk_circ_data = CircuitLayout::from_circuit(&plonk_circ_data);
                let public_inputs =
                    std::iter::once(("out".to_owned(), circ_data.chain.last().unwrap().unwrap()))
                        .collect();
                let setup_rng = &mut test_rng();
                let zk_rng = &mut test_rng();
                let srs =
                    MarlinPcPlonk::<E::Fr, E>::universal_setup(n.next_power_of_two(), setup_rng);
                let (pk, vk) = MarlinPcPlonk::<E::Fr, E>::circuit_setup(&srs, &circ_no_data);
                let timer = start_timer!(|| timer_label);
                let pf = MarlinPcPlonk::<E::Fr, E>::prove(&pk, &plonk_circ_data, zk_rng);
                end_timer!(timer);
                MarlinPcPlonk::<E::Fr, E>::verify(&vk, &circ_no_data, pf, &public_inputs);
            }

            fn mpc<E: PairingEngine, S: PairingShare<E>>(n: usize, timer_label: &str) {
                let rng = &mut test_rng();
                let circ_no_data = plonk_squaring_circuit(RepeatedSquaringCircuit::without_data(n));
                let circ_no_data = CircuitLayout::from_circuit(&circ_no_data);

                let a = E::Fr::rand(rng);
                let circ_data = mpc_squaring_circuit::<
                    E::Fr,
                    <MpcPairingEngine<E, S> as PairingEngine>::Fr,
                >(a, n);
                let plonk_circ_data = plonk_squaring_circuit(circ_data.clone());
                let plonk_circ_data = CircuitLayout::from_circuit(&plonk_circ_data);
                let public_inputs = std::iter::once((
                    "out".to_owned(),
                    circ_data.chain.last().unwrap().unwrap().reveal(),
                ))
                .collect();
                let setup_rng = &mut test_rng();
                let zk_rng = &mut test_rng();
                let srs =
                    MarlinPcPlonk::<E::Fr, E>::universal_setup(n.next_power_of_two(), setup_rng);
                let (pk, vk) = MarlinPcPlonk::<E::Fr, E>::circuit_setup(&srs, &circ_no_data);
                let mpc_pk = Reveal::from_public(pk);
                MpcMultiNet::reset_stats();
                let t = start_timer!(|| timer_label);
                let pf = channel::without_cheating(|| {
                    let pf = MarlinPcPlonk::<
                        <MpcPairingEngine<E, S> as PairingEngine>::Fr,
                        MpcPairingEngine<E, S>,
                    >::prove(&mpc_pk, &plonk_circ_data, zk_rng);

                    let reveal_timer = start_timer!(|| "reveal");
                    let pf = pf.reveal();
                    end_timer!(reveal_timer);
                    pf
                });
                end_timer!(t);
                MarlinPcPlonk::<E::Fr, E>::verify(&vk, &circ_no_data, pf, &public_inputs);
            }
        }
    }

    fn mpc_squaring_circuit<Fr: Field, MFr: Field + Reveal<Base = Fr>>(
        start: Fr,
        squarings: usize,
    ) -> RepeatedSquaringCircuit<MFr> {
        let raw_chain: Vec<Fr> = std::iter::successors(Some(start), |a| Some(a.square()))
            .take(squarings + 1)
            .collect();
        let rng = &mut test_rng();
        let chain_shares = MFr::king_share_batch(raw_chain, rng);
        RepeatedSquaringCircuit {
            chain: chain_shares.into_iter().map(Some).collect(),
        }
    }

    impl<ConstraintF: Field> ConstraintSynthesizer<ConstraintF>
        for RepeatedSquaringCircuit<ConstraintF>
    {
        fn generate_constraints(
            self,
            cs: ConstraintSystemRef<ConstraintF>,
        ) -> Result<(), SynthesisError> {
            let mut vars: Vec<Variable> = self
                .chain
                .iter()
                .take(self.squarings())
                .map(|o| cs.new_witness_variable(|| o.ok_or(SynthesisError::AssignmentMissing)))
                .collect::<Result<_, _>>()?;
            vars.push(cs.new_input_variable(|| {
                self.chain
                    .last()
                    .unwrap()
                    .ok_or(SynthesisError::AssignmentMissing)
            })?);

            for i in 0..self.squarings() {
                cs.enforce_constraint(lc!() + vars[i], lc!() + vars[i], lc!() + vars[i + 1])?;
            }

            Ok(())
        }
    }
}

#[derive(Debug, StructOpt)]
struct ShareInfo {
    /// File with list of hosts
    #[structopt(long, parse(from_os_str))]
    hosts: PathBuf,

    /// Which party are you? 0 or 1?
    #[structopt(long, default_value = "0")]
    party: u8,

    /// Use spdz?
    #[structopt(long)]
    alg: MpcAlg,
}

impl ShareInfo {
    fn setup(&self) {
        MpcMultiNet::init_from_file(self.hosts.to_str().unwrap(), self.party as usize)
    }
    fn teardown(&self) {
        debug!("Stats: {:#?}", MpcMultiNet::stats());
        MpcMultiNet::deinit();
    }
    fn run<E: PairingEngine, B: SnarkBench>(
        &self,
        computation: Computation,
        computation_size: usize,
        _b: B,
        timed_label: &str,
    ) {
        match computation {
            Computation::Squaring => match self.alg {
                MpcAlg::Spdz => B::mpc::<E, mpc_algebra::share::spdz::SpdzPairingShare<E>>(
                    computation_size,
                    timed_label,
                ),
                MpcAlg::Hbc => B::mpc::<E, mpc_algebra::share::add::AdditivePairingShare<E>>(
                    computation_size,
                    timed_label,
                ),
                MpcAlg::Gsz => B::mpc::<E, mpc_algebra::share::gsz20::GszPairingShare<E>>(
                    computation_size,
                    timed_label,
                ),
            },
        }
    }
}

arg_enum! {
    #[derive(PartialEq, Debug, Clone, Copy)]
    pub enum MpcAlg {
        Spdz,
        Hbc,
        Gsz,
    }
}

arg_enum! {
    #[derive(PartialEq, Debug, Clone, Copy)]
    pub enum Computation {
        Squaring,
    }
}

arg_enum! {
    #[derive(PartialEq, Debug, Clone, Copy)]
    pub enum ProofSystem {
        Groth16,
        Marlin,
        Plonk,
    }
}

#[derive(Debug, StructOpt)]
enum FieldOpt {
    Mpc {
        #[structopt(flatten)]
        party_info: ShareInfo,
    },
    Local,
    ArkLocal,
}

impl FieldOpt {
    fn setup(&self) {
        match self {
            FieldOpt::Mpc { party_info, .. } => party_info.setup(),
            _ => {}
        }
    }
    fn teardown(&self) {
        match self {
            FieldOpt::Mpc { party_info, .. } => party_info.teardown(),
            _ => {}
        }
        println!("Stats: {:#?}", MpcMultiNet::stats());
    }
    fn run<E: PairingEngine, B: SnarkBench>(
        &self,
        computation: Computation,
        computation_size: usize,
        b: B,
        timed_label: &str,
    ) {
        self.setup();
        match self {
            FieldOpt::Mpc { party_info, .. } => {
                party_info.run::<E, B>(computation, computation_size, b, timed_label)
            }
            FieldOpt::Local => B::local::<E>(computation_size, timed_label),
            FieldOpt::ArkLocal => B::ark_local::<E>(computation_size, timed_label),
        }
        self.teardown();
    }
}

#[derive(Debug, StructOpt)]
#[structopt(name = "proof", about = "Standard and MPC proofs")]
struct Opt {
    /// Computation to perform
    #[structopt(short = "c")]
    computation: Computation,

    /// Proof system to use
    #[structopt(short = "p")]
    proof_system: ProofSystem,

    /// Computation to perform
    #[structopt(long, default_value = "10")]
    computation_size: usize,

    #[structopt(subcommand)]
    field: FieldOpt,
}

impl Opt {}

fn main() {
    let opt = Opt::from_args();
    env_logger::init();
    match opt.proof_system {
        ProofSystem::Groth16 => opt.field.run::<ark_bls12_377::Bls12_377, _>(
            opt.computation,
            opt.computation_size,
            squarings::groth::Groth16Bench,
            TIMED_SECTION_LABEL,
        ),
        ProofSystem::Plonk => opt.field.run::<ark_bls12_377::Bls12_377, _>(
            opt.computation,
            opt.computation_size,
            squarings::plonk::PlonkBench,
            TIMED_SECTION_LABEL,
        ),
        ProofSystem::Marlin => opt.field.run::<ark_bls12_377::Bls12_377, _>(
            opt.computation,
            opt.computation_size,
            squarings::marlin::MarlinBench,
            TIMED_SECTION_LABEL,
        ),
    }
}
