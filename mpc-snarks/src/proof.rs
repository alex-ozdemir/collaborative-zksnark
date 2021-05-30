#![allow(dead_code)]
#![allow(unused_imports)]
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
use structopt::StructOpt;

use std::net::{SocketAddr, ToSocketAddrs};

mod groth;
mod marlin;
mod silly;
use mpc_algebra::{channel, ss::honest_but_curious::*};
use mpc_trait::Reveal;

// Field
type Fr = ark_bls12_377::Fr;
// Pairing (E)ngine
type E = ark_bls12_377::Bls12_377;
// MPC Field
type MFr = MpcField<Fr>;
// MPC pairing engine
type ME = MpcPairingEngine<E>;

const TIMED_SECTION_LABEL: &str = "timed section";

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

        pub fn mpc(n: usize) {
            let rng = &mut test_rng();
            let circ_no_data = RepeatedSquaringCircuit::without_data(n);

            let params = generate_random_parameters::<E, _, _>(circ_no_data, rng).unwrap();

            let pvk = prepare_verifying_key::<E>(&params.vk);
            let mpc_params = Reveal::from_public(params);

            let a = Fr::rand(rng);
            let computation_timer = start_timer!(|| "do the mpc (cheat)");
            let circ_data = mpc_squaring_circuit(a, n);
            let public_inputs = vec![circ_data.chain.last().unwrap().unwrap().reveal()];
            end_timer!(computation_timer);
            channel::reset_stats();
            let timer = start_timer!(|| TIMED_SECTION_LABEL);
            let mpc_proof = create_random_proof::<ME, _, _>(circ_data, &mpc_params, rng).unwrap();
            let proof = mpc_proof.reveal();
            end_timer!(timer);

            assert!(verify_proof(&pvk, &proof, &public_inputs).unwrap());
        }

        pub fn local(n: usize) {
            let rng = &mut test_rng();
            let circ_no_data = RepeatedSquaringCircuit::without_data(n);

            let params = generate_random_parameters::<E, _, _>(circ_no_data, rng).unwrap();

            let pvk = prepare_verifying_key::<E>(&params.vk);

            let a = Fr::rand(rng);
            let circ_data = RepeatedSquaringCircuit::from_start(a, n);
            let public_inputs = vec![circ_data.chain.last().unwrap().unwrap()];
            let timer = start_timer!(|| TIMED_SECTION_LABEL);
            let proof = create_random_proof::<E, _, _>(circ_data, &params, rng).unwrap();
            end_timer!(timer);

            assert!(verify_proof(&pvk, &proof, &public_inputs).unwrap());
        }

        pub fn local_ark(n: usize) {
            let rng = &mut test_rng();
            let circ_no_data = RepeatedSquaringCircuit::without_data(n);

            let params = generate_random_parameters::<E, _, _>(circ_no_data, rng).unwrap();

            let pvk = prepare_verifying_key::<E>(&params.vk);

            let a = Fr::rand(rng);
            let circ_data = RepeatedSquaringCircuit::from_start(a, n);
            let public_inputs = vec![circ_data.chain.last().unwrap().unwrap()];
            let timer = start_timer!(|| TIMED_SECTION_LABEL);
            let proof =
                ark_groth16::create_random_proof::<E, _, _>(circ_data, &params, rng).unwrap();
            end_timer!(timer);

            assert!(verify_proof(&pvk, &proof, &public_inputs).unwrap());
        }
    }

    pub mod marlin {
        use super::*;
        use ark_marlin::Marlin;
        use ark_marlin::*;
        use ark_poly::univariate::DensePolynomial;
        use ark_poly_commit::marlin::marlin_pc::MarlinKZG10;

        type LocalMarlin = Marlin<Fr, MarlinKZG10<E, DensePolynomial<Fr>>, Blake2s>;
        type MpcMarlin = Marlin<MFr, MarlinKZG10<ME, DensePolynomial<MFr>>, Blake2s>;

        pub fn local(n: usize) {
            let rng = &mut test_rng();
            let circ_no_data = RepeatedSquaringCircuit::without_data(n);

            let srs = LocalMarlin::universal_setup(n, n + 2, 3 * n, rng).unwrap();

            let (pk, vk) = LocalMarlin::index(&srs, circ_no_data).unwrap();

            let a = Fr::rand(rng);
            let circ_data = RepeatedSquaringCircuit::from_start(a, n);
            let public_inputs = vec![circ_data.chain.last().unwrap().unwrap()];
            let timer = start_timer!(|| TIMED_SECTION_LABEL);
            let zk_rng = &mut test_rng();
            let proof = LocalMarlin::prove(&pk, circ_data, zk_rng).unwrap();
            end_timer!(timer);
            assert!(LocalMarlin::verify(&vk, &public_inputs, &proof, rng).unwrap());
        }

        pub fn mpc(n: usize) {
            let rng = &mut test_rng();
            let circ_no_data = RepeatedSquaringCircuit::without_data(n);

            let srs = LocalMarlin::universal_setup(n, n + 2, 3 * n, rng).unwrap();

            let (pk, vk) = LocalMarlin::index(&srs, circ_no_data).unwrap();
            let mpc_pk = IndexProverKey::from_public(pk);

            let a = Fr::rand(rng);
            let computation_timer = start_timer!(|| "do the mpc (cheat)");
            let circ_data = mpc_squaring_circuit(a, n);
            let public_inputs = vec![circ_data.chain.last().unwrap().unwrap().reveal()];
            end_timer!(computation_timer);

            let timer = start_timer!(|| TIMED_SECTION_LABEL);
            let zk_rng = &mut test_rng();
            let mpc_proof = MpcMarlin::prove(&mpc_pk, circ_data, zk_rng).unwrap();
            let proof = mpc_proof.reveal();
            end_timer!(timer);
            assert!(LocalMarlin::verify(&vk, &public_inputs, &proof, rng).unwrap());
        }
    }

    pub mod plonk {
        use super::*;
        use ark_poly::univariate::DensePolynomial;
        use ark_poly_commit::marlin::marlin_pc::MarlinKZG10;
        use mpc_plonk::relations::flat::CircuitLayout;
        use mpc_plonk::relations::structured::PlonkCircuit;
        use mpc_plonk::*;
        use mpc_trait::Reveal;

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
        type LocalPlonk = mpc_plonk::Plonk<Fr, MarlinKZG10<E, DensePolynomial<Fr>>>;
        type MpcPlonk = mpc_plonk::Plonk<MFr, MarlinKZG10<ME, DensePolynomial<MFr>>>;

        pub fn local(n: usize) {
            let rng = &mut test_rng();
            let circ_no_data = plonk_squaring_circuit(RepeatedSquaringCircuit::without_data(n));
            let circ_no_data = CircuitLayout::from_circuit(&circ_no_data);

            let a = Fr::rand(rng);
            let circ_data = RepeatedSquaringCircuit::from_start(a, n);
            let plonk_circ_data = plonk_squaring_circuit(circ_data.clone());
            let plonk_circ_data = CircuitLayout::from_circuit(&plonk_circ_data);
            let public_inputs =
                std::iter::once(("out".to_owned(), circ_data.chain.last().unwrap().unwrap()))
                    .collect();
            let setup_rng = &mut test_rng();
            let zk_rng = &mut test_rng();
            let srs = LocalPlonk::universal_setup(n.next_power_of_two(), setup_rng);
            let (pk, vk) = LocalPlonk::circuit_setup(&srs, &circ_no_data);
            let timer = start_timer!(|| TIMED_SECTION_LABEL);
            let pf = LocalPlonk::prove(&pk, &plonk_circ_data, zk_rng);
            end_timer!(timer);
            LocalPlonk::verify(&vk, &circ_no_data, pf, &public_inputs);
        }

        pub fn mpc(n: usize) {
            let rng = &mut test_rng();
            let circ_no_data = plonk_squaring_circuit(RepeatedSquaringCircuit::without_data(n));
            let circ_no_data = CircuitLayout::from_circuit(&circ_no_data);

            let a = Fr::rand(rng);
            let circ_data = mpc_squaring_circuit(a, n);
            let plonk_circ_data = plonk_squaring_circuit(circ_data.clone());
            let plonk_circ_data = CircuitLayout::from_circuit(&plonk_circ_data);
            let public_inputs = std::iter::once((
                "out".to_owned(),
                circ_data.chain.last().unwrap().unwrap().reveal(),
            ))
            .collect();
            let setup_rng = &mut test_rng();
            let zk_rng = &mut test_rng();
            let srs = LocalPlonk::universal_setup(n.next_power_of_two(), setup_rng);
            let (pk, vk) = LocalPlonk::circuit_setup(&srs, &circ_no_data);
            let t = start_timer!(|| TIMED_SECTION_LABEL);
            let mpc_pk = ProverKey::from_public(pk);
            let mpc_pf = MpcPlonk::prove(&mpc_pk, &plonk_circ_data, zk_rng);
            let pf = mpc_pf.reveal();
            end_timer!(t);
            LocalPlonk::verify(&vk, &circ_no_data, pf, &public_inputs);
        }
    }

    fn mpc_squaring_circuit(start: Fr, squarings: usize) -> RepeatedSquaringCircuit<MFr> {
        let rng = &mut test_rng();
        let raw_chain: Vec<Fr> = std::iter::successors(Some(start), |a| Some(a.square()))
            .take(squarings + 1)
            .collect();
        let randomness: Vec<Fr> = std::iter::repeat_with(|| Fr::rand(rng))
            .take(squarings + 1)
            .collect();
        let first_shares: Vec<Fr> = randomness
            .iter()
            .zip(raw_chain.into_iter())
            .map(|(r, v)| v + r)
            .collect();
        let second_shares: Vec<Fr> = randomness.into_iter().map(|r| -r).collect();

        let my_shares = if channel::am_first() {
            channel::exchange(second_shares);
            first_shares
        } else {
            let zeros: Vec<Fr> = std::iter::repeat_with(|| Fr::from(0u64))
                .take(squarings + 1)
                .collect();
            channel::exchange(zeros.clone())
        };
        RepeatedSquaringCircuit {
            chain: my_shares
                .into_iter()
                .map(|s| Some(MpcField::from_add_shared(s)))
                .collect(),
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
struct PartyInfo {
    /// Your host
    #[structopt(long, default_value = "localhost")]
    host: String,

    /// Your port
    #[structopt(long, default_value = "8000")]
    port: u16,

    /// Peer host
    #[structopt(long, default_value = "localhost")]
    peer_host: String,

    /// Peer port
    #[structopt(long, default_value = "8000")]
    peer_port: u16,

    /// Which party are you? 0 or 1?
    #[structopt(long, default_value = "0")]
    party: u8,
}

impl PartyInfo {
    fn setup(&self) {
        let self_addr = (self.host.clone(), self.port)
            .to_socket_addrs()
            .unwrap()
            .filter(SocketAddr::is_ipv4)
            .next()
            .unwrap();
        let peer_addr = (self.peer_host.clone(), self.peer_port)
            .to_socket_addrs()
            .unwrap()
            .filter(SocketAddr::is_ipv4)
            .next()
            .unwrap();
        channel::init(self_addr, peer_addr, self.party == 0);
    }
    fn teardown(&self) {
        debug!("Stats: {:#?}", channel::stats());
        channel::deinit();
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
        party_info: PartyInfo,
    },
    Local,
    ArkLocal,
}

impl FieldOpt {
    fn setup(&self) {
        match self {
            FieldOpt::Mpc { party_info } => party_info.setup(),
            _ => {}
        }
    }
    fn teardown(&self) {
        match self {
            FieldOpt::Mpc { party_info } => party_info.teardown(),
            _ => {}
        }
    }
    fn run(&self, computation: Computation, proof_system: ProofSystem, computation_size: usize) {
        self.setup();
        match computation {
            Computation::Squaring => match (self, proof_system) {
                (FieldOpt::Mpc { .. }, ProofSystem::Groth16) => {
                    squarings::groth::mpc(computation_size);
                }
                (FieldOpt::Mpc { .. }, ProofSystem::Marlin) => {
                    squarings::marlin::mpc(computation_size);
                }
                (FieldOpt::Mpc { .. }, ProofSystem::Plonk) => {
                    squarings::plonk::mpc(computation_size);
                }
                (FieldOpt::Local, ProofSystem::Groth16) => {
                    squarings::groth::local(computation_size);
                }
                (FieldOpt::Local, ProofSystem::Marlin) => {
                    squarings::marlin::local(computation_size);
                }
                (FieldOpt::Local, ProofSystem::Plonk) => {
                    squarings::plonk::local(computation_size);
                }
                (FieldOpt::ArkLocal, ProofSystem::Groth16) => {
                    squarings::groth::local_ark(computation_size);
                }
                _ => unimplemented!(
                    "Proof {:?} with field configuration {:?}",
                    proof_system,
                    self
                ),
            },
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
    opt.field
        .run(opt.computation, opt.proof_system, opt.computation_size);
    println!("Exchange stats: {:#?}", channel::stats());
}
