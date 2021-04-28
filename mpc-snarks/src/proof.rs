use ark_bls12_377::Bls12_377;
use ark_ff::{Field, UniformRand};
use ark_groth16::{generate_random_parameters, prepare_verifying_key, verify_proof};
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable},
};
use ark_std::test_rng;
use ark_std::{end_timer, start_timer};
use clap::arg_enum;
use log::debug;
use structopt::StructOpt;
use mpc_trait::MpcWire;

use std::net::{SocketAddr, ToSocketAddrs};

mod groth;
mod silly;
use groth::{pf_publicize, pk_to_mpc, prover::create_random_proof};
use mpc_algebra::{channel, MpcPairingEngine, MpcVal};

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
        Self { chain: f.into_iter().map(Some).collect() }
    }
    fn squarings(&self) -> usize {
        self.chain.len() - 1
    }
}

fn mpc_squaring_circuit(start: ark_bls12_377::Fr, squarings: usize) -> RepeatedSquaringCircuit<MpcVal<ark_bls12_377::Fr>> {
    let rng = &mut test_rng();
    let raw_chain: Vec<ark_bls12_377::Fr> = std::iter::successors(Some(start), |a| Some(a.square())).take(squarings + 1).collect();
    let randomness: Vec<ark_bls12_377::Fr> = std::iter::repeat_with(|| ark_bls12_377::Fr::rand(rng)).take(squarings + 1).collect();
    let first_shares: Vec<ark_bls12_377::Fr> = randomness.iter().zip(raw_chain.into_iter()).map(|(r, v)| v + r).collect();
    let second_shares: Vec<ark_bls12_377::Fr> = randomness.into_iter().map(|r| -r).collect();

    let my_shares = if channel::am_first() {
        channel::exchange(second_shares);
        first_shares
    } else {
        let zeros: Vec<ark_bls12_377::Fr> = std::iter::repeat_with(|| ark_bls12_377::Fr::from(0u64)).take(squarings + 1).collect();
        channel::exchange(zeros.clone())
    };
    RepeatedSquaringCircuit { chain: my_shares.into_iter().map(|s| Some(MpcVal::from_shared(s))).collect() }
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

fn test_squaring_mpc(n: usize) {
    let rng = &mut test_rng();
    let circ_no_data = RepeatedSquaringCircuit::without_data(n);

    let params = generate_random_parameters::<Bls12_377, _, _>(circ_no_data, rng).unwrap();

    let pvk = prepare_verifying_key::<Bls12_377>(&params.vk);
    let mpc_params = pk_to_mpc(params);

    let a = ark_bls12_377::Fr::rand(rng);
    let computation_timer = start_timer!(|| "do the mpc (cheat)");
    let circ_data = mpc_squaring_circuit(a, n);
    let public_inputs = vec![circ_data.chain.last().unwrap().unwrap().publicize_unwrap()];
    end_timer!(computation_timer);
    channel::reset_stats();
    let timer = start_timer!(|| "timed section");
    let mpc_proof =
        create_random_proof::<MpcPairingEngine<Bls12_377>, _, _>(circ_data, &mpc_params, rng)
            .unwrap();
    let proof = pf_publicize(mpc_proof);
    end_timer!(timer);

    assert!(verify_proof(&pvk, &proof, &public_inputs).unwrap());
}

fn test_squaring_local(n: usize) {
    let rng = &mut test_rng();
    let circ_no_data = RepeatedSquaringCircuit::without_data(n);

    let params = generate_random_parameters::<Bls12_377, _, _>(circ_no_data, rng).unwrap();

    let pvk = prepare_verifying_key::<Bls12_377>(&params.vk);

    let a = ark_bls12_377::Fr::rand(rng);
    let circ_data = RepeatedSquaringCircuit::from_start(a, n);
    let public_inputs = vec![circ_data.chain.last().unwrap().unwrap()];
    let timer = start_timer!(|| "timed section");
    let proof = create_random_proof::<Bls12_377, _, _>(circ_data, &params, rng).unwrap();
    end_timer!(timer);

    assert!(verify_proof(&pvk, &proof, &public_inputs).unwrap());
}

fn test_squaring_local_ark(n: usize) {
    let rng = &mut test_rng();
    let circ_no_data = RepeatedSquaringCircuit::without_data(n);

    let params = generate_random_parameters::<Bls12_377, _, _>(circ_no_data, rng).unwrap();

    let pvk = prepare_verifying_key::<Bls12_377>(&params.vk);

    let a = ark_bls12_377::Fr::rand(rng);
    let circ_data = RepeatedSquaringCircuit::from_start(a, n);
    let public_inputs = vec![circ_data.chain.last().unwrap().unwrap()];
    let timer = start_timer!(|| "timed section");
    let proof = ark_groth16::create_random_proof::<Bls12_377, _, _>(circ_data, &params, rng).unwrap();
    end_timer!(timer);

    assert!(verify_proof(&pvk, &proof, &public_inputs).unwrap());
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

#[derive(Debug, StructOpt)]
enum FieldOpt {
    Mpc {
        #[structopt(flatten)]
        party_info: PartyInfo,
    },
    Local {},
    ArkLocal {},
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
    fn run(&self, computation: Computation, computation_size: usize) {
        self.setup();
        match computation {
            Computation::Squaring => match self {
                FieldOpt::Mpc { .. } => {
                    test_squaring_mpc(computation_size);
                }
                FieldOpt::Local {} => {
                    test_squaring_local(computation_size);
                }
                FieldOpt::ArkLocal {} => {
                    test_squaring_local_ark(computation_size);
                }
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
    opt.field.run(opt.computation, opt.computation_size);
}
