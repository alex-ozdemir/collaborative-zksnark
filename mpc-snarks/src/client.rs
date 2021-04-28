use log::debug;

use ark_bls12_377::Fr;
use ark_ec::group::Group;
use ark_ec::PairingEngine;
use ark_ec::ProjectiveCurve;
use ark_ff::Field;
use ark_poly::domain::radix2::Radix2EvaluationDomain;
use ark_poly::EvaluationDomain;
use ark_poly::{Polynomial, UVPolynomial};
use ark_poly_commit::PolynomialCommitment;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::SeedableRng;
use std::net::{SocketAddr, ToSocketAddrs};

use mpc_algebra::{channel, ComField, MpcCurve, MpcCurve2, MpcVal};
use mpc_trait::MpcWire;

use clap::arg_enum;
use merlin::Transcript;
use structopt::StructOpt;

mod groth;
mod silly;

arg_enum! {
    #[derive(PartialEq, Debug)]
    pub enum Computation {
        Fft,
        Sum,
        Product,
        Commit,
        Merkle,
        Fri,
        Dh,
        PairingDh,
        PairingProd,
        PairingDiv,
        Groth16,
        Marlin,
        PolyEval,
        PcCom,
    }
}

enum ComputationDomain {
    G1,
    G2,
    Field,
    Pairing,
    BlsPairing,
    PolyField,
}

#[derive(Debug, StructOpt)]
#[structopt(name = "client", about = "An example MPC")]
struct Opt {
    /// Activate debug mode
    // short and long flags (-d, --debug) will be deduced from the field's name
    #[structopt(short, long)]
    debug: bool,

    /// Your host
    #[structopt(long, default_value = "localhost")]
    host: String,

    /// Your port
    #[structopt(long, default_value = "8000")]
    port: u16,

    /// Peer host
    #[structopt(long)]
    peer_host: String,

    /// Peer port
    #[structopt(long, default_value = "8000")]
    peer_port: u16,

    /// Which party are you? 0 or 1?
    #[structopt(long, default_value = "0")]
    party: u8,

    /// Computation to perform
    #[structopt()]
    computation: Computation,

    /// Computation to perform
    #[structopt(long)]
    use_g2: bool,

    /// Input a
    #[structopt()]
    args: Vec<u64>,
}

impl Opt {
    fn domain(&self) -> ComputationDomain {
        match &self.computation {
            Computation::Dh => {
                if self.use_g2 {
                    ComputationDomain::G2
                } else {
                    ComputationDomain::G1
                }
            }

            Computation::PairingDh | Computation::PairingProd | Computation::PairingDiv => {
                ComputationDomain::Pairing
            }
            Computation::Marlin | Computation::Groth16 | Computation::PcCom => {
                ComputationDomain::BlsPairing
            }
            Computation::PolyEval => ComputationDomain::PolyField,
            _ => ComputationDomain::Field,
        }
    }
}

impl Computation {
    fn run_bls(&self, inputs: Vec<MFr>) -> Vec<MFr> {
        let outputs: Vec<MFr> = match self {
                        Computation::Groth16 => {
                            groth::mpc_test_prove_and_verify(1);
                            vec![]
                        }
            //            Computation::Marlin => {
            //                //mpc::marlin::local_test_prove_and_verify::<ark_bls12_377::Bls12_377>(1);
            //                mpc::marlin::mpc_test_prove_and_verify(1);
            //                vec![]
            //            }
            //            Computation::PcCom => {
            //                let poly = MP::from_coefficients_slice(&inputs);
            //                let x = MFr::from(2u32);
            //                let rng = &mut ark_std::test_rng();
            //                let srs = mpc::poly::pc::MpcPolyCommit::setup(10, Some(1), rng).unwrap();
            //                let (ck, vk) = mpc::poly::pc::MpcPolyCommit::trim(&srs, 2, 1, Some(&[2])).unwrap();
            //                let (commits, rands) = mpc::poly::pc::MpcPolyCommit::commit(
            //                    &ck,
            //                    &[ark_poly_commit::LabeledPolynomial::new("a".into(), poly, Some(2), Some(1))],
            //                    Some(rng),
            //                )
            //                .unwrap();
            //                println!("{:#?}", commits.len());
            //                println!("{:#?}", commits[0].commitment());
            //                println!("{:#?}", rands[0]);
            //                println!("{:#?}", rands.len());
            //                vec![]
            //            }
            c => unimplemented!("Cannot run_pairing {:?}", c),
        };
        println!("Stats: {:#?}", channel::stats());
        drop(inputs);
        println!("Outputs:");
        for (i, v) in outputs.iter().enumerate() {
            println!("  {}: {}", i, v);
        }
        outputs
    }
    fn run_pairing<P: PairingEngine>(
        &self,
        inputs: Vec<<P as PairingEngine>::Fr>,
    ) -> Vec<<P as PairingEngine>::Fr>
    where
        <P as PairingEngine>::Fr: MpcWire,
        <P as PairingEngine>::Fqk: MpcWire,
    {
        let outputs = match self {
            Computation::PairingDh => {
                assert_eq!(3, inputs.len());
                let a = inputs[0];
                let b = inputs[1];
                let c = inputs[2];
                let g1 = <P as PairingEngine>::G1Projective::prime_subgroup_generator();
                let g2 = <P as PairingEngine>::G2Projective::prime_subgroup_generator();
                let g1a = <<P as PairingEngine>::G1Projective as Group>::mul(&g1, &a);
                let g2b = <<P as PairingEngine>::G2Projective as Group>::mul(&g2, &b);
                let g1c = <<P as PairingEngine>::G1Projective as Group>::mul(&g1, &c);
                let mut gc = P::pairing(g1c, g2);
                gc.publicize();
                let mut gcc = P::pairing(g1a, g2b);
                gcc.publicize();
                assert_eq!(gc, gcc);
                vec![]
            }
            Computation::PairingProd => {
                // ((a + b) * g1, (c + d) * g2) = (a * g1, c * g2)
                //                              * (b * g1, c * g2)
                //                              * (a * g1, d * g2)
                //                              * (b * g1, d * g2)
                assert_eq!(4, inputs.len());
                let a = inputs[0];
                let b = inputs[1];
                let c = inputs[2];
                let d = inputs[3];
                let ab = a + b;
                let cd = c + d;
                let g1 = <P as PairingEngine>::G1Projective::prime_subgroup_generator();
                let g2 = <P as PairingEngine>::G2Projective::prime_subgroup_generator();
                let g1ab = <<P as PairingEngine>::G1Projective as Group>::mul(&g1, &ab);
                let g2cd = <<P as PairingEngine>::G2Projective as Group>::mul(&g2, &cd);
                let g1a = <<P as PairingEngine>::G1Projective as Group>::mul(&g1, &a);
                let g1b = <<P as PairingEngine>::G1Projective as Group>::mul(&g1, &b);
                let g2c = <<P as PairingEngine>::G2Projective as Group>::mul(&g2, &c);
                let g2d = <<P as PairingEngine>::G2Projective as Group>::mul(&g2, &d);
                let mut gtabcd = P::pairing(g1ab, g2cd);
                let gtac = P::pairing(g1a, g2c);
                let gtbc = P::pairing(g1b, g2c);
                let gtad = P::pairing(g1a, g2d);
                let gtbd = P::pairing(g1b, g2d);
                let mut gtabcd2 = gtac * gtbc * gtad * gtbd;
                gtabcd.publicize();
                gtabcd2.publicize();
                assert_eq!(gtabcd, gtabcd2);
                vec![]
            }
            Computation::PairingDiv => {
                // ((a - b) * g1, (c - d) * g2) = (a * g1, c * g2)
                //                              / (b * g1, c * g2)
                //                              / (a * g1, d * g2)
                //                              * (b * g1, d * g2)
                assert_eq!(4, inputs.len());
                let a = inputs[0];
                let b = inputs[1];
                let c = inputs[2];
                let d = inputs[3];
                let ab = a - b;
                let cd = c - d;
                let g1 = <P as PairingEngine>::G1Projective::prime_subgroup_generator();
                let g2 = <P as PairingEngine>::G2Projective::prime_subgroup_generator();
                let g1ab = <<P as PairingEngine>::G1Projective as Group>::mul(&g1, &ab);
                let g2cd = <<P as PairingEngine>::G2Projective as Group>::mul(&g2, &cd);
                let g1a = <<P as PairingEngine>::G1Projective as Group>::mul(&g1, &a);
                let g1b = <<P as PairingEngine>::G1Projective as Group>::mul(&g1, &b);
                let g2c = <<P as PairingEngine>::G2Projective as Group>::mul(&g2, &c);
                let g2d = <<P as PairingEngine>::G2Projective as Group>::mul(&g2, &d);
                let mut gtabcd = P::pairing(g1ab, g2cd);
                let gtac = P::pairing(g1a, g2c);
                let gtbc = P::pairing(g1b, g2c);
                let gtad = P::pairing(g1a, g2d);
                let gtbd = P::pairing(g1b, g2d);
                let mut gtabcd2 = gtac / gtbc / gtad * gtbd;
                gtabcd.publicize();
                gtabcd2.publicize();
                assert_eq!(gtabcd, gtabcd2);
                vec![]
            }
            c => unimplemented!("Cannot run_pairing {:?}", c),
        };
        println!("Outputs:");
        for (i, v) in outputs.iter().enumerate() {
            println!("  {}: {}", i, v);
        }
        outputs
    }
    fn run_gp<G: ProjectiveCurve + MpcWire>(
        &self,
        inputs: Vec<<G as Group>::ScalarField>,
    ) -> Vec<G> {
        let outputs = match self {
            Computation::Dh => {
                assert_eq!(3, inputs.len());
                let a = inputs[0];
                let b = inputs[1];
                let c = inputs[2];
                let g = G::prime_subgroup_generator();
                let ga = <G as Group>::mul(&g, &a);
                let gb = <G as Group>::mul(&g, &b);
                let mut gc = <G as Group>::mul(&g, &c);
                let mut gcc = ga + gb;
                gc.publicize();
                gcc.publicize();
                assert_eq!(gc, gcc);
                vec![]
            }
            c => unimplemented!("Cannot run_dh {:?}", c),
        };
        println!("Outputs:");
        for (i, v) in outputs.iter().enumerate() {
            println!("  {}: {}", i, v);
        }
        outputs
    }
    fn run_uv_poly<F: Field, P: UVPolynomial<F>>(&self, inputs: Vec<F>) -> Vec<F> {
        let outputs = match self {
            Computation::PolyEval => {
                let p = P::from_coefficients_vec(inputs);
                let x = F::from(2u32);
                vec![p.evaluate(&x)]
            }
            c => unimplemented!("Cannot run_uv_poly {:?}", c),
        };
        println!("Outputs:");
        for (i, v) in outputs.iter().enumerate() {
            println!("  {}: {}", i, v);
        }
        outputs
    }
    fn run_field<F: ComField>(&self, mut inputs: Vec<F>) -> Vec<F> {
        let outputs = match self {
            Computation::Fft => {
                let d = Radix2EvaluationDomain::<F>::new(inputs.len()).unwrap();
                d.ifft_in_place(&mut inputs);
                inputs
            }
            Computation::Sum => {
                vec![inputs.into_iter().fold(F::from(0u32), std::ops::Add::add)]
            }
            Computation::Product => {
                assert_eq!(inputs.len(), 2);
                vec![inputs[0] * inputs[1]]
            }
            Computation::Commit => {
                let mut t = Transcript::new(b"commit");
                for i in &inputs {
                    let mut bytes = Vec::new();
                    i.serialize(&mut bytes).unwrap();
                    t.append_message(b"input", &bytes);
                }
                let mut challenge_bytes = vec![0u8; 64];
                t.challenge_bytes(b"challenge", &mut challenge_bytes);
                let c = F::from_random_bytes(&challenge_bytes).expect("Couldn't sample");
                vec![c]
            }
            Computation::Merkle => {
                let mut t = Transcript::new(b"merkle");
                let (k, c) = F::commit(&inputs[..]);
                let mut bytes = Vec::new();
                c.serialize(&mut bytes).unwrap();
                t.append_message(b"commitment", &bytes);
                let mut challenge_bytes: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0];
                t.challenge_bytes(b"challenge", &mut challenge_bytes[..]);
                let n = u64::from_be_bytes(challenge_bytes) as usize;
                let i = n % inputs.len();
                println!("Query at: {}", i);
                let (value, pf) = F::open_at(&inputs[..], &k, i);
                let v = F::check_opening(&c, pf, i, value);
                assert!(v);
                println!("Valid proof: {}", v);
                vec![]
            }
            Computation::Fri => {
                let mut t = Transcript::new(b"fri");
                let n = inputs.len();
                assert!(n.is_power_of_two());
                let k = n.trailing_zeros() as usize;
                let l = k + 1;
                let mut fs = vec![inputs];
                let mut commitments = Vec::new();
                let mut alphas = Vec::new();
                println!("k: {}", k);
                for i in 0..k {
                    let f_last = fs.last().unwrap();
                    let mut evals = f_last.clone();
                    evals.extend(std::iter::repeat(F::zero()).take((1 << (l - i)) - evals.len()));
                    let d = Radix2EvaluationDomain::<F>::new(evals.len()).unwrap();
                    d.fft_in_place(&mut evals);
                    let (tree, root) = F::commit(&evals);
                    commitments.push((evals, tree, root));
                    let mut bytes = Vec::new();
                    commitments.last().unwrap().2.serialize(&mut bytes).unwrap();
                    t.append_message(b"commitment", &bytes);
                    //TODO: entropy problem for large fields...
                    // need to wrestle with ff's random sampling implementation properly
                    let mut challenge_bytes = [0u8; 32];
                    t.challenge_bytes(b"challenge", &mut challenge_bytes);
                    let mut rng = rand::rngs::StdRng::from_seed(challenge_bytes);
                    let alpha = F::public_rand(&mut rng);
                    println!("Fri commit round {}, challenge: {}", i, alpha);
                    let mut f_next = Vec::new();
                    for i in 0..f_last.len() / 2 {
                        f_next.push(f_last[2 * i] + f_last[2 * i + 1] * alpha);
                    }
                    fs.push(f_next);
                    alphas.push(alpha);
                }
                assert_eq!(fs.last().unwrap().len(), 1);
                let mut constant = fs.last().unwrap().last().unwrap().clone();
                constant.publicize();
                println!("Constant: {}", constant);
                let mut bytes = Vec::new();
                constant.serialize(&mut bytes).unwrap();
                t.append_message(b"constant", &bytes);

                let iter = 1;
                for j in 0..iter {
                    println!("FRI chain check {}/{}", j + 1, iter);
                    let mut challenge_bytes: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0];
                    t.challenge_bytes(b"challenge", &mut challenge_bytes[..]);
                    let mut x_i = u64::from_be_bytes(challenge_bytes) % (1 << l);
                    // index of x in seq.
                    for i in 0..k {
                        let n: u64 = 1 << (l - i);
                        let omega = F::get_root_of_unity(n as usize).unwrap();
                        let x = omega.pow(&[x_i]);
                        let neg_x_i = (n / 2 + x_i) % n;
                        assert_eq!(-x, omega.pow(&[neg_x_i]));
                        let x2_i = 2 * x_i % n / 2;
                        let (val, pf) =
                            F::open_at(&commitments[i].0[..], &commitments[i].1, x_i as usize);
                        let mut bytes = Vec::new();
                        pf.serialize(&mut bytes).unwrap();
                        t.append_message(b"path", &bytes);
                        assert!(F::check_opening(&commitments[i].2, pf, x_i as usize, val));
                        let (neg_val, neg_pf) =
                            F::open_at(&commitments[i].0[..], &commitments[i].1, neg_x_i as usize);
                        let mut bytes = Vec::new();
                        neg_pf.serialize(&mut bytes).unwrap();
                        t.append_message(b"path1", &bytes);
                        assert!(F::check_opening(
                            &commitments[i].2,
                            neg_pf,
                            neg_x_i as usize,
                            neg_val
                        ));
                        let next_val = if i + 1 < k {
                            let (next_val, next_pf) = F::open_at(
                                &commitments[i + 1].0[..],
                                &commitments[i + 1].1,
                                x2_i as usize,
                            );
                            let mut bytes = Vec::new();
                            next_pf.serialize(&mut bytes).unwrap();
                            t.append_message(b"path2", &bytes);
                            assert!(F::check_opening(
                                &commitments[i + 1].2,
                                next_pf,
                                x2_i as usize,
                                next_val
                            ));
                            next_val
                        } else {
                            constant
                        };
                        assert!(
                            next_val
                                == (val + neg_val) / F::from(2u8)
                                    + alphas[i] * (val - neg_val) / (F::from(2u8) * x)
                        );
                        // TODO: add to transcript
                        x_i = x2_i;
                    }
                }
                vec![]
            }
            c => unimplemented!("Cannot run_field {:?}", c),
        };
        println!("Outputs:");
        for (i, v) in outputs.iter().enumerate() {
            println!("  {}: {}", i, v);
        }
        outputs
    }
}

type MFr = MpcVal<Fr>;
type G1 = ark_bls12_377::G1Projective;
type MG1 = MpcCurve<G1>;
type G2 = ark_bls12_377::G2Projective;
type MG2 = MpcCurve2<G2>;
type P = ark_poly::univariate::DensePolynomial<Fr>;
type MP = ark_poly::univariate::DensePolynomial<MFr>;

fn main() -> () {
    let opt = Opt::from_args();
    if opt.debug {
        env_logger::builder()
            .filter_level(log::LevelFilter::Debug)
            .init();
    } else {
        env_logger::init();
    }
    let domain = opt.domain();
    let self_addr = (opt.host, opt.port)
        .to_socket_addrs()
        .unwrap()
        .filter(SocketAddr::is_ipv4)
        .next()
        .unwrap();
    let peer_addr = (opt.peer_host, opt.peer_port)
        .to_socket_addrs()
        .unwrap()
        .filter(SocketAddr::is_ipv4)
        .next()
        .unwrap();
    channel::init(self_addr, peer_addr, opt.party == 0);
    debug!("Start");
    let inputs = opt
        .args
        .iter()
        .map(|i| MFr::from_shared(Fr::from(*i)))
        .collect::<Vec<MFr>>();
    println!("Inputs:");
    for (i, v) in inputs.iter().enumerate() {
        println!("  {}: {}", i, v);
    }
    match domain {
        ComputationDomain::Field => {
            let mut outputs = opt.computation.run_field(inputs);
            outputs.iter_mut().for_each(|c| c.publicize());
            println!("Public Outputs:");
            for (i, v) in outputs.iter().enumerate() {
                println!("  {}: {}", i, v);
            }
        }
        ComputationDomain::G1 => {
            let mut outputs = opt.computation.run_gp::<MG1>(inputs);
            outputs.iter_mut().for_each(|c| c.publicize());
            println!("Public Outputs:");
            for (i, v) in outputs.iter().enumerate() {
                println!("  {}: {}", i, v);
            }
        }
        ComputationDomain::G2 => {
            let mut outputs = opt.computation.run_gp::<MG2>(inputs);
            outputs.iter_mut().for_each(|c| c.publicize());
            println!("Public Outputs:");
            for (i, v) in outputs.iter().enumerate() {
                println!("  {}: {}", i, v);
            }
        }
        ComputationDomain::Pairing => {
            let mut outputs = opt
                .computation
                .run_pairing::<mpc_algebra::MpcPairingEngine<ark_bls12_377::Bls12_377>>(inputs);
            outputs.iter_mut().for_each(|c| c.publicize());
            println!("Public Outputs:");
            for (i, v) in outputs.iter().enumerate() {
                println!("  {}: {}", i, v);
            }
        }
        ComputationDomain::BlsPairing => {
            let mut outputs = opt.computation.run_bls(inputs);
            outputs.iter_mut().for_each(|c| c.publicize());
            println!("Public Outputs:");
            for (i, v) in outputs.iter().enumerate() {
                println!("  {}: {}", i, v);
            }
        }
        ComputationDomain::PolyField => {
            let mut outputs = opt.computation.run_uv_poly::<MFr, MP>(inputs);
            outputs.iter_mut().for_each(|c| c.publicize());
            println!("Public Outputs:");
            for (i, v) in outputs.iter().enumerate() {
                println!("  {}: {}", i, v);
            }
        }
    }
    debug!("Stats: {:#?}", channel::stats());
    channel::deinit();
    debug!("Done");
}
