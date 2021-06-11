#![feature(trait_alias)]
//! Mostly just for testing
use log::debug;

use ark_bls12_377::Fr;
use ark_ec::{group::Group, AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::Field;
use ark_poly::domain::radix2::Radix2EvaluationDomain;
use ark_poly::univariate::DensePolynomial;
use ark_poly::{EvaluationDomain, Polynomial, UVPolynomial};
use ark_poly_commit::marlin_pc;
use ark_poly_commit::PolynomialCommitment;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::SeedableRng;
use std::borrow::Cow;
use std::net::{SocketAddr, ToSocketAddrs};

use mpc_algebra::com::ComField;
use mpc_algebra::honest_but_curious as hbc;
use mpc_algebra::malicious_majority as mm;
use mpc_algebra::*;
use mpc_trait::MpcWire;

use clap::arg_enum;
use merlin::Transcript;
use structopt::StructOpt;

mod groth;
mod marlin;
mod plonk;
mod silly;

arg_enum! {
    #[derive(PartialEq, Debug)]
    pub enum Computation {
        Fft,
        Sum,
        Product,
        PProduct,
        Commit,
        Merkle,
        Fri,
        Dh,
        NaiveMsm,
        GroupOps,
        PairingDh,
        PairingProd,
        PairingDiv,
        Groth16,
        Marlin,
        PolyEval,
        MarlinPc,
        MarlinPcBatch,
        Msm,
        Kzg,
        KzgZk,
        KzgZkBatch,
        PcTwoCom,
        Plonk,
        PolyDiv,
    }
}

#[derive(PartialEq, Debug)]
enum ComputationDomain {
    G1,
    G2,
    Group,
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

    /// Computation to perform
    #[structopt(long)]
    spdz: bool,

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
            Computation::NaiveMsm | Computation::GroupOps => {
                ComputationDomain::Group
            }
            Computation::PairingDh | Computation::PairingProd | Computation::PairingDiv => {
                ComputationDomain::Pairing
            }
            Computation::Marlin
            | Computation::Groth16
            | Computation::Plonk
            | Computation::Kzg
            | Computation::KzgZk
            | Computation::Msm
            | Computation::KzgZkBatch
            | Computation::MarlinPc
            | Computation::MarlinPcBatch => ComputationDomain::BlsPairing,
            Computation::PolyEval => ComputationDomain::PolyField,
            _ => ComputationDomain::Field,
        }
    }
}

fn pairing_engine_test<E: PairingEngine>(
    a: E::Fr,
    b: E::Fr,
) -> (E::Fr, E::G1Projective, E::G2Projective, E::Fqk) {
    let p = a * b * b * E::Fr::from(5u8) + b + E::Fr::from(1u8);
    let g12a = E::G1Affine::prime_subgroup_generator().scalar_mul(a * E::Fr::from(2u8));
    let g1bb = E::G1Affine::prime_subgroup_generator().scalar_mul(b * b);
    let sum = g12a + g1bb;
    let g2ab = E::G2Affine::prime_subgroup_generator().scalar_mul(a * b);
    let pair = E::pairing(sum, g2ab);
    let pair2 = E::pairing(g12a, g2ab);
    let pair3 = pair * pair2;
    (p, sum, g2ab, pair3)
}

fn powers_to_mpc<'a>(
    p: ark_poly_commit::kzg10::Powers<'a, ark_bls12_377::Bls12_377>,
) -> ark_poly_commit::kzg10::Powers<'a, hbc::MpcPairingEngine<ark_bls12_377::Bls12_377>> {
    ark_poly_commit::kzg10::Powers {
        powers_of_g: Cow::Owned(
            p.powers_of_g
                .iter()
                .cloned()
                .map(MpcG1Affine::from_public)
                .collect(),
        ),
        powers_of_gamma_g: Cow::Owned(
            p.powers_of_gamma_g
                .iter()
                .cloned()
                .map(MpcG1Affine::from_public)
                .collect(),
        ),
    }
}
fn commit_from_mpc<'a>(
    p: ark_poly_commit::kzg10::Commitment<hbc::MpcPairingEngine<ark_bls12_377::Bls12_377>>,
) -> ark_poly_commit::kzg10::Commitment<ark_bls12_377::Bls12_377> {
    ark_poly_commit::kzg10::Commitment(p.0.reveal())
}
fn pf_from_mpc<'a>(
    pf: ark_poly_commit::kzg10::Proof<hbc::MpcPairingEngine<ark_bls12_377::Bls12_377>>,
) -> ark_poly_commit::kzg10::Proof<ark_bls12_377::Bls12_377> {
    ark_poly_commit::kzg10::Proof {
        w: pf.w.reveal(),
        random_v: pf.random_v.map(MpcField::reveal),
    }
}

impl Computation {
    fn run_bls(&self, inputs: Vec<MFr>) -> Vec<MFr> {
        let outputs: Vec<MFr> = match self {
            Computation::Groth16 => {
                groth::mpc_test_prove_and_verify::<
                    ark_bls12_377::Bls12_377,
                    mpc_algebra::AdditivePairingShare<ark_bls12_377::Bls12_377>,
                >(1);
                vec![]
            }
            Computation::Marlin => {
                marlin::mpc_test_prove_and_verify(1);
                vec![]
            }
            Computation::Plonk => {
                plonk::local_test_prove_and_verify(1);
                plonk::mpc_test_prove_and_verify(1);
                vec![]
            }
            Computation::MarlinPc => {
                let poly = MP::from_coefficients_slice(&inputs);
                let x = MFr::from(2u32);
                let polys = vec![ark_poly_commit::LabeledPolynomial::new(
                    "a".into(),
                    poly.clone(),
                    Some(2),
                    Some(1),
                )];
                let rng = &mut ark_std::test_rng();
                let srs = MarlinPc::setup(10, Some(1), rng).unwrap();
                let (ck, vk) = MarlinPc::trim(&srs, 2, 1, Some(&[2])).unwrap();
                let mpc_ck = <MarlinMPc as PolynomialCommitment<MFr, DensePolynomial<MFr>>>::CommitterKey::from_public(ck);
                let (mpc_commits, mpc_rands) =
                    MarlinMPc::commit(&mpc_ck, &polys, Some(rng)).unwrap();
                let commits = mpc_commits.clone().reveal();
                //let srs = mpc_algebra::poly::pc::MpcPolyCommit::setup(10, Some(1), rng).unwrap();
                //let (ck, vk) =
                //    mpc_algebra::poly::pc::MpcPolyCommit::trim(&srs, 2, 1, Some(&[2])).unwrap();
                //let (labeled_commits, rands) = mpc_algebra::poly::pc::MpcPolyCommit::commit(
                //.unwrap();
                let chal = MFr::from(2u32);
                let values: Vec<Fr> = vec![poly.evaluate(&x).reveal()];
                println!("{} -> {}", x, values[0]);
                let mpc_pf = MarlinMPc::open(
                    &mpc_ck,
                    &polys,
                    &mpc_commits,
                    &x,
                    chal,
                    &mpc_rands,
                    Some(rng),
                )
                .unwrap();
                println!("{:?}", mpc_pf);
                let pf = mpc_pf.reveal();
                let result = MarlinPc::check(
                    &vk,
                    &commits,
                    &x.reveal(),
                    values,
                    &pf,
                    chal.reveal(),
                    Some(rng),
                )
                .unwrap();
                assert!(result);
                vec![]
            }
            Computation::MarlinPcBatch => {
                assert_eq!(inputs.len(), 6);
                let poly = MP::from_coefficients_slice(&inputs[0..3]);
                let poly2 = MP::from_coefficients_slice(&inputs[3..6]);
                let polys = vec![
                    ark_poly_commit::LabeledPolynomial::new("1".to_owned(), poly, Some(2), Some(1)),
                    ark_poly_commit::LabeledPolynomial::new(
                        "2".to_owned(),
                        poly2,
                        Some(2),
                        Some(1),
                    ),
                ];
                let rng = &mut ark_std::test_rng();
                let srs = MarlinPc::setup(10, Some(1), rng).unwrap();
                let (ck, vk) = MarlinPc::trim(&srs, 2, 1, Some(&[2])).unwrap();
                let mpc_ck = <MarlinMPc as PolynomialCommitment<MFr, DensePolynomial<MFr>>>::CommitterKey::from_public(ck);
                let (mpc_commits, mpc_rands) =
                    MarlinMPc::commit(&mpc_ck, &polys, Some(rng)).unwrap();
                let commits = mpc_commits.clone().reveal();
                let x = MFr::from(2u32);
                let chal = MFr::from(4u32);
                let values: Vec<Fr> = polys
                    .iter()
                    .map(|p| p.polynomial().evaluate(&x).reveal())
                    .collect();
                let mpc_pf = MarlinMPc::open(
                    &mpc_ck,
                    &polys,
                    &mpc_commits,
                    &x,
                    chal,
                    &mpc_rands,
                    Some(rng),
                )
                .unwrap();
                println!("{:?}", mpc_pf);
                let pf = mpc_pf.reveal();
                let result = MarlinPc::check(
                    &vk,
                    &commits,
                    &x.reveal(),
                    values,
                    &pf,
                    chal.reveal(),
                    Some(rng),
                )
                .unwrap();
                assert!(result);
                vec![]
            }
            Computation::Kzg => {
                {
                    let a = inputs[0].reveal();
                    let b = inputs[1].reveal();
                    let (w, x, y, z) = pairing_engine_test::<ME>(inputs[0], inputs[1]);
                    assert_eq!(
                        pairing_engine_test::<E>(a, b),
                        (w.reveal(), x.reveal(), y.reveal(), z.reveal())
                    )
                }
                let poly = MP::from_coefficients_slice(&inputs);
                let rng = &mut ark_std::test_rng();
                let pp = ark_poly_commit::kzg10::KZG10::<
                    ark_bls12_377::Bls12_377,
                    ark_poly::univariate::DensePolynomial<ark_bls12_377::Fr>,
                >::setup(10, true, rng)
                .unwrap();
                let powers_of_gamma_g = (0..11)
                    .map(|i| pp.powers_of_gamma_g[&i])
                    .collect::<Vec<_>>();
                let powers = ark_poly_commit::kzg10::Powers::<ark_bls12_377::Bls12_377> {
                    powers_of_g: Cow::Borrowed(&pp.powers_of_g),
                    powers_of_gamma_g: Cow::Owned(powers_of_gamma_g),
                };
                let mpc_powers = powers_to_mpc(powers);
                let (commit, rand) =
                    ark_poly_commit::kzg10::KZG10::commit(&mpc_powers, &poly, None, None).unwrap();
                println!("{:?}", commit);
                let commit = commit_from_mpc(commit);
                println!("{:?}", commit);
                let mpc_x = MFr::from(2u32);
                let mpc_pf =
                    ark_poly_commit::kzg10::KZG10::open(&mpc_powers, &poly, mpc_x, &rand).unwrap();
                let y = poly.evaluate(&mpc_x).reveal();
                let x = mpc_x.reveal();
                println!("{:?}", mpc_pf);
                let pf = pf_from_mpc(mpc_pf);
                println!("{:?}", pf);
                let vk = ark_poly_commit::kzg10::VerifierKey::<ark_bls12_377::Bls12_377> {
                    g: pp.powers_of_g[0],
                    gamma_g: pp.powers_of_gamma_g[&0],
                    h: pp.h,
                    beta_h: pp.beta_h,
                    prepared_h: pp.prepared_h,
                    prepared_beta_h: pp.prepared_beta_h,
                };
                println!("{:?}", commit);
                println!("{} -> {}", x, y);
                let result = ark_poly_commit::kzg10::KZG10::<
                    ark_bls12_377::Bls12_377,
                    ark_poly::univariate::DensePolynomial<ark_bls12_377::Fr>,
                >::check(&vk, &commit, x, y, &pf)
                .unwrap();
                assert_eq!(result, true);
                vec![]
            }
            Computation::KzgZk => {
                let poly = MP::from_coefficients_slice(&inputs);
                let rng = &mut ark_std::test_rng();
                let pp = ark_poly_commit::kzg10::KZG10::<
                    ark_bls12_377::Bls12_377,
                    ark_poly::univariate::DensePolynomial<ark_bls12_377::Fr>,
                >::setup(10, true, rng)
                .unwrap();
                let powers_of_gamma_g = (0..11)
                    .map(|i| pp.powers_of_gamma_g[&i])
                    .collect::<Vec<_>>();
                let powers = ark_poly_commit::kzg10::Powers::<ark_bls12_377::Bls12_377> {
                    powers_of_g: Cow::Borrowed(&pp.powers_of_g),
                    powers_of_gamma_g: Cow::Owned(powers_of_gamma_g),
                };
                let mpc_powers = powers_to_mpc(powers);
                let (commit, rand) =
                    ark_poly_commit::kzg10::KZG10::commit(&mpc_powers, &poly, Some(2), Some(rng))
                        .unwrap();
                let commit = commit_from_mpc(commit);
                let mpc_x = MFr::from(2u32);
                let mpc_pf =
                    ark_poly_commit::kzg10::KZG10::open(&mpc_powers, &poly, mpc_x, &rand).unwrap();
                let y = poly.evaluate(&mpc_x).reveal();
                let x = mpc_x.reveal();
                let pf = pf_from_mpc(mpc_pf);
                let vk = ark_poly_commit::kzg10::VerifierKey::<ark_bls12_377::Bls12_377> {
                    g: pp.powers_of_g[0],
                    gamma_g: pp.powers_of_gamma_g[&0],
                    h: pp.h,
                    beta_h: pp.beta_h,
                    prepared_h: pp.prepared_h,
                    prepared_beta_h: pp.prepared_beta_h,
                };
                println!("{} -> {}", x, y);
                let result = ark_poly_commit::kzg10::KZG10::<
                    ark_bls12_377::Bls12_377,
                    ark_poly::univariate::DensePolynomial<ark_bls12_377::Fr>,
                >::check(&vk, &commit, x, y, &pf)
                .unwrap();
                assert_eq!(result, true);
                vec![]
            }
            Computation::KzgZkBatch => {
                assert_eq!(inputs.len(), 6);
                let poly = MP::from_coefficients_slice(&inputs[0..3]);
                let poly2 = MP::from_coefficients_slice(&inputs[3..6]);
                let rng = &mut ark_std::test_rng();
                let pp = ark_poly_commit::kzg10::KZG10::<
                    ark_bls12_377::Bls12_377,
                    ark_poly::univariate::DensePolynomial<ark_bls12_377::Fr>,
                >::setup(10, true, rng)
                .unwrap();
                let powers_of_gamma_g = (0..11)
                    .map(|i| pp.powers_of_gamma_g[&i])
                    .collect::<Vec<_>>();
                let powers = ark_poly_commit::kzg10::Powers::<ark_bls12_377::Bls12_377> {
                    powers_of_g: Cow::Borrowed(&pp.powers_of_g),
                    powers_of_gamma_g: Cow::Owned(powers_of_gamma_g),
                };
                let mpc_powers = powers_to_mpc(powers);
                let (commit, rand) =
                    ark_poly_commit::kzg10::KZG10::commit(&mpc_powers, &poly, Some(2), Some(rng))
                        .unwrap();
                let (commit2, rand2) =
                    ark_poly_commit::kzg10::KZG10::commit(&mpc_powers, &poly2, Some(2), Some(rng))
                        .unwrap();
                let commit = commit_from_mpc(commit);
                let commit2 = commit_from_mpc(commit2);
                let mpc_x = MFr::from(2u32);
                let mpc_x2 = MFr::from(1u32);
                let mpc_pf =
                    ark_poly_commit::kzg10::KZG10::open(&mpc_powers, &poly, mpc_x, &rand).unwrap();
                let mpc_pf2 =
                    ark_poly_commit::kzg10::KZG10::open(&mpc_powers, &poly2, mpc_x2, &rand2)
                        .unwrap();
                let y = poly.evaluate(&mpc_x).reveal();
                let y2 = poly2.evaluate(&mpc_x2).reveal();
                let x = mpc_x.reveal();
                let x2 = mpc_x2.reveal();
                let pf = pf_from_mpc(mpc_pf);
                let pf2 = pf_from_mpc(mpc_pf2);
                let vk = ark_poly_commit::kzg10::VerifierKey::<ark_bls12_377::Bls12_377> {
                    g: pp.powers_of_g[0],
                    gamma_g: pp.powers_of_gamma_g[&0],
                    h: pp.h,
                    beta_h: pp.beta_h,
                    prepared_h: pp.prepared_h,
                    prepared_beta_h: pp.prepared_beta_h,
                };
                println!("{} -> {}", x, y);
                println!("{} -> {}", x2, y2);
                let result = ark_poly_commit::kzg10::KZG10::<
                    ark_bls12_377::Bls12_377,
                    ark_poly::univariate::DensePolynomial<ark_bls12_377::Fr>,
                >::batch_check(
                    &vk, &[commit, commit2], &[x, x2], &[y, y2], &[pf, pf2], rng
                )
                .unwrap();
                assert_eq!(result, true);
                vec![]
            }
            Computation::Msm => {
                let rng = &mut rand::rngs::StdRng::from_seed([0u8; 32]);
                let ps: Vec<MFr> = (0..inputs.len()).map(|_| MFr::public_rand(rng)).collect();
                let sum: MFr = inputs.iter().zip(ps.iter()).map(|(a, b)| *a * b).sum();
                let mut public_gens =
                    vec![<ME as PairingEngine>::G1Affine::prime_subgroup_generator(); inputs.len()];
                for (g, c) in public_gens.iter_mut().zip(ps.iter()) {
                    *g = g.scalar_mul(*c).into();
                }
                let mut msm =
                    <ME as PairingEngine>::G1Affine::multi_scalar_mul(&public_gens, &inputs);
                let mut expected = <ME as PairingEngine>::G1Projective::prime_subgroup_generator()
                    .scalar_mul(&sum);
                msm.publicize();
                expected.publicize();
                assert_eq!(msm, expected);
                vec![]
            }
            c => unimplemented!("Cannot run_bls {:?}", c),
        };
        println!("Stats: {:#?}", mpc_net::stats());
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
    fn run_group<G: Group>(
        &self,
        inputs: Vec<G::ScalarField>,
        generator: G,
    ) {
        match self {
            Computation::Dh => {
                assert_eq!(2, inputs.len());
                let a = inputs[0];
                let b = inputs[1];
                let g = generator;
                let mut alice = G::mul(&G::mul(&g, &a), &b);
                let mut bob = G::mul(&G::mul(&g, &b), &a);
                alice.publicize();
                bob.publicize();
                assert_eq!(alice, bob);
            }
            Computation::Msm => {
                let _bases: Vec<G> = (0u8..).map(|i| generator.mul(&G::ScalarField::from(i))).take(inputs.len()).collect();
                todo!()
            }
            Computation::GroupOps => {
                let g = generator;
                let mut r1 = (g.mul(&inputs[0]) + &g - &g).mul(&G::ScalarField::from(4u8));
                r1.publicize();
                let mut t = inputs[0];
                t.publicize();
                let mut r2 = g.mul(&(t * G::ScalarField::from(4u8)));
                r2.publicize();
                assert_eq!(r1, r2);
            }
            c => unimplemented!("Cannot run_dh {:?}", c),
        }
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
            Computation::PolyDiv => {
                let p = DensePolynomial::from_coefficients_vec(inputs.clone());
                let q = DensePolynomial::from_coefficients_vec(vec![F::from(1u8), F::from(1u8)]);
                let a = &p / &q;
                let x = F::from(1u8);
                let mut d = a.evaluate(&x) * q.evaluate(&x) - p.evaluate(&x);
                d.publicize();
                assert!(d.is_zero());
                vec![]
            }
            Computation::Sum => {
                vec![inputs.into_iter().fold(F::from(0u32), std::ops::Add::add)]
            }
            Computation::Product => {
                assert_eq!(inputs.len(), 2);
                let product = inputs[0] * inputs[1];
                //assert_eq!(inputs[0].reveal() * inputs[1].reveal(), product.reveal());
                vec![product]
            }
            Computation::PProduct => {
                assert_eq!(inputs.len(), 2);
                let mut pp = inputs.clone();
                for p in &mut inputs {
                    p.publicize()
                }
                let t = inputs[0];
                inputs[1] *= t;
                F::partial_products_in_place(&mut pp[..]);
                for p in &mut pp {
                    p.publicize()
                }
                assert_eq!(pp[0], inputs[0]);
                assert_eq!(pp[1], inputs[1]);
                vec![]
            }
            // Commented out because it serializes secrets
            // Computation::Commit => {
            //     let mut t = Transcript::new(b"commit");
            //     for i in &inputs {
            //         let mut bytes = Vec::new();
            //         i.serialize(&mut bytes).unwrap();
            //         t.append_message(b"input", &bytes);
            //     }
            //     let mut challenge_bytes = vec![0u8; 64];
            //     t.challenge_bytes(b"challenge", &mut challenge_bytes);
            //     let c = F::from_random_bytes(&challenge_bytes).expect("Couldn't sample");
            //     vec![c]
            // }
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

type E = ark_bls12_377::Bls12_377;
type ME = hbc::MpcPairingEngine<E>;
type MFr = hbc::MpcField<Fr>;
type MG1 = hbc::MpcG1Projective<E>;
type MG2 = hbc::MpcG2Projective<E>;
type P = ark_poly::univariate::DensePolynomial<Fr>;
type MP = ark_poly::univariate::DensePolynomial<MFr>;
trait Pc = ark_poly_commit::PolynomialCommitment<Fr, DensePolynomial<Fr>>;
trait MPc = ark_poly_commit::PolynomialCommitment<MFr, DensePolynomial<MFr>>;
type MarlinPc = marlin_pc::MarlinKZG10<E, P>;
type MarlinMPc = marlin_pc::MarlinKZG10<ME, MP>;

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
    mpc_net::init(self_addr, peer_addr, opt.party == 0);
    debug!("Start");
    if opt.spdz {
        let inputs = opt
            .args
            .iter()
            .map(|i| mm::MpcField::<Fr>::from_add_shared(Fr::from(*i)))
            .collect::<Vec<_>>();
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
            ComputationDomain::Group | ComputationDomain::G1 => {
                let generator = mm::MpcGroup::<ark_bls12_377::G1Projective>::from_public(ark_bls12_377::G1Projective::prime_subgroup_generator());
                opt.computation.run_group::<mm::MpcGroup<ark_bls12_377::G1Projective>>(inputs, generator);
            }
            d => panic!("Bad domain: {:?}", d),
        }
    } else {
        let inputs = opt
            .args
            .iter()
            .map(|i| MFr::from_add_shared(Fr::from(*i)))
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
                    .run_pairing::<hbc::MpcPairingEngine<ark_bls12_377::Bls12_377>>(inputs);
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
            d => panic!("Bad domain: {:?}", d),
        }
    }
    debug!("Stats: {:#?}", mpc_net::stats());
    mpc_net::deinit();
    debug!("Done");
}
