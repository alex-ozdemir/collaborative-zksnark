use ark_ec::group::Group;
use ark_ff::{FftField, UniformRand};
use log::debug;
use mpc_algebra::gsz20::group::GszGroupShare;
use mpc_algebra::{add::NaiveMsm, share::gsz20::*, Reveal, share::field::ScalarShare};
use mpc_net::multi;

use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "example", about = "An example of StructOpt usage.")]
struct Opt {
    /// Id
    id: usize,

    /// Input file
    #[structopt(parse(from_os_str))]
    input: PathBuf,
}

fn test<F: FftField>() {
    let rng = &mut ark_std::test_rng();
    let (a, b) = field::double_rand::<F>();
    let a_pub = field::open(&a);
    let b_pub = field::open(&b);
    assert_eq!(a_pub, b_pub);

    for _i in 0..10 {
        let a_pub = F::rand(rng);
        let b_pub = F::rand(rng);
        let a = GszFieldShare::from_public(a_pub);
        let b = GszFieldShare::from_public(b_pub);
        let c = field::mult(a, &b);
        let c_pub = field::open(&c);
        assert_eq!(c_pub, a_pub * b_pub);
        assert_ne!(c_pub, a_pub * b_pub + F::one());
    }

    let size = 1000;
    let a_pubs: Vec<F> = (0..size).map(|_| F::rand(rng)).collect();
    let b_pubs: Vec<F> = (0..size).map(|_| F::rand(rng)).collect();
    let a: Vec<_> = a_pubs.iter().map(|a| GszFieldShare::from_public(*a)).collect();
    let b: Vec<_> = b_pubs.iter().map(|b| GszFieldShare::from_public(*b)).collect();
    let c = field::batch_mult(a, &b);
    let c_pub = GszFieldShare::batch_open(c.clone());
    for i in 0..c.len() {
        assert_eq!(c_pub[i], a_pubs[i] * b_pubs[i]);
    }
}

fn test_group<G: Group>() {
    let rng = &mut ark_std::test_rng();
    let (a, b) = group::double_rand::<G, NaiveMsm<G>>();
    let a_pub = group::open(&a);
    let b_pub = group::open(&b);
    assert_eq!(a_pub, b_pub);

    for _i in 0..2 {
        let a_pub = G::ScalarField::rand(rng);
        let b_pub = G::rand(rng);
        let a = GszFieldShare::from_public(a_pub);
        let b = GszGroupShare::<G, NaiveMsm<G>>::from_public(b_pub);
        let c = group::mult(&a, b);
        let c_pub = group::open(&c);
        assert_eq!(c_pub, b_pub.mul(&a_pub));
    }
}

fn main() {
    env_logger::builder().format_timestamp(None).init();
    //env_logger::builder().format_timestamp(None).format_module_path(false).init();
    debug!("Start");
    let opt = Opt::from_args();
    println!("{:?}", opt);
    multi::init_from_path(opt.input.to_str().unwrap(), opt.id);

    test::<ark_bls12_377::Fr>();
    test_group::<ark_bls12_377::G1Projective>();
    test_group::<ark_bls12_377::G2Projective>();
    test_group::<ark_bls12_377::G1Affine>();
    test_group::<ark_bls12_377::G2Affine>();

    debug!("Done");
    multi::uninit();
}
