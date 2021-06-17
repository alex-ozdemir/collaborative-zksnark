use ark_ec::{group::Group, AffineCurve, PairingEngine};
use ark_ff::{FftField, Field, PrimeField, UniformRand};
use log::debug;
use mpc_algebra::gsz20::group::GszGroupShare;
use mpc_algebra::{
    msm::NaiveMsm, share::field::FieldShare, share::group::GroupShare, share::gsz20::*,
    share::pairing::PairingShare, Reveal,
};
use mpc_net::{MpcNet, MpcMultiNet as Net};

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

fn test_ip<F: FftField>() {
    let rng = &mut ark_std::test_rng();
    let iters = 4;
    let size = 100;
    for _iter in 0..iters {
        let a_pubs: Vec<F> = (0..size).map(|_| F::rand(rng)).collect();
        let b_pubs: Vec<F> = (0..size).map(|_| F::rand(rng)).collect();
        //let a_pubs: Vec<F> = (0..size).map(|i| F::from(i as u32)).collect();
        //let b_pubs: Vec<F> = (0..size).map(|i| F::from(i as u32)).collect();
        //let a_pubs: Vec<F> = vec![2u8, 1u8].into_iter().map(F::from).collect();
        //let b_pubs: Vec<F> = vec![2u8, 1u8].into_iter().map(F::from).collect();
        let ip_pub = a_pubs
            .iter()
            .zip(&b_pubs)
            .fold(F::zero(), |x, (a, b)| x + *a * b);
        let a: Vec<_> = a_pubs
            .iter()
            .map(|a| GszFieldShare::from_public(*a))
            .collect();
        let b: Vec<_> = b_pubs
            .iter()
            .map(|b| GszFieldShare::from_public(*b))
            .collect();
        let ip = GszFieldShare::from_public(ip_pub);
        field::ip_check(a, b, ip);
    }
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
        let c = field::mult(a, &b, true);
        let c_pub = field::open(&c);
        assert_eq!(c_pub, a_pub * b_pub);
        assert_ne!(c_pub, a_pub * b_pub + F::one());
    }

    let size = 1000;
    let a_pubs: Vec<F> = (0..size).map(|_| F::rand(rng)).collect();
    let b_pubs: Vec<F> = (0..size).map(|_| F::rand(rng)).collect();
    let a: Vec<_> = a_pubs
        .iter()
        .map(|a| GszFieldShare::from_public(*a))
        .collect();
    let b: Vec<_> = b_pubs
        .iter()
        .map(|b| GszFieldShare::from_public(*b))
        .collect();
    let c = field::batch_mult(a, &b, true);
    let c_pub = GszFieldShare::batch_open(c.clone());
    for i in 0..c.len() {
        assert_eq!(c_pub[i], a_pubs[i] * b_pubs[i]);
    }
}

fn test_mul_field<E: PairingEngine>() {
    use mpc_algebra::share::PanicBeaverSource;
    let rng = &mut ark_std::test_rng();
    let g = E::pairing(
        E::G1Affine::prime_subgroup_generator(),
        E::G2Affine::prime_subgroup_generator(),
    );

    for _i in 0..2 {
        let a_exp_pub = E::Fr::rand(rng);
        let b_exp_pub = E::Fr::rand(rng);
        let a_pub = g.pow(a_exp_pub.into_repr());
        let b_pub = g.pow(b_exp_pub.into_repr());
        let a = mul_field::MulFieldShare::<E::Fqk, E::Fr>::from_public(a_pub);
        let b = mul_field::MulFieldShare::<E::Fqk, E::Fr>::from_public(b_pub);
        let c = a.mul(b, &mut PanicBeaverSource::default());
        let c_pub = mul_field::open_mul_field(&c);
        assert_eq!(c_pub, a_pub * b_pub);
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
        let c = group::mult(&a, b, true);
        let c_pub = group::open(&c);
        assert_eq!(c_pub, b_pub.mul(&a_pub));
    }

    let s1_pub = G::ScalarField::rand(rng);
    let s2_pub = G::ScalarField::rand(rng);
    let s2 = GszFieldShare::from_public(s1_pub);
    let mut a = a;
    <GszGroupShare<G, NaiveMsm<G>> as GroupShare<G>>::scale_pub_scalar(&mut a, &s1_pub);
    let as1s2 = <GszGroupShare<G, NaiveMsm<G>> as GroupShare<G>>::scale(
        a,
        s2,
        &mut mpc_algebra::wire::group::DummyGroupTripleSource::default(),
    );
    let as1s2_pub = group::open(&as1s2);
    assert_eq!(as1s2_pub, a_pub.mul(&s1_pub).mul(&s2_pub));
    test_group_ip::<G>();
}

fn test_group_ip<G: Group>() {
    let rng = &mut ark_std::test_rng();
    let iters = 2;
    let size = 10;
    for _iter in 0..iters {
        let a_pubs: Vec<G::ScalarField> = (0..size).map(|_| G::ScalarField::rand(rng)).collect();
        let b_pubs: Vec<G> = (0..size).map(|_| G::rand(rng)).collect();
        //let a_pubs: Vec<F> = (0..size).map(|i| F::from(i as u32)).collect();
        //let b_pubs: Vec<F> = (0..size).map(|i| F::from(i as u32)).collect();
        //let a_pubs: Vec<F> = vec![2u8, 1u8].into_iter().map(F::from).collect();
        //let b_pubs: Vec<F> = vec![2u8, 1u8].into_iter().map(F::from).collect();
        let ip_pub = a_pubs
            .iter()
            .zip(&b_pubs)
            .fold(G::zero(), |x, (a, b)| x + b.mul(a));
        let a: Vec<_> = a_pubs
            .iter()
            .map(|a| GszFieldShare::from_public(*a))
            .collect();
        let b: Vec<_> = b_pubs
            .iter()
            .map(|b| GszGroupShare::<G, NaiveMsm<G>>::from_public(*b))
            .collect();
        let ip = GszGroupShare::from_public(ip_pub);
        group::ip_check(a, b, ip);
    }
}

fn test_pairing<E: PairingEngine, S: PairingShare<E>>() {
    use mpc_algebra::wire::group::DummyGroupTripleSource;
    let gp1_src = &mut DummyGroupTripleSource::default();
    let gp2_src = &mut DummyGroupTripleSource::default();
    let rng = &mut ark_std::test_rng();
    let g1 = E::G1Affine::prime_subgroup_generator();
    let g2 = E::G2Affine::prime_subgroup_generator();

    for _i in 0..2 {
        let a_pub = E::Fr::rand(rng);
        let b_pub = E::Fr::rand(rng);
        let a = S::FrShare::from_public(a_pub);
        let b = S::FrShare::from_public(b_pub);
        let g1a = <S::G1AffineShare as GroupShare<E::G1Affine>>::scale_pub_group(g1, &a);
        let g2b = <S::G2AffineShare as GroupShare<E::G2Affine>>::scale_pub_group(g2, &b);
        let g1ab = <S::G1AffineShare as GroupShare<E::G1Affine>>::scale(g1a, b, gp1_src);
        let g2ab = <S::G2AffineShare as GroupShare<E::G2Affine>>::scale(g2b, a, gp2_src);
        let g1ab_pub = g1ab.reveal();
        let g2ab_pub = g2ab.reveal();
        assert_eq!(g1ab_pub, Group::mul(&Group::mul(&g1, &a_pub), &b_pub));
        assert_eq!(g2ab_pub, Group::mul(&Group::mul(&g2, &a_pub), &b_pub));
        let g1a_plus_b = <S::G1AffineShare as GroupShare<E::G1Affine>>::multi_scale_pub_group(
            &[g1, g1],
            &[a, b],
        )
        .reveal();
        assert_eq!(g1a_plus_b, Group::mul(&g1, &(a_pub + b_pub)));
        let g2a_plus_b = <S::G2AffineShare as GroupShare<E::G2Affine>>::multi_scale_pub_group(
            &[g2, g2],
            &[a, b],
        )
        .reveal();
        assert_eq!(g2a_plus_b, Group::mul(&g2, &(a_pub + b_pub)));
    }
}

fn main() {
    env_logger::builder().format_timestamp(None).init();
    //env_logger::builder().format_timestamp(None).format_module_path(false).init();
    debug!("Start");
    let opt = Opt::from_args();
    println!("{:?}", opt);
    Net::init_from_file(opt.input.to_str().unwrap(), opt.id);

    test::<ark_bls12_377::Fr>();
    test_ip::<ark_bls12_377::Fr>();
    test_group::<ark_bls12_377::G1Projective>();
    test_group::<ark_bls12_377::G2Projective>();
    test_group::<ark_bls12_377::G1Affine>();
    test_group::<ark_bls12_377::G2Affine>();
    test_mul_field::<ark_bls12_377::Bls12_377>();
    test_pairing::<ark_bls12_377::Bls12_377, GszPairingShare<ark_bls12_377::Bls12_377>>();

    debug!("Done");
    Net::deinit();
}
