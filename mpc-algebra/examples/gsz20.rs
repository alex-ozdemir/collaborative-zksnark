use ark_ff::FftField;
use log::debug;
use mpc_algebra::{share::gsz20::*, Reveal};
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
    let (a, b) = double_rand::<F>();
    let a_pub = open(&a);
    let b_pub = open(&b);
    assert_eq!(a_pub, b_pub);

    for _i in 0..10 {
        let a_pub = F::rand(rng);
        let b_pub = F::rand(rng);
        let a = GszFieldShare::from_public(a_pub);
        let b = GszFieldShare::from_public(b_pub);
        let c = mult(a, &b);
        let c_pub = open(&c);
        assert_eq!(c_pub, a_pub * b_pub);
        assert_ne!(c_pub, a_pub * b_pub + F::one());
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

    debug!("Done");
    multi::uninit();
}
