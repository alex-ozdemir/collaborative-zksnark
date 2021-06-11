use log::debug;
use mpc_net::multi;
use mpc_algebra::ss::share::gsz20;
use ark_ff::FftField;

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
    let (a, b) = gsz20::double_rand::<F>();
    let a_pub = gsz20::open(&a);
    let b_pub = gsz20::open_degree(&b, gsz20::t() * 2);
    assert_eq!(a_pub, b_pub);
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
