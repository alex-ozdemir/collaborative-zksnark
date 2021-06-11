use log::debug;
use mpc_net::multi as net;
use mpc_algebra::share::gs20;

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

fn main() {
    env_logger::builder().format_timestamp(None).format_module_path(false).init();
    debug!("Start");
    let opt = Opt::from_args();
    println!("{:?}", opt);
    multi::init_from_path(opt.input.to_str().unwrap(), opt.id);
    let all = multi::broadcast(&[opt.id as u8]);
    println!("{:?}", all);
    let r = multi::send_to_king(&[opt.id as u8]);
    let all = multi::recv_from_king(r);
    println!("{:?}", all);
    multi::uninit();
}
