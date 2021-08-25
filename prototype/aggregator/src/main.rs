extern crate common;
extern crate interface;

mod agg_state;
mod service;

use crate::{agg_state::register_aggregator, service::start_service};

use common::enclave_wrapper::DcNetEnclave;
use interface::KemPubKey;

use std::{
    error::Error,
    fs::File,
    io::{BufRead, BufReader},
    sync::{Arc, Mutex},
};

use clap::{App, Arg};

// Parses the KEM pubkey file. It's a
fn parse_pubkey_file(filename: &str) -> Result<Vec<KemPubKey>, Box<dyn Error>> {
    let f = File::open(filename)?;
    serde_json::from_reader(f).map_err(Into::into)
}

fn main() -> Result<(), Box<dyn Error>> {
    let enclave = {
        let enclave_handle = DcNetEnclave::init("/sgxdcnet/lib/enclave.signed.so")?;
        Arc::new(Mutex::new(enclave_handle))
    };

    let matches = App::new("SGX DCNet Aggregator")
        .version("0.1.0")
        .arg(
            Arg::with_name("pubkey-file")
                .short("p")
                .long("pubkey-file")
                .value_name("FILE")
                .default_value("pubkeys.json")
                .takes_value(true)
                .help("A JSON file containing a list of anytrust server KEM pubkeys"),
        )
        .get_matches();
    let pubkey_filename = matches.value_of("pubkey-file").unwrap();
    let pubkeys = parse_pubkey_file(&pubkey_filename).unwrap();

    let (state, reg_msg) = register_aggregator(enclave, pubkeys)?;

    start_service(state);

    Ok(())
}
