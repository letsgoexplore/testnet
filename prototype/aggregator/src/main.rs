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

// Parses the KEM pubkey file. Each line is a base64-encoded byte sequence. The byte sequence is a
// CBOR encoding of a KemPubKey
fn parse_kemfile(filename: &str) -> Result<Vec<KemPubKey>, Box<dyn Error>> {
    let f = File::open(filename)?;
    let mut reader = BufReader::new(f);
    let mut line = String::new();

    let mut pubkeys: Vec<KemPubKey> = Vec::new();

    while reader.read_line(&mut line)? > 0 {
        let bytes = base64::decode(&line)?;
        let pubkey = serde_cbor::from_slice(&bytes)?;

        pubkeys.push(pubkey);
    }

    Ok(pubkeys)
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
                .required(true)
                .takes_value(true)
                .help(
                    "A text file containing newline-separated, base64-encoded KEM pubkeys of \
                    anytrust nodes",
                ),
        )
        .get_matches();
    let kem_filename = matches.value_of("pubkey-file").unwrap();
    let pubkeys = parse_kemfile(&kem_filename).unwrap();

    let (state, reg_msg) = register_aggregator(enclave, pubkeys)?;

    start_service(state);

    Ok(())
}
