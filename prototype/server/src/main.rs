extern crate common;
extern crate interface;

mod server_state;
use server_state::ServerState;

use common::enclave_wrapper::DcNetEnclave;
use interface::KemPubKey;

use std::{
    error::Error,
    fs::File,
    sync::{Arc, Mutex},
};

use clap::{App, Arg};

const AGGREGATOR_ADDR: &str = "http://localhost:8080";
const GET_AGG_PATH: &str = "get-agg";

/// Load the server state from a file
fn load_server_state(
    filename: &str,
    enclave: &DcNetEnclave,
) -> Result<ServerState, Box<dyn Error>> {
    match File::open(filename) {
        Ok(f) => serde_json::from_reader(f).map_err(Into::into),
        _ => {
            println!("Creating new state");
            let state = ServerState::new(&enclave)?.0;
            save_state(filename, &state);
            Ok(state)
        }
    }
}

/// Saves the server state
fn save_state(filename: &str, state: &ServerState) -> Result<(), Box<dyn Error>> {
    let mut f = File::create(filename)?;
    serde_json::to_writer(&mut f, state)?;

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    // Do setup
    let enclave = DcNetEnclave::init("/sgxdcnet/lib/enclave.signed.so")?;

    let matches = App::new("SGX DCNet Anytrust Node")
        .version("0.1.0")
        .arg(
            Arg::with_name("server-state")
                .short("s")
                .long("server-state")
                .value_name("FILE")
                .required(false)
                .takes_value(true)
                .default_value("server-state.json")
                .help("A file that contains this server's previous state"),
        )
        .get_matches();

    let save_filename = matches.value_of("server-state").unwrap();
    let state = load_server_state(save_filename, &enclave)?;

    /*
    // Print the KEM pubkey
    let pubkey_str = {
        println!("Unsealing PK");
        let kem_pubkey = enclave.unseal_to_public_key_on_p256(&state.signing_key.0)?;
        println!("Unsealed PK");
        base64::encode(serde_json::to_vec(&kem_pubkey)?)
    };
    println!("Using KEM pubkey\n{}", pubkey_str);

    // Now connect to the aggregator
    let agg = reqwest::blocking::get(format!("{}/{}", AGGREGATOR_ADDR, GET_AGG_PATH))?.bytes()?;
    println!("Got an aggregate of {} bytes", agg.len());

    */
    enclave.destroy();
    Ok(())
}
