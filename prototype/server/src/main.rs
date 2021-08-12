extern crate common;
extern crate interface;

mod server_state;
use server_state::ServerState;

use common::enclave_wrapper::DcNetEnclave;
use interface::KemPubKey;

use std::error::Error;

const AGGREGATOR_ADDR: &str = "http://localhost:8080";
const GET_AGG_PATH: &str = "get-agg";

fn main() -> Result<(), Box<dyn Error>> {
    // Do setup
    let enclave = DcNetEnclave::init("/sgxdcnet/lib/enclave.signed.so")?;
    println!("Making new server");
    let (state, _) = ServerState::new(&enclave)?;

    // Print the KEM pubkey
    let pubkey_str = {
        println!("Unsealing PK");
        let kem_pubkey = enclave.unseal_to_public_key_on_p256(&state.signing_key.0)?;
        println!("Unsealed PK");
        base64::encode(serde_cbor::to_vec(&kem_pubkey)?)
    };
    println!("Using KEM pubkey\n{}", pubkey_str);

    // Now connect to the aggregator
    let agg = reqwest::blocking::get(format!("{}/{}", AGGREGATOR_ADDR, GET_AGG_PATH))?.bytes()?;
    println!("Got an aggregate of {} bytes", agg.len());

    enclave.destroy();
    Ok(())
}
