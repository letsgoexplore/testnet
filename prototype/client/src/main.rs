extern crate common;
extern crate interface;

use std::error::Error;

use common::enclave_wrapper::{DcNetEnclave, EnclaveResult, KemPubKey};
use dc_proto::{anytrust_node_client::AnytrustNodeClient, SgxMsg};
pub mod dc_proto {
    tonic::include_proto!("dc_proto");
}
use interface::{DcMessage, SealedPrvKey, SealedServerSecrets};

use rand::Rng;

struct UserState<'a> {
    enclave: &'a DcNetEnclave,
    signing_key: SealedPrvKey,
    shared_secrets: SealedServerSecrets,
    server_set: Vec<KemPubKey>,
}

fn register_user(
    enclave: &DcNetEnclave,
    pubkeys: Vec<KemPubKey>,
) -> Result<(UserState, SgxMsg), Box<dyn Error>> {
    let (sealed_shared_secrets, sealed_usk, reg_data) = enclave.register_user(&pubkeys)?;

    let state = UserState {
        enclave,
        signing_key: sealed_usk,
        shared_secrets: sealed_shared_secrets,
        server_set: pubkeys,
    };
    let msg = SgxMsg { payload: reg_data };

    Ok((state, msg))
}

impl<'a> UserState<'a> {
    fn submit_msg(&self, round: u32, msg: &DcMessage) -> Result<SgxMsg, Box<dyn Error>> {
        unimplemented!();
    }
}

async fn test_register_user<R: Rng>(
    rng: &mut R,
    anytrust_url: String,
    enclave: &DcNetEnclave,
) -> Result<(), Box<dyn Error>> {
    // Make a fresh set of some pubkeys
    let pubkeys: Vec<KemPubKey> = (0..6).map(|_| KemPubKey::rand_placeholder(rng)).collect();

    let (state, reg_msg) = register_user(enclave, pubkeys)?;
    let req = tonic::Request::new(reg_msg);

    let mut client = AnytrustNodeClient::connect(anytrust_url).await?;
    let res = client.register_pubkey(req).await?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut rng = rand::thread_rng();

    // TODO: maybe not hardcode the enclave path
    let enclave = DcNetEnclave::init("/sgxdcnet/lib/enclave.signed.so")?;
    enclave.run_enclave_tests();

    // Run registration
    let anytrust_url = "http://[::1]:78934".to_string();
    test_register_user(&mut rng, anytrust_url, &enclave).await?;

    enclave.destroy();
    Ok(())
}
