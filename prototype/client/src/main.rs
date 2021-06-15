extern crate common;
extern crate interface;

use std::error::Error;

use common::enclave_wrapper::{DcNetEnclave, EnclaveResult, KemPubKey};
use dc_proto::{anytrust_node_client::AnytrustNodeClient, SgxMsg};
pub mod dc_proto {
    tonic::include_proto!("dc_proto");
}
use interface::{
    DcMessage, SealedFootprintTicket, SealedPrvKey, SealedServerSecrets, UserId, UserSubmissionReq,
};

use rand::Rng;

struct UserState<'a> {
    /// A reference to this machine's enclave
    enclave: &'a DcNetEnclave,
    /// A unique identifier for this client. Computed as the hash of the client's pubkey.
    user_id: UserId,
    /// This client's signing key. Can only be accessed from within the enclave.
    signing_key: SealedPrvKey,
    /// The set anytrust servers that this client is registered with
    server_set: Vec<KemPubKey>,
    /// The secrets that this client shares with the anytrust servers. Can only be accessed from
    /// within the enclave.
    shared_secrets: SealedServerSecrets,
}

fn register_user(
    enclave: &DcNetEnclave,
    pubkeys: Vec<KemPubKey>,
) -> Result<(UserState, SgxMsg), Box<dyn Error>> {
    let (sealed_shared_secrets, sealed_usk, user_id, reg_data) = enclave.register_user(&pubkeys)?;

    let state = UserState {
        user_id,
        enclave,
        signing_key: sealed_usk,
        shared_secrets: sealed_shared_secrets,
        server_set: pubkeys,
    };
    let msg = SgxMsg { payload: reg_data };

    Ok((state, msg))
}

impl<'a> UserState<'a> {
    fn submit_round_msg(
        &self,
        round: u32,
        msg: &DcMessage,
        ticket: &SealedFootprintTicket,
    ) -> Result<SgxMsg, Box<dyn Error>> {
        let req = UserSubmissionReq {
            user_id: self.user_id,
            round,
            msg: msg.clone(),
            ticket: ticket.clone(),
            shared_secrets: self.shared_secrets.clone(),
        };

        let msg_blob = self
            .enclave
            .user_submit_round_msg(&req, &self.signing_key)?;

        Ok(SgxMsg { payload: msg_blob })
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
