extern crate common;
extern crate interface;

use std::{collections::BTreeSet, error::Error};

use common::enclave_wrapper::{DcNetEnclave, EnclaveResult};
use dc_proto::{anytrust_node_client::AnytrustNodeClient, SgxMsg};

pub mod dc_proto {
    tonic::include_proto!("dc_proto");
}

use interface::{
    compute_group_id, DcMessage, EntityId, KemPubKey, SealedFootprintTicket, SealedKey,
    SealedServerSecrets, UserSubmissionReq,
};

use rand::Rng;

struct UserState<'a> {
    /// A reference to this machine's enclave
    enclave: &'a DcNetEnclave,
    /// A unique identifier for this client. Computed as the hash of the client's pubkey.
    user_id: EntityId,
    /// A unique for the set anytrust servers that this client is registered with
    anytrust_group_id: EntityId,
    /// This client's signing key. Can only be accessed from within the enclave.
    signing_key: SealedKey,
    /// The secrets that this client shares with the anytrust servers. Can only be accessed from
    /// within the enclave.
    shared_secrets: SealedServerSecrets,
}

fn register_user(
    enclave: &DcNetEnclave,
    pubkeys: Vec<KemPubKey>,
) -> Result<(UserState, SgxMsg), Box<dyn Error>> {
    let (sealed_shared_secrets, sealed_usk, user_id, reg_data) = enclave.register_user(&pubkeys)?;

    let anytrust_ids: BTreeSet<EntityId> = pubkeys.iter().map(|pk| pk.get_entity_id()).collect();
    let anytrust_group_id = compute_group_id(&anytrust_ids);

    let state = UserState {
        user_id,
        anytrust_group_id,
        enclave,
        signing_key: sealed_usk.to_owned(),
        shared_secrets: sealed_shared_secrets.to_owned(),
    };
    let msg = SgxMsg {
        payload: reg_data.to_vec(),
    };

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
            anytrust_group_id: self.anytrust_group_id,
            round,
            msg: msg.clone(),
            ticket: ticket.clone(),
            server_secrets: self.shared_secrets.clone(),
        };

        let msg_blob = self
            .enclave
            .user_submit_round_msg(&req, &self.signing_key)?;

        Ok(SgxMsg {
            payload: msg_blob.0,
        })
    }
}

async fn test_register_user<R: Rng>(
    rng: &mut R,
    anytrust_url: String,
    enclave: &DcNetEnclave,
) -> Result<(), Box<dyn Error>> {
    // Make a fresh set of some pubkeys
    let pubkeys: Vec<KemPubKey> = (0..6)
        .map(|_| KemPubKey::rand_invalid_placeholder(rng))
        .collect();

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
