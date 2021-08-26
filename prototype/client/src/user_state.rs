use std::{collections::BTreeSet, error::Error};

use common::enclave_wrapper::{DcNetEnclave, EnclaveResult};
use dc_proto::{anytrust_node_client::AnytrustNodeClient, SgxMsg};
use serde::{Deserialize, Serialize};

pub mod dc_proto {
    tonic::include_proto!("dc_proto");
}

use interface::{
    compute_anytrust_group_id, compute_group_id, DcMessage, EntityId, KemPubKey,
    RoundSubmissionBlob, SealedFootprintTicket, SealedSharedSecretDb, SealedSigPrivKey,
    UserRegistrationBlob, UserSubmissionReq,
};

#[derive(Serialize, Deserialize)]
pub struct UserState {
    /// A unique identifier for this client. Computed as the hash of the client's pubkey.
    user_id: EntityId,
    /// A unique for the set anytrust servers that this client is registered with
    anytrust_group_id: EntityId,
    /// This client's signing key. Can only be accessed from within the enclave.
    signing_key: SealedSigPrivKey,
    /// The secrets that this client shares with the anytrust servers. Maps entity ID to shared
    /// secret. Can only be accessed from within the enclave.
    shared_secrets: SealedSharedSecretDb,
}

impl UserState {
    /// Creates a new user state and registration blob for the server
    pub fn new(
        enclave: &DcNetEnclave,
        pubkeys: Vec<KemPubKey>,
    ) -> Result<(UserState, UserRegistrationBlob), Box<dyn Error>> {
        let (sealed_shared_secrets, sealed_usk, user_id, reg_blob) = enclave.new_user(&pubkeys)?;

        let anytrust_group_id = compute_anytrust_group_id(&pubkeys);

        let state = UserState {
            user_id,
            anytrust_group_id,
            signing_key: sealed_usk.to_owned(),
            shared_secrets: sealed_shared_secrets.to_owned(),
        };

        Ok((state, reg_blob))
    }

    pub fn submit_round_msg(
        &self,
        enclave: &DcNetEnclave,
        round: u32,
        msg: &DcMessage,
        ticket: &SealedFootprintTicket,
    ) -> Result<RoundSubmissionBlob, Box<dyn Error>> {
        let req = UserSubmissionReq {
            user_id: self.user_id,
            anytrust_group_id: self.anytrust_group_id,
            round,
            msg: msg.clone(),
            ticket: ticket.clone(),
            shared_secrets: self.shared_secrets.clone(),
        };

        let blob = enclave.user_submit_round_msg(&req, &self.signing_key)?;
        Ok(blob)
    }
}
