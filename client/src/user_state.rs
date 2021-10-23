use crate::util::Result;

use common::enclave_wrapper::DcNetEnclave;
use serde::{Deserialize, Serialize};

use interface::{
    compute_anytrust_group_id, DcMessage, EntityId, KemPubKey, RoundOutput, RoundSubmissionBlob,
    SealedSharedSecretDb, SealedSigPrivKey, ServerPubKeyPackage, UserRegistrationBlob,
    UserReservationReq, UserSubmissionReq,
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
    /// The anytrust servers' KEM and signing pubkeys
    anytrust_group_keys: Vec<ServerPubKeyPackage>,
}

impl UserState {
    /// Creates a new user state and registration blob for the server
    pub fn new(
        enclave: &DcNetEnclave,
        pubkeys: Vec<ServerPubKeyPackage>,
    ) -> Result<(UserState, UserRegistrationBlob)> {
        let (sealed_shared_secrets, sealed_usk, user_id, reg_blob) = enclave.new_user(&pubkeys)?;

        let kem_pubkeys: Vec<KemPubKey> = pubkeys.iter().map(|p| p.kem).collect();
        let anytrust_group_id = compute_anytrust_group_id(&kem_pubkeys);

        let state = UserState {
            user_id,
            anytrust_group_id,
            signing_key: sealed_usk.to_owned(),
            shared_secrets: sealed_shared_secrets.to_owned(),
            anytrust_group_keys: pubkeys,
        };

        Ok((state, reg_blob))
    }

    pub fn submit_round_msg(
        &self,
        enclave: &DcNetEnclave,
        round: u32,
        msg: DcMessage,
        prev_round_output: RoundOutput,
    ) -> Result<RoundSubmissionBlob> {
        let req = UserSubmissionReq {
            user_id: self.user_id,
            anytrust_group_id: self.anytrust_group_id,
            round,
            msg,
            shared_secrets: self.shared_secrets.clone(),
            prev_round_output,
        };

        let blob = enclave.user_submit_round_msg(&req, &self.signing_key)?;
        Ok(blob)
    }

    pub fn reserve_slot(&self, enclave: &DcNetEnclave, round: u32) -> Result<RoundSubmissionBlob> {
        let req = UserReservationReq {
            user_id: self.user_id,
            anytrust_group_id: self.anytrust_group_id,
            round,
            shared_secrets: self.shared_secrets.clone(),
        };

        let blob = enclave.user_reserve_slot(&req, &self.signing_key)?;
        Ok(blob)
    }
}