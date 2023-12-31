use crate::util::Result;

use common::enclave::DcNetEnclave;
use serde::{Deserialize, Serialize};

use interface::{
    compute_anytrust_group_id, EntityId, SealedSharedSecretsDbClient, SealedSigPrivKey,
    ServerPubKeyPackage, SgxProtectedKeyPub, UserMsg, UserRegistrationBlob, UserSubmissionBlob,
    UserSubmissionReq, DC_NET_ROUNDS_PER_WINDOW,
};

#[derive(Clone, Serialize, Deserialize)]
pub struct UserState {
    /// A unique identifier for this client. Computed as the hash of the client's pubkey.
    user_id: EntityId,
    /// A unique for the set anytrust servers that this client is registered with
    anytrust_group_id: EntityId,
    /// This client's signing key. Can only be accessed from within the enclave.
    signing_key: SealedSigPrivKey,
    /// The secrets that this client shares with the anytrust servers. Maps entity ID to shared
    /// secret. Can only be accessed from within the enclave.
    shared_secrets: SealedSharedSecretsDbClient,
    /// The anytrust servers' KEM and signing pubkeys
    anytrust_group_keys: Vec<ServerPubKeyPackage>,
    /// Times talked or reserved so far in this window
    times_participated: u32,
}

impl UserState {
    /// Creates a `n` UserStates and registration blobs for the server
    pub fn new_multi(
        enclave: &DcNetEnclave,
        n: usize,
        pubkeys: Vec<ServerPubKeyPackage>,
    ) -> Result<Vec<(UserState, UserRegistrationBlob)>> {
        let vec = enclave.new_user_batch(&pubkeys, n)?;

        let users_and_reg_blobs = vec
            .into_iter()
            .map(|(sealed_shared_secrets, sealed_usk, reg_blob)| {
                let user_id = EntityId::from(&reg_blob);
                let kem_pubkeys: Vec<SgxProtectedKeyPub> = pubkeys
                    .iter()
                    .map(|p| SgxProtectedKeyPub(p.kem.to_bytes()))
                    .collect();
                let anytrust_group_id = compute_anytrust_group_id(&kem_pubkeys);

                let state = UserState {
                    user_id,
                    anytrust_group_id,
                    signing_key: sealed_usk.to_owned(),
                    shared_secrets: sealed_shared_secrets.to_owned(),
                    anytrust_group_keys: pubkeys.clone(),
                    times_participated: 0,
                };
                (state, reg_blob)
            })
            .collect();

        Ok(users_and_reg_blobs)
    }

    pub fn get_times_participated(&self) -> u32 {
        self.times_participated
    }

    pub fn submit_round_msg(
        &mut self,
        enclave: &DcNetEnclave,
        round: u32,
        msg: UserMsg,
    ) -> Result<UserSubmissionBlob> {
        let msg_is_cover = msg.is_cover();
        let req = UserSubmissionReq {
            user_id: self.user_id,
            anytrust_group_id: self.anytrust_group_id,
            round,
            msg,
            shared_secrets: self.shared_secrets.clone(),
            server_pks: self.anytrust_group_keys.clone(),
        };

        // If this round is a new window, clear the number of times participated
        if round % DC_NET_ROUNDS_PER_WINDOW == 0 {
            self.times_participated = 0;
        }

        // Submit the message
        let (blob, ratcheted_secrets) = enclave.user_submit_round_msg(&req, &self.signing_key)?;

        // Ratchet the secrets forward
        self.shared_secrets = ratcheted_secrets;

        // If this message was participatory, increment times_participated
        if !msg_is_cover {
            self.times_participated += 1;
        }

        Ok(blob)
    }
}
