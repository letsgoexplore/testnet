use crate::util::Result;

use interface::{
    EntityId,
    RoundOutputUpdated,
    UserRegistrationBlobNew,
    ServerPubKeyPackageNoSGX,
};

use log::info;
use serde::{Deserialize, Serialize};

use ed25519_dalek::SecretKey;

use common::types_nosgx::{
    AggregatedMessage,
    SharedSecretsDbServer,
    SignedPubKeyDbNoSGX,
    RoundSubmissionBlobNoSGX,
    UnblindedAggregateShareBlobNoSGX,
    AggRegistrationBlobNoSGX,
    ServerRegistrationBlobNoSGX,
};

use crate::server_nosgx::{
    new_server,
    recv_user_registration_batch,
    recv_aggregator_registration,
    recv_server_registration,
    unblind_aggregate,
    derive_round_output,
};

#[derive(Serialize, Deserialize)]
pub struct ServerState {
    /// A unique identifier for this aggregator. Computed as the hash of the server's KEM pubkey.
    pub server_id: EntityId,
    /// This server's's signing key.
    pub signing_key: SecretKey,
    /// This server's KEM decapsulation key.
    pub decap_key: SecretKey,
    /// The KEM and signing public keys of this server
    pub pubkey_pkg: ServerPubKeyPackageNoSGX,
    /// A partial aggregate of received user messages
    pub partial_agg: Option<AggregatedMessage>,
    /// A sealed database of secrets shared with users. Maps entity ID to shared secret.
    pub shared_secrets: SharedSecretsDbServer,
    /// A map of EntityIds to the corresponding public key
    pub pubkeys: SignedPubKeyDbNoSGX,
    /// The size of this anytrust group, including this node
    pub anytrust_group_size: usize,
}

impl ServerState {
    pub fn new() -> Result<(ServerState, ServerPubKeyPackageNoSGX)> {
        let (ssk, ksk, server_id, reg_blob) = new_server()?;
        // Group size starts out as 1. This will increment every time an anytrust node is
        // registered with this node.
        let anytrust_group_size = 1;
        // The registration blob is just the pubkey package info
        let pubkey_pkg = reg_blob.clone();

        let state = ServerState {
            server_id,
            signing_key: ssk,
            decap_key: ksk,
            pubkey_pkg,
            partial_agg: None,
            shared_secrets: SharedSecretsDbServer::default(),
            pubkeys: SignedPubKeyDbNoSGX::default(),
            anytrust_group_size,
        };

        Ok((state, reg_blob))
    }

    /// XORs the shared secrets into the given aggregate. Returns the server's share of the
    /// unblinded aggregate as well as the ratcheted shared secrets
    pub fn unblind_aggregate(
        &mut self,
        toplevel_agg: &RoundSubmissionBlobNoSGX,
    ) -> Result<UnblindedAggregateShareBlobNoSGX> {
        let (share, ratcheted_secrets) =
            unblind_aggregate(toplevel_agg, &self.signing_key, &self.shared_secrets)?;

        // Ratchet the secrets forward
        self.shared_secrets = ratcheted_secrets;

        Ok(share)
    }

    /// Derives the final round output given all the shares of the unblinded aggregates
    pub fn derive_round_output(
        &self,
        server_aggs: &[UnblindedAggregateShareBlobNoSGX],
    ) -> Result<RoundOutputUpdated> {
        derive_round_output(&self.signing_key, server_aggs)
    }

    /// Registers a user with this server
    pub fn recv_user_registrations(
        &mut self,
        input_blobs: &[UserRegistrationBlobNew],
    ) -> Result<()> {
        recv_user_registration_batch(
            &mut self.pubkeys,
            &mut self.shared_secrets,
            &self.decap_key,
            input_blobs,
        )?;

        Ok(())
    }

    /// Registers an aggregator with this server
    pub fn recv_aggregator_registration(
        &mut self,
        input_blob: &AggRegistrationBlobNoSGX,
    ) -> Result<()> {
        recv_aggregator_registration(&mut self.pubkeys, input_blob)?;

        Ok(())
    }

    /// Registers another anytrust server with this server. This will be added to the server's
    /// anytrust group
    pub fn recv_server_registration(
        &mut self,
        input_blob: &ServerRegistrationBlobNoSGX,
    ) -> Result<()> {
        // Input the registration and increment the size of the group
        recv_server_registration(&mut self.pubkeys, input_blob)?;
        self.anytrust_group_size += 1;

        info!(
            "Registered new server. Anytrust group size is now {}",
            self.anytrust_group_size
        );

        Ok(())
    }
}

/// Tests that making a new server succeeds
#[test]
fn test_new_server() {
    ServerState::new().unwrap();
}
