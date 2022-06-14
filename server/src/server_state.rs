use crate::util::Result;

use common::ecall_wrapper::DcNetEnclave;
use interface::{
    AggRegistrationBlob, EntityId, RoundOutput, RoundSubmissionBlob, SealedKemPrivKey,
    SealedSharedSecretDb, SealedSigPrivKey, ServerPubKeyPackage, ServerRegistrationBlob,
    SignedPartialAggregate, SignedPubKeyDb, UnblindedAggregateShareBlob, UserRegistrationBlob,
};

use log::info;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct ServerState {
    /// A unique identifier for this aggregator. Computed as the hash of the server's KEM pubkey.
    pub server_id: EntityId,
    /// This server's's signing key. Can only be accessed from within the enclave.
    pub signing_key: SealedSigPrivKey,
    /// This server's KEM decapsulation key. Can only be accessed from within the enclave.
    pub decap_key: SealedKemPrivKey,
    /// The KEM and signing public keys of this server
    pub pubkey_pkg: ServerPubKeyPackage,
    /// A partial aggregate of received user messages
    pub partial_agg: Option<SignedPartialAggregate>,
    /// A sealed database of secrets shared with users. Maps entity ID to shared secret. Can only
    /// be accessed from within the enclave.
    pub shared_secrets: SealedSharedSecretDb,
    /// A map of EntityIds to the corresponding public key
    pub pubkeys: SignedPubKeyDb,
    /// The size of this anytrust group, including this node
    pub anytrust_group_size: usize,
}

impl ServerState {
    pub fn new(enclave: &DcNetEnclave) -> Result<(ServerState, ServerRegistrationBlob)> {
        let (sealed_ssk, sealed_ksk, server_id, reg_blob) = enclave.new_server()?;
        // Group size starts out as 1. This will increment every time an anytrust node is
        // registered with this node.
        let anytrust_group_size = 1;
        // The registration blob is just the pubkey package info
        let pubkey_pkg = reg_blob.clone();

        let state = ServerState {
            server_id,
            signing_key: sealed_ssk,
            decap_key: sealed_ksk,
            pubkey_pkg,
            partial_agg: None,
            shared_secrets: SealedSharedSecretDb::default(),
            pubkeys: SignedPubKeyDb::default(),
            anytrust_group_size,
        };

        Ok((state, reg_blob))
    }

    /// XORs the shared secrets into the given aggregate. Returns the server's share of the
    /// unblinded aggregate as well as the ratcheted shared secrets
    pub fn unblind_aggregate(
        &mut self,
        enclave: &DcNetEnclave,
        toplevel_agg: &RoundSubmissionBlob,
    ) -> Result<UnblindedAggregateShareBlob> {
        let (share, ratcheted_secrets) =
            enclave.unblind_aggregate(toplevel_agg, &self.signing_key, &self.shared_secrets)?;

        // Ratchet the secrets forward
        self.shared_secrets = ratcheted_secrets;

        Ok(share)
    }

    /// Derives the final round output given all the shares of the unblinded aggregates
    pub fn derive_round_output(
        &self,
        enclave: &DcNetEnclave,
        server_aggs: &[UnblindedAggregateShareBlob],
    ) -> Result<RoundOutput> {
        enclave
            .derive_round_output(&self.signing_key, server_aggs)
            .map_err(Into::into)
    }

    /// Registers a user with this server
    pub fn recv_user_registration(
        &mut self,
        enclave: &DcNetEnclave,
        input_blob: &UserRegistrationBlob,
    ) -> Result<()> {
        enclave.recv_user_registration(
            &mut self.pubkeys,
            &mut self.shared_secrets,
            &self.decap_key,
            input_blob,
        )?;

        Ok(())
    }

    /// Registers an aggregator with this server
    pub fn recv_aggregator_registration(
        &mut self,
        enclave: &DcNetEnclave,
        input_blob: &AggRegistrationBlob,
    ) -> Result<()> {
        enclave.recv_aggregator_registration(&mut self.pubkeys, input_blob)?;

        Ok(())
    }

    /// Registers another anytrust server with this server. This will be added to the server's
    /// anytrust group
    pub fn recv_server_registration(
        &mut self,
        enclave: &DcNetEnclave,
        input_blob: &ServerRegistrationBlob,
    ) -> Result<()> {
        // Input the registration and increment the size of the group
        enclave.recv_server_registration(&mut self.pubkeys, input_blob)?;
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
    let enclave = DcNetEnclave::init("/sgxdcnet/lib/enclave.signed.so").unwrap();
    ServerState::new(&enclave).unwrap();
    enclave.destroy();
}
