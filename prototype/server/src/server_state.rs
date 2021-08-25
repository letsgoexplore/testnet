use std::{collections::BTreeSet, error::Error};

use common::enclave_wrapper::{DcNetEnclave, EnclaveResult};
use dc_proto::{anytrust_node_client::AnytrustNodeClient, SgxMsg};
pub mod dc_proto {
    tonic::include_proto!("dc_proto");
}
use interface::{
    compute_group_id, AggRegistrationBlob, DcMessage, EntityId, KemPubKey, RoundOutput,
    RoundSubmissionBlob, SealedFootprintTicket, SealedKemPrivKey, SealedSharedSecretDb,
    SealedSigPrivKey, ServerRegistrationBlob, SignedPartialAggregate, SignedPubKeyDb,
    UnblindedAggregateShareBlob, UserRegistrationBlob, UserSubmissionReq,
};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct ServerState {
    /// A unique identifier for this aggregator. Computed as the hash of the server's KEM pubkey.
    pub server_id: EntityId,
    /// This server's's signing key. Can only be accessed from within the enclave.
    pub signing_key: SealedSigPrivKey,
    /// This server's KEM decapsulation key. Can only be accessed from within the enclave.
    pub decap_key: SealedKemPrivKey,
    /// A partial aggregate of received user messages
    pub partial_agg: Option<SignedPartialAggregate>,
    /// A sealed database of secrets shared with users. Maps entity ID to shared secret. Can only
    /// be accessed from within the enclave.
    pub shared_secrets: SealedSharedSecretDb,
    /// A map of EntityIds to the corresponding public key
    pub pubkeys: SignedPubKeyDb,
}

impl ServerState {
    pub fn new(enclave: &DcNetEnclave) -> Result<(ServerState, SgxMsg), Box<dyn Error>> {
        let (sealed_ssk, sealed_ksk, server_id, reg_data) = enclave.new_server()?;

        let state = ServerState {
            server_id,
            signing_key: sealed_ssk,
            decap_key: sealed_ksk,
            partial_agg: None,
            shared_secrets: SealedSharedSecretDb::default(),
            pubkeys: SignedPubKeyDb::default(),
        };
        let msg = SgxMsg {
            payload: reg_data.kem_key.tee_linkable_attestation,
        };

        Ok((state, msg))
    }

    /// XORs the shared secrets into the given aggregate. Returns the server's share of the
    /// unblinded aggregate
    pub fn unblind_aggregate(
        &self,
        enclave: &DcNetEnclave,
        toplevel_agg: &RoundSubmissionBlob,
    ) -> Result<UnblindedAggregateShareBlob, Box<dyn Error>> {
        let share =
            enclave.unblind_aggregate(toplevel_agg, &self.signing_key, &self.shared_secrets)?;

        Ok(share)
    }

    /// Derives the final round output given all the shares of the unblinded aggregates
    pub fn derive_round_output(
        &self,
        enclave: &DcNetEnclave,
        server_aggs: &[UnblindedAggregateShareBlob],
    ) -> Result<RoundOutput, Box<dyn Error>> {
        let output = enclave.derive_round_output(server_aggs)?;

        Ok(output)
    }

    pub fn recv_user_registration(
        &mut self,
        enclave: &DcNetEnclave,
        input_blob: &UserRegistrationBlob,
    ) -> Result<(), Box<dyn Error>> {
        enclave.recv_user_registration(
            &mut self.pubkeys,
            &mut self.shared_secrets,
            &self.decap_key,
            input_blob,
        )?;

        Ok(())
    }

    pub fn recv_aggregator_registration(
        &mut self,
        enclave: &DcNetEnclave,
        input_blob: &AggRegistrationBlob,
    ) -> Result<(), Box<dyn Error>> {
        enclave.recv_aggregator_registration(&mut self.pubkeys, input_blob)?;

        Ok(())
    }

    pub fn recv_server_registration(
        &mut self,
        enclave: &DcNetEnclave,
        input_blob: &ServerRegistrationBlob,
    ) -> Result<(), Box<dyn Error>> {
        enclave.recv_server_registration(&mut self.pubkeys, input_blob)?;

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
