extern crate common;
extern crate interface;

use std::{collections::BTreeSet, error::Error};

use common::enclave_wrapper::{DcNetEnclave, EnclaveResult};
use dc_proto::{anytrust_node_client::AnytrustNodeClient, SgxMsg};
pub mod dc_proto {
    tonic::include_proto!("dc_proto");
}
use interface::{
    compute_group_id, AggRegistrationBlob, DcMessage, EntityId, KemPubKey, RoundOutput,
    RoundSubmissionBlob, SealedFootprintTicket, SealedKemPrivKey, SealedSharedSecretDb,
    SealedSigPrivKey, ServerRegistrationBlob, SignedPartialAggregate, SignedPubKeyDbBlob,
    UnblindedAggregateShare, UserRegistrationBlob, UserSubmissionReq,
};

use rand::Rng;

struct ServerState<'a> {
    /// A reference to this machine's enclave
    pub enclave: &'a DcNetEnclave,
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
    pub pubkeys: SignedPubKeyDbBlob,
}

impl<'a> ServerState<'a> {
    fn new(enclave: &'a DcNetEnclave) -> Result<(ServerState, SgxMsg), Box<dyn Error>> {
        let (sealed_ssk, sealed_ksk, server_id, reg_data) = enclave.new_server()?;

        let state = ServerState {
            enclave,
            server_id,
            signing_key: sealed_ssk,
            decap_key: sealed_ksk,
            partial_agg: None,
            shared_secrets: SealedSharedSecretDb::default(),
            pubkeys: SignedPubKeyDbBlob::default(),
        };
        let msg = SgxMsg {
            payload: reg_data.0,
        };

        Ok((state, msg))
    }

    /// XORs the shared secrets into the given aggregate. Returns the server's share of the
    /// unblinded aggregate
    fn unblind_aggregate(
        &self,
        toplevel_agg: &RoundSubmissionBlob,
    ) -> Result<UnblindedAggregateShare, Box<dyn Error>> {
        let share = self.enclave.unblind_aggregate(
            toplevel_agg,
            &self.signing_key,
            &self.shared_secrets,
        )?;

        Ok(share)
    }

    /// Derives the final round output given all the shares of the unblinded aggregates
    pub fn derive_round_output(
        &self,
        server_aggs: &[UnblindedAggregateShare],
    ) -> Result<RoundOutput, Box<dyn Error>> {
        let output = self.enclave.derive_round_output(server_aggs)?;

        Ok(output)
    }

    fn recv_user_registration(
        &mut self,
        input_blob: &UserRegistrationBlob,
    ) -> Result<(), Box<dyn Error>> {
        self.enclave.recv_user_registration(
            &mut self.pubkeys,
            &mut self.shared_secrets,
            &self.decap_key,
            input_blob,
        )?;

        Ok(())
    }

    fn recv_aggregator_registration(
        &mut self,
        input_blob: &AggRegistrationBlob,
    ) -> Result<(), Box<dyn Error>> {
        self.enclave
            .recv_aggregator_registration(&mut self.pubkeys, input_blob)?;

        Ok(())
    }

    fn recv_server_registration(
        &mut self,
        input_blob: &ServerRegistrationBlob,
    ) -> Result<(), Box<dyn Error>> {
        self.enclave
            .recv_server_registration(&mut self.pubkeys, input_blob)?;

        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut rng = rand::thread_rng();

    // TODO: maybe not hardcode the enclave path
    let enclave = DcNetEnclave::init("/sgxdcnet/lib/enclave.signed.so")?;
    enclave.run_enclave_tests();

    // TODO: Write a test routine for server

    enclave.destroy();
    Ok(())
}
