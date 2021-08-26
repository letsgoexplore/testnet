use std::{collections::BTreeSet, error::Error};

use common::enclave_wrapper::{DcNetEnclave, EnclaveResult};
use dc_proto::{anytrust_node_client::AnytrustNodeClient, SgxMsg};
use serde::{Deserialize, Serialize};
pub mod dc_proto {
    tonic::include_proto!("dc_proto");
}
use interface::{
    compute_group_id, AggRegistrationBlob, DcMessage, EntityId, KemPubKey, RoundSubmissionBlob,
    SealedFootprintTicket, SealedSigPrivKey, SignedPartialAggregate, UserSubmissionReq,
};

use rand::Rng;

#[derive(Serialize, Deserialize)]
pub(crate) struct AggregatorState {
    /// A unique identifier for this aggregator. Computed as the hash of the aggregator's pubkey.
    agg_id: EntityId,
    /// A unique for the set anytrust servers that this aggregator is registered with
    anytrust_group_id: EntityId,
    /// This aggregator's signing key. Can only be accessed from within the enclave.
    signing_key: SealedSigPrivKey,
    /// A partial aggregate of received user messages
    partial_agg: Option<SignedPartialAggregate>,
}

impl AggregatorState {
    /// Makes a new aggregate given the pubkeys of the servers
    pub(crate) fn new(
        enclave: &DcNetEnclave,
        pubkeys: Vec<KemPubKey>,
    ) -> Result<(AggregatorState, AggRegistrationBlob), Box<dyn Error>> {
        let (sealed_ask, agg_id, reg_data) = enclave.new_aggregator()?;

        let anytrust_ids: BTreeSet<EntityId> =
            pubkeys.iter().map(|pk| pk.get_entity_id()).collect();
        let anytrust_group_id = compute_group_id(&anytrust_ids);

        let state = AggregatorState {
            agg_id,
            anytrust_group_id,
            signing_key: sealed_ask,
            partial_agg: None,
        };

        Ok((state, reg_data))
    }

    /// Clears whatever aggregate exists and makes an empty one for the given round
    pub(crate) fn clear(
        &mut self,
        enclave: &DcNetEnclave,
        round: u32,
    ) -> Result<(), Box<dyn Error>> {
        // Make a new partial aggregate and put it in the local state
        let partial_agg = enclave.new_aggregate(round, &self.anytrust_group_id)?;
        self.partial_agg = Some(partial_agg);

        Ok(())
    }

    /// Adds the given input to the partial aggregate
    pub(crate) fn add_to_aggregate(
        &mut self,
        enclave: &DcNetEnclave,
        input_blob: &RoundSubmissionBlob,
    ) -> Result<(), Box<dyn Error>> {
        let partial_agg = self
            .partial_agg
            .as_mut()
            .expect("cannot add to aggregate without first calling new_aggregate");
        let _ = enclave.add_to_aggregate(partial_agg, input_blob, &self.signing_key)?;
        Ok(())
    }

    /// Packages the current aggregate into a message that can be sent to the next aggregator or an
    /// anytrust node
    pub(crate) fn finalize_aggregate(
        &self,
        enclave: &DcNetEnclave,
    ) -> Result<RoundSubmissionBlob, Box<dyn Error>> {
        let partial_agg = self
            .partial_agg
            .as_ref()
            .expect("cannot finalize aggregate without first calling new_aggregate");
        let blob = enclave.finalize_aggregate(partial_agg)?;

        Ok(blob)
    }
}
