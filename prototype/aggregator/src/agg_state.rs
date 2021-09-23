use crate::util::{AggregatorError, Result};

use std::collections::BTreeSet;

use common::enclave_wrapper::DcNetEnclave;
use interface::{
    compute_group_id, AggRegistrationBlob, EntityId, RoundSubmissionBlob, SealedSigPrivKey,
    ServerPubKeyPackage, SignedPartialAggregate,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct AggregatorState {
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
        pubkeys: Vec<ServerPubKeyPackage>,
    ) -> Result<(AggregatorState, AggRegistrationBlob)> {
        let (sealed_ask, agg_id, reg_data) = enclave.new_aggregator()?;

        let anytrust_ids: BTreeSet<EntityId> =
            pubkeys.iter().map(|pk| pk.kem.get_entity_id()).collect();
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
    pub(crate) fn clear(&mut self, enclave: &DcNetEnclave, round: u32) -> Result<()> {
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
    ) -> Result<()> {
        let partial_agg = self
            .partial_agg
            .as_mut()
            .ok_or(AggregatorError::Uninitialized)?;
        let _ = enclave.add_to_aggregate(partial_agg, input_blob, &self.signing_key)?;
        Ok(())
    }

    /// Packages the current aggregate into a message that can be sent to the next aggregator or an
    /// anytrust node
    pub(crate) fn finalize_aggregate(&self, enclave: &DcNetEnclave) -> Result<RoundSubmissionBlob> {
        let partial_agg = self
            .partial_agg
            .as_ref()
            .ok_or(AggregatorError::Uninitialized)?;
        let blob = enclave.finalize_aggregate(partial_agg)?;

        Ok(blob)
    }
}
