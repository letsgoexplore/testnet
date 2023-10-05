use crate::util::{AggregatorError, Result};

use std::collections::BTreeSet;

use interface::{
    compute_group_id, EntityId, RateLimitNonce, ServerPubKeyPackage, DC_NET_ROUNDS_PER_WINDOW,
};
use serde::{Deserialize, Serialize};

extern crate ed25519_dalek;
use ed25519_dalek::SecretKey;

use crate::agg::{add_to_aggregate, finalize_aggregate, new_aggregator};
use common::types::{AggRegistrationBlob, AggregatedMessage, SubmissionMessage};

#[derive(Serialize, Deserialize)]
pub struct AggregatorState {
    /// A unique identifier for this aggregator. Computed as the hash of the aggregator's pubkey.
    agg_id: EntityId,
    /// A unique for the set anytrust servers that this aggregator is registered with
    anytrust_group_id: EntityId,
    /// This aggregator's signing key.
    signing_key: SecretKey,
    /// A partial aggregate of received user messages
    partial_agg: Option<AggregatedMessage>,
    /// The level in the aggregation tree of this aggregator. 0 means this is a leaf aggregator.
    pub(crate) level: u32,
    /// The sequence number of aggregator.
    /// Note: [onlyevaluation] this is only for evaluation use.
    /// This is for aggregator knowing which file to save or read the msg.
    pub(crate) agg_number: Option<u32>,
    /// The observed rate limiting nonces from this window. This is Some iff this aggregator is a
    /// leaf aggregator
    observed_nonces: Option<BTreeSet<RateLimitNonce>>,
}

impl AggregatorState {
    /// Makes a new aggregate given the pubkeys of the servers. leaf_node = true iff this
    /// aggregator is a leaf-level aggregator
    pub(crate) fn new(
        pubkeys: Vec<ServerPubKeyPackage>,
        level: u32,
        agg_number: u32,
    ) -> Result<(AggregatorState, AggRegistrationBlob)> {
        let (sk, agg_id, reg_data) = new_aggregator()?;

        let anytrust_ids: BTreeSet<EntityId> =
            pubkeys.iter().map(|pk| EntityId::from(&pk.kem)).collect();
        let anytrust_group_id = compute_group_id(&anytrust_ids);

        // If this is a leaf aggregator, we collect nonces
        let observed_nonces = if level == 0 {
            Some(BTreeSet::new())
        } else {
            None
        };

        let state = AggregatorState {
            agg_id,
            anytrust_group_id,
            signing_key: sk,
            partial_agg: None,
            level,
            agg_number: Some(agg_number),
            observed_nonces,
        };

        Ok((state, reg_data))
    }

    /// Clears whatever aggregate exists and makes an empty one for the given round
    pub(crate) fn clear(&mut self, round: u32) -> Result<()> {
        // Make a new partial aggregate and put it in the local state
        let partial_agg: AggregatedMessage = Default::default();

        self.partial_agg = Some(partial_agg);

        // If the round marks a new window, clear the nonces too
        if round % DC_NET_ROUNDS_PER_WINDOW == 0 {
            self.observed_nonces.as_mut().map(|s| s.clear());
        }

        Ok(())
    }

    /// Adds the given input to the partial aggregate
    pub(crate) fn add_to_aggregate(&mut self, input_blob: &SubmissionMessage) -> Result<()> {
        let partial_agg = self
            .partial_agg
            .as_mut()
            .ok_or(AggregatorError::Uninitialized)?;
        let _ = add_to_aggregate(
            partial_agg,
            &mut self.observed_nonces,
            input_blob,
            &self.signing_key,
        )?;
        Ok(())
    }

    /// Packages the current aggregate into a message that can be sent to the next aggregator or an
    /// anytrust node
    // use std::mem;
    pub(crate) fn finalize_aggregate(&self) -> Result<AggregatedMessage> {
        let partial_agg = self
            .partial_agg
            .as_ref()
            .ok_or(AggregatorError::Uninitialized)?;
        let blob = finalize_aggregate(partial_agg)?;
        // println!("aggregated_msg.scheduling_msg.len:{}",blob.aggregated_msg.scheduling_msg.len());
        // println!("aggregated_msg.aggregated_msg.len:{}",blob.aggregated_msg.aggregated_msg.len());
        // println!("aggregated_msg.aggregated_msg[0].array.len:{}",blob.aggregated_msg.aggregated_msg[0].array.len());
        // println!("aggregated_msg.aggregated_msg[0].num_rows:{}",blob.aggregated_msg.aggregated_msg.num_rows());
        // println!("aggregated_msg.aggregated_msg[0].num_columns:{}",blob.aggregated_msg.aggregated_msg.num_columns());
        // println!("Btree length:{}",blob.user_ids.len());

        Ok(blob)
    }
}
