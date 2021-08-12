use std::{
    cell::RefCell,
    collections::BTreeSet,
    error::Error,
    sync::{Arc, Mutex},
};

use common::enclave_wrapper::{DcNetEnclave, EnclaveResult};
use dc_proto::{anytrust_node_client::AnytrustNodeClient, SgxMsg};
pub mod dc_proto {
    tonic::include_proto!("dc_proto");
}
use interface::{
    compute_group_id, DcMessage, EntityId, KemPubKey, RoundSubmissionBlob, SealedFootprintTicket,
    SealedSigPrivKey, SignedPartialAggregate, UserSubmissionReq,
};

use rand::Rng;

pub(crate) struct AggregatorState {
    /// A reference to this machine's enclave
    enclave: Arc<Mutex<DcNetEnclave>>,
    /// A unique identifier for this aggregator. Computed as the hash of the aggregator's pubkey.
    agg_id: EntityId,
    /// A unique for the set anytrust servers that this aggregator is registered with
    anytrust_group_id: EntityId,
    /// This aggregator's signing key. Can only be accessed from within the enclave.
    signing_key: SealedSigPrivKey,
    /// A partial aggregate of received user messages
    partial_agg: Option<SignedPartialAggregate>,
}

pub(crate) fn register_aggregator(
    enclave: Arc<Mutex<DcNetEnclave>>,
    pubkeys: Vec<KemPubKey>,
) -> Result<(AggregatorState, SgxMsg), Box<dyn Error>> {
    let (sealed_ask, agg_id, reg_data) = enclave.lock().unwrap().new_aggregator()?;

    let anytrust_ids: BTreeSet<EntityId> = pubkeys.iter().map(|pk| pk.get_entity_id()).collect();
    let anytrust_group_id = compute_group_id(&anytrust_ids);

    let state = AggregatorState {
        agg_id,
        anytrust_group_id,
        enclave,
        signing_key: sealed_ask,
        partial_agg: None,
    };
    let msg = SgxMsg {
        payload: reg_data.0.tee_linkable_attestation,
    };

    Ok((state, msg))
}

impl AggregatorState {
    /// Clears whatever aggregate exists and makes an empty one for the given round
    pub(crate) fn new_aggregate(&mut self, round: u32) -> Result<(), Box<dyn Error>> {
        // Make a new partial aggregate and put it in the local state
        let partial_agg = self
            .enclave
            .lock()
            .unwrap()
            .new_aggregate(round, &self.anytrust_group_id)?;
        self.partial_agg = Some(partial_agg);

        Ok(())
    }

    /// Adds the given input to the partial aggregate
    pub(crate) fn add_to_aggregate(
        &mut self,
        input_blob: &RoundSubmissionBlob,
    ) -> Result<(), Box<dyn Error>> {
        let partial_agg = self
            .partial_agg
            .as_mut()
            .expect("cannot add to aggregate without first calling new_aggregate");
        let _ = self.enclave.lock().unwrap().add_to_aggregate(
            partial_agg,
            input_blob,
            &self.signing_key,
        )?;
        Ok(())
    }

    /// Packages the current aggregate into a message that can be sent to the next aggregator or an
    /// anytrust node
    pub(crate) fn finalize_aggregate(&self) -> Result<SgxMsg, Box<dyn Error>> {
        let partial_agg = self
            .partial_agg
            .as_ref()
            .expect("cannot finalize aggregate without first calling new_aggregate");
        let msg = self
            .enclave
            .lock()
            .unwrap()
            .finalize_aggregate(partial_agg)?;

        Ok(SgxMsg { payload: msg.0 })
    }
}
