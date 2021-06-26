extern crate common;
extern crate interface;

use std::{collections::BTreeSet, error::Error};

use common::enclave_wrapper::{AggregateBlob, DcNetEnclave, EnclaveResult};
use dc_proto::{anytrust_node_client::AnytrustNodeClient, SgxMsg};
pub mod dc_proto {
    tonic::include_proto!("dc_proto");
}
use interface::{
    compute_group_id, DcMessage, EntityId, KemPubKey, MarshalledPartialAggregate,
    SealedFootprintTicket, SealedServerSecrets, SealedPrivateKey, UserSubmissionReq,
};

use rand::Rng;

struct AggregatorState<'a> {
    /// A reference to this machine's enclave
    enclave: &'a DcNetEnclave,
    /// A unique identifier for this aggregator. Computed as the hash of the aggregator's pubkey.
    agg_id: EntityId,
    /// A unique for the set anytrust servers that this aggregator is registered with
    anytrust_group_id: EntityId,
    /// This aggregator's signing key. Can only be accessed from within the enclave.
    signing_key: SealedPrivateKey,
    /// A partial aggregate of received user messages
    partial_agg: Option<MarshalledPartialAggregate>,
}

fn register_aggregator(
    enclave: &DcNetEnclave,
    pubkeys: Vec<KemPubKey>,
) -> Result<(AggregatorState, SgxMsg), Box<dyn Error>> {
    let (sealed_ask, agg_id, reg_data) = enclave.register_aggregator(&pubkeys)?;

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
        payload: reg_data.0,
    };

    Ok((state, msg))
}

impl<'a> AggregatorState<'a> {
    /// Clears whatever aggregate exists and makes an empty one for the given round
    fn new_aggregate(&mut self, round: u32) -> Result<(), Box<dyn Error>> {
        // Make a new partial aggregate and put it in the local state
        let partial_agg = self.enclave.new_aggregate(round, &self.anytrust_group_id)?;
        self.partial_agg = Some(partial_agg);

        Ok(())
    }

    /// Adds the given input to the partial aggregate
    fn add_to_aggregate(&mut self, input_blob: &AggregateBlob) -> Result<(), Box<dyn Error>> {
        let partial_agg = self
            .partial_agg
            .as_mut()
            .expect("cannot add to aggregate without first calling new_aggregate");
        let _ = self.enclave.add_to_aggregate(partial_agg, input_blob)?;
        Ok(())
    }

    /// Packages the current aggregate into a message that can be sent to the next aggregator or an
    /// anytrust node
    fn finalize_aggregate(&self) -> Result<SgxMsg, Box<dyn Error>> {
        let partial_agg = self
            .partial_agg
            .as_ref()
            .expect("cannot finalize aggregate without first calling new_aggregate");
        let msg = self.enclave.finalize_aggregate(partial_agg)?;

        Ok(SgxMsg { payload: msg.0 })
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut rng = rand::thread_rng();

    // TODO: maybe not hardcode the enclave path
    let enclave = DcNetEnclave::init("/sgxdcnet/lib/enclave.signed.so")?;
    enclave.run_enclave_tests();

    // TODO: Write a test routine for aggregator

    enclave.destroy();
    Ok(())
}
