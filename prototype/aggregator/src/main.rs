extern crate common;
extern crate interface;

use std::error::Error;

use common::enclave_wrapper::{DcNetEnclave, EnclaveResult, KemPubKey};
use dc_proto::{anytrust_node_client::AnytrustNodeClient, SgxMsg};
pub mod dc_proto {
    tonic::include_proto!("dc_proto");
}
use interface::{
    DcMessage, EntityId, SealedFootprintTicket, SealedPartialAggregate, SealedPrvKey,
    SealedServerSecrets, UserSubmissionReq,
};

use rand::Rng;

struct AggregatorState<'a> {
    /// A reference to this machine's enclave
    enclave: &'a DcNetEnclave,
    /// A unique identifier for this aggregator. Computed as the hash of the aggregator's pubkey.
    agg_id: EntityId,
    /// This aggregator's signing key. Can only be accessed from within the enclave.
    signing_key: SealedPrvKey,
    /// The set anytrust servers that this client is registered with
    server_set: Vec<KemPubKey>,
    /// The secrets that this client shares with the anytrust servers. Can only be accessed from
    /// within the enclave.
    shared_secrets: SealedServerSecrets,
    /// A partial aggregate of received user messages
    partial_agg: Option<SealedPartialAggregate>,
}

fn register_aggregator(
    enclave: &DcNetEnclave,
    pubkeys: Vec<KemPubKey>,
) -> Result<(AggregatorState, SgxMsg), Box<dyn Error>> {
    let (sealed_shared_secrets, sealed_ask, agg_id, reg_data) =
        enclave.register_entity(&pubkeys)?;

    let state = AggregatorState {
        agg_id,
        enclave,
        signing_key: sealed_ask,
        shared_secrets: sealed_shared_secrets,
        server_set: pubkeys,
        partial_agg: None,
    };
    let msg = SgxMsg { payload: reg_data };

    Ok((state, msg))
}

impl<'a> AggregatorState<'a> {
    /// Clears whatever aggregate exists and makes an empty one for the given round
    fn new_aggregate(&mut self, round: u32) -> Result<(), Box<dyn Error>> {
        // Make a new partial aggregate and put it in the local state
        let partial_agg = self.enclave.new_aggregate(round, &self.server_set)?;
        self.partial_agg = Some(partial_agg);

        Ok(())
    }

    /// Adds the given input to the partial aggregate
    fn add_to_aggregate(&mut self, input_blob: &[u8]) -> Result<(), Box<dyn Error>> {
        let partial_agg = self
            .partial_agg
            .as_mut()
            .expect("cannot add to aggregate without first calling new_aggregate");
        let _ = self.enclave.add_to_aggregate(partial_agg, &input_blob)?;
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

        Ok(SgxMsg { payload: msg })
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
