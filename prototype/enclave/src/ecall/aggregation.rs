use crypto::*;
use interface::DcMessage;
use messages_types::SignedUserMessage;
use sgx_types::{sgx_status_t, SgxError, SgxResult};
use std::prelude::v1::*;
use types::*;

use crate::interface::*;
use crypto::{SgxSignature, Signable};
use std::vec::Vec;

use serde_cbor;
use sgx_status_t::{SGX_ERROR_INVALID_PARAMETER, SGX_ERROR_UNEXPECTED};
use std::slice;
use utils;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AggregatedMessage {
    pub round: u32,
    pub anytrust_group_id: EntityId,
    pub user_ids: Vec<EntityId>,
    pub aggregated_msg: DcMessage,
    pub tee_sig: SgxSignature,
    pub tee_pk: SgxSigningPubKey,
}

use types::Zero;

impl Zero for AggregatedMessage {
    fn zero() -> Self {
        AggregatedMessage {
            round: 0,
            anytrust_group_id: EntityId::default(),
            user_ids: Vec::new(),
            aggregated_msg: DcMessage::zero(),
            tee_sig: SgxSignature::default(),
            tee_pk: SgxSigningPubKey::default(),
        }
    }
}

use sgx_types::sgx_status_t::{SGX_INTERNAL_ERROR_ENCLAVE_CREATE_INTERRUPTED, SGX_SUCCESS};
use sha2::Digest;
use sha2::Sha256;
use types::DcNetError::AggregationError;

impl Signable for AggregatedMessage {
    fn digest(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        for id in self.user_ids.iter() {
            hasher.input(id);
        }
        hasher.input(&self.aggregated_msg);

        hasher.result().to_vec()
    }

    fn get_sig(&self) -> SgxSignature {
        self.tee_sig
    }

    fn get_pk(&self) -> SgxSigningPubKey {
        self.tee_pk
    }
}

impl SignMutable for AggregatedMessage {
    fn sign_mut(&mut self, sk: &SgxSigningKey) -> SgxError {
        let (sig, pk) = self.sign(sk)?;
        self.tee_pk = pk;
        self.tee_sig = sig;

        Ok(())
    }
}

pub fn aggregate_internal(
    incoming_msg: &SignedUserMessage,
    current_aggregation: &AggregatedMessage,
    tee_signing_sk: &SgxSigningKey,
) -> SgxResult<AggregatedMessage> {
    // verify signature
    if !incoming_msg.verify()? {
        println!("can't verify sig on incoming_msg");
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }

    // FIXME: check incoming_msg.pk against a list of accepted public keys

    println!("new input: {:?}", incoming_msg);

    if incoming_msg.round != current_aggregation.round {
        println!("incoming_msg.round != agg.round");
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }

    if current_aggregation.user_ids.contains(&incoming_msg.user_id) {
        println!("user already in");
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }

    // create a new aggregation
    let mut new_agg = current_aggregation.clone();

    // aggregate in the new message
    new_agg.user_ids.push(incoming_msg.user_id);
    new_agg
        .aggregated_msg
        .xor_mut(&DcMessage(incoming_msg.msg.0));

    // sign
    new_agg.sign_mut(&tee_signing_sk)?;

    Ok(new_agg)
}

#[no_mangle]
pub extern "C" fn ecall_aggregate(
    sign_user_msg_ptr: *const u8,
    sign_user_msg_len: usize,
    current_aggregation_ptr: *const u8,
    current_aggregation_len: usize,
    sealed_tee_prv_key_ptr: *mut u8,
    sealed_tee_prv_key_len: usize,
    output_aggregation_ptr: *mut u8,
    output_size: usize,
    output_bytes_written: *mut usize,
) -> sgx_status_t {
    let incoming_msg = unmarshal_or_abort!(SignedUserMessage, sign_user_msg_ptr, sign_user_msg_len);

    let current_agg = if current_aggregation_len == 0 {
        unmarshal_or_abort!(
            AggregatedMessage,
            current_aggregation_ptr,
            current_aggregation_len
        )
    } else {
        AggregatedMessage {
            round: incoming_msg.round,
            anytrust_group_id: incoming_msg.anytrust_group_id,
            user_ids: vec![],
            aggregated_msg: DcMessage::default(),
            tee_sig: Default::default(),
            tee_pk: Default::default(),
        }
    };

    let tee_signing_sk = unseal_or_abort!(
        SgxSigningKey,
        sealed_tee_prv_key_ptr,
        sealed_tee_prv_key_len
    );

    // Forward e-call to the internal safe version once deserialization and unmarshalling is done.
    let new_agg = unwrap_or_abort!(
        aggregate_internal(&incoming_msg, &current_agg, &tee_signing_sk),
        SGX_ERROR_INVALID_PARAMETER
    );

    // Write to user land
    match utils::serialize_to_ptr(
        &new_agg,
        output_aggregation_ptr,
        output_size,
        output_bytes_written,
    ) {
        Ok(_) => SGX_SUCCESS,
        Err(e) => {
            println!("can serialize {}", e);
            e
        }
    }
}
