use crate::crypto::*;
use crate::interface::*;
use crate::types::*;

use sgx_types::sgx_status_t;
use sgx_types::SgxResult;
use std::prelude::v1::*;

pub fn aggregate(
    incoming_msg: &SignedUserMessage,
    agg: &AggregatedMessage,
    tee_sk: &PrvKey,
) -> DcNetResult<AggregatedMessage> {
    // verify signature
    if !incoming_msg.verify().map_err(DcNetError::from)? {
        return Err(DcNetError::AggregationError("invalid sig"));
    }

    if incoming_msg.round != agg.round {
        return Err(DcNetError::AggregationError("invalid round"));
    }

    if agg.user_ids.contains(&incoming_msg.user_id) {
        return Err(DcNetError::AggregationError("user already in"));
    }

    let mut new_agg = agg.to_owned();

    // aggregate in the new message
    new_agg.user_ids.push(incoming_msg.user_id);
    new_agg
        .aggregated_msg
        .xor_mut(&DCMessage::from(incoming_msg.message));

    let (sig, pk) = new_agg.sign(tee_sk)?;

    new_agg.tee_sig = sig;
    new_agg.tee_pk = pk;

    Ok(new_agg)
}

use serde_cbor;
use sgx_status_t::{SGX_ERROR_INVALID_PARAMETER, SGX_ERROR_UNEXPECTED};
use std::slice;
use utils;

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
    let signed_user_msg =
        unmarshal_or_return!(SignedUserMessage, sign_user_msg_ptr, sign_user_msg_len);

    // if current_aggregation_len == 0, create an empty AggregatedMessage
    let current_agg = {
        if current_aggregation_len == 0 {
            AggregatedMessage {
                user_ids: vec![],
                aggregated_msg: DCMessage::zero(),
                round: signed_user_msg.round,
                tee_sig: Default::default(),
                tee_pk: Default::default(),
            }
        } else {
            unmarshal_or_return!(
                AggregatedMessage,
                current_aggregation_ptr,
                current_aggregation_len
            )
        }
    };

    let tee_prv_key = match utils::unseal_prv_key(sealed_tee_prv_key_ptr, sealed_tee_prv_key_len) {
        Ok(k) => k,
        Err(e) => return e,
    };

    println!("sign msg: {:?}", signed_user_msg);

    let new_agg = match aggregate(&signed_user_msg, &current_agg, &tee_prv_key) {
        Ok(agg) => agg,
        Err(e) => {
            println!("Err: {}", e);
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    println!("new agg: {:?}", new_agg);

    let serialized = unwrap_or_return!(serde_cbor::to_vec(&new_agg), SGX_ERROR_UNEXPECTED);
    if serialized.len() > output_size {
        println!("not enough output space. need {}", serialized.len());
        return SGX_ERROR_INVALID_PARAMETER;
    }

    unsafe {
        output_aggregation_ptr.copy_from(serialized.as_ptr(), serialized.len());
        output_bytes_written.write(serialized.len())
    }

    sgx_status_t::SGX_SUCCESS
}
