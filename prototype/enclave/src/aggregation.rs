use crate::crypto::*;
use crate::interface::*;
use crate::types::*;

use sgx_serialize::{Decoder, Encoder};
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
