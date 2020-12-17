use crate::crypto::*;
use crate::interface::*;
use crate::types::*;

use sgx_serialize::{Decoder, Encoder};
use sgx_types::SgxResult;
use std::prelude::v1::*;

pub fn aggregate(
    incoming_msg: &SignedUserMessage,
    agg: &AggregatedMessage,
) -> DcNetResult<AggregatedMessage> {
    let mut new_agg = agg.to_owned();

    // verify signature
    if !incoming_msg.verify().map_err(DcNetError::from)? {
        return Err(DcNetError::AggregationError("invalid sig"));
    }

    // aggregate in the new message
    new_agg.user_ids.push(incoming_msg.user_id);
    new_agg
        .aggregated_msg
        .xor_mut(&DCMessage::from(incoming_msg.message));

    // todo: add sig

    Ok(new_agg)
}
