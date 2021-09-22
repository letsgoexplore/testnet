extern crate interface;
extern crate sgx_types;

use self::interface::*;
use crate::crypto::Xor;
use crate::messages_types::AggregatedMessage;
use crate::unseal::{MarshallAs, UnsealableAs};
use byteorder::ByteOrder;
use byteorder::LittleEndian;
use core::convert::TryInto;
use crypto;
use crypto::{MultiSignable, SgxPrivateKey, SharedSecretsDb, SignMutable};
use interface::UserSubmissionReq;
use sgx_status_t::{SGX_ERROR_INVALID_PARAMETER, SGX_ERROR_UNEXPECTED};
use sgx_tcrypto::SgxEccHandle;
use sgx_types::{SgxError, SgxResult};
use sha2::Digest;
use sha2::Sha256;
use std::collections::BTreeSet;
use std::convert::TryFrom;
use std::debug;
use std::iter::FromIterator;
use std::prelude::v1::*;

pub fn user_submit_internal(
    input: &(UserSubmissionReq, SealedSigPrivKey),
) -> SgxResult<RoundSubmissionBlob> {
    let send_request = &input.0;
    // unseal user's sk
    let signing_sk = (&input.1).unseal()?;
    // Determine whether the message is just cover traffic
    let msg_is_empty = send_request.msg == Default::default();

    // check user key matches user_id
    if EntityId::from(&SgxSigningPubKey::try_from(&signing_sk)?) != send_request.user_id {
        error!("user id mismatch");
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }

    debug!("✅ user id matches user signing key");

    // check anytrust group id matches server pubkeys
    // TODO: these pub keys are untrustworthy
    let server_sig_pks: Vec<SgxSigningPubKey> =
        send_request.shared_secrets.db.keys().cloned().collect();
    if send_request.anytrust_group_id != compute_anytrust_group_id(&server_sig_pks) {
        error!("reserve_req.anytrust_group_id != EntityId::from(server_sig_pks)");
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }

    debug!("✅ shared secrets matches anytrust groupid");

    // make a new footprint
    let (cur_slot, cur_fp, next_slot, next_fp) = derive_reservation(
        &signing_sk,
        &send_request.anytrust_group_id,
        send_request.round,
    );

    // Check the scheduling result from the previous round (the ticket) unless
    // a) this is the first round (round = 0) or
    // b) req.msg is all zeroes (i.e., the user is not sending anything but just scheduling).
    if send_request.round == 0 {
        debug!(
            "✅ user is permitted to send msg at slot {} because it's round 0",
            cur_slot
        );
    } else if msg_is_empty {
        debug!(
            "✅ user is permitted to send msg at slot {} because msg is all-zero",
            cur_slot
        );
    } else {
        // validate the request
        if send_request.round != send_request.prev_round_output.round + 1 {
            error!("wrong round #");
            return Err(SGX_ERROR_INVALID_PARAMETER);
        }

        // verify server's signatures
        let verified_index = send_request
            .prev_round_output
            .verify_multisig(&server_sig_pks)?;
        info!("round output verified against {:?}", verified_index);

        if send_request.prev_round_output.dc_msg.scheduling_msg[cur_slot] != cur_fp {
            error!(
                "❌ can't send in slot {} at round {}. fp mismatch.",
                cur_slot, send_request.round
            );
            return Err(SGX_ERROR_INVALID_PARAMETER);
        }
        debug!(
            "✅ user is permitted to send msg at slot {} for round {}",
            cur_slot, send_request.round
        );
    }

    debug!(
        "✅ user will schedule for slot {} for next round",
        next_slot
    );

    // Put use message in the designated slot of the round message
    let mut round_msg = DcRoundMessage::default();
    round_msg.scheduling_msg[next_slot] = next_fp;
    round_msg.aggregated_msg[cur_slot] = send_request.msg.clone();

    // Derive the round key from shared secrets
    let shared_secrets = send_request.shared_secrets.unseal()?;
    if shared_secrets.anytrust_group_id() != send_request.anytrust_group_id {
        error!("shared_secrets.anytrust_group_id() != send_request.anytrust_group_id");
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }

    debug!("round msg: {:?}", round_msg);

    let round_key = match crypto::derive_round_secret(send_request.round, &shared_secrets) {
        Ok(k) => k,
        Err(e) => {
            error!("can't derive round secret {}", e);
            return Err(SGX_ERROR_INVALID_PARAMETER);
        }
    };

    // encrypt the message with round_key
    let encrypted_msg = round_key.xor(&round_msg);

    let mut mutable = AggregatedMessage {
        user_ids: BTreeSet::from_iter(vec![send_request.user_id].into_iter()),
        anytrust_group_id: send_request.anytrust_group_id,
        round: send_request.round,
        tee_sig: Default::default(),
        tee_pk: Default::default(),
        aggregated_msg: encrypted_msg,
    };

    // sign
    if mutable.sign_mut(&signing_sk).is_err() {
        error!("can't sign");
        return Err(SGX_ERROR_UNEXPECTED);
    }

    debug!("encrypted msg: {:?}", mutable);

    // serialize
    Ok(mutable.marshal()?)
}

/// Return deterministically derived footprint reservation for the given parameter
///
/// ```
/// if epoch == 0:
///         Let prev_slot_idx = H("first-slot-idx", usk, anytrust_group_id)
///         Let prev_slot_val = H("first-slot-val", usk, anytrust_group_id)
/// else:
/// 		Let prev_slot_idx = H("sched-slot-idx", usk, anytrust_group_id, round-1)
/// 		Let prev_slot_val = H("sched-slot-val", usk, anytrust_group_id, round-1)
/// Let next_slot_idx = H("sched-slot-idx", usk, anytrust_group_id, round)
/// Let next_slot_val = H("sched-slot-val", usk, anytrust_group_id, round)
///
/// return (prev_slot_idx, prev_slot_val, next_slot_idx, next_slot_val)
/// ```
fn derive_reservation(
    usk: &SgxPrivateKey,
    anytrust_group_id: &EntityId,
    round: u32,
) -> (usize, interface::Footprint, usize, interface::Footprint) {
    const FIRST_SLOT_IDX: &[u8; 14] = b"first-slot-idx";
    const FIRST_SLOT_VAL: &[u8; 14] = b"first-slot-val";
    const SCHED_SLOT_IDX: &[u8; 14] = b"sched-slot-idx";
    const SCHED_SLOT_VAL: &[u8; 14] = b"sched-slot-val";

    // hash three things to u32
    let h3_to_u32 = |label: &[u8; 14], usk: &SgxPrivateKey, anytrust_group_id: &EntityId| {
        let mut h = Sha256::new();
        h.input(label);
        h.input(usk);
        h.input(anytrust_group_id);

        let hash = h.result().to_vec();

        (LittleEndian::read_u32(&hash))
    };

    // hash three things to u32
    let h4_to_u32 =
        |label: &[u8; 14], usk: &SgxPrivateKey, anytrust_group_id: &EntityId, round: u32| {
            let mut h = Sha256::new();
            h.input(label);
            h.input(usk);
            h.input(anytrust_group_id);
            h.input(round.to_le_bytes());

            let hash = h.result().to_vec();

            LittleEndian::read_u32(&hash)
        };

    let (prev_slot_idx, prev_slot_val) = {
        if round == 0 {
            (
                h3_to_u32(FIRST_SLOT_IDX, usk, anytrust_group_id) as usize,
                h3_to_u32(FIRST_SLOT_VAL, usk, anytrust_group_id),
            )
        } else {
            (
                h4_to_u32(SCHED_SLOT_IDX, usk, anytrust_group_id, round - 1) as usize,
                h4_to_u32(SCHED_SLOT_VAL, usk, anytrust_group_id, round - 1),
            )
        }
    };

    let next_slot_idx = h4_to_u32(SCHED_SLOT_IDX, usk, anytrust_group_id, round) as usize;
    let next_slot_val = h4_to_u32(SCHED_SLOT_VAL, usk, anytrust_group_id, round);

    (
        prev_slot_idx % DC_NET_N_SLOTS,
        prev_slot_val,
        next_slot_idx % DC_NET_N_SLOTS,
        next_slot_val,
    )
}

/// 1. Check the signature on the preivous round output against a signing key (might have to change API a bit for that)
/// 2. Check that the current round is prev_round+1
/// 3. Make a new footprint reservation for this round
pub fn user_reserve_slot(
    input: &(UserReservationReq, SealedSigPrivKey),
) -> SgxResult<RoundSubmissionBlob> {
    let req = input.0.clone();
    let signing_sk = input.1.clone();
    user_submit_internal(&(
        UserSubmissionReq {
            user_id: req.user_id,
            anytrust_group_id: req.anytrust_group_id,
            round: req.round,
            msg: Default::default(),
            prev_round_output: Default::default(),
            shared_secrets: req.shared_secrets,
        },
        signing_sk,
    ))
}
