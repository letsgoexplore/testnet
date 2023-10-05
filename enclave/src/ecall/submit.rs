extern crate interface;
extern crate sgx_types;

use self::interface::*;
use crate::unseal::UnsealableInto;
use byteorder::ByteOrder;
use byteorder::LittleEndian;
use crypto;
use crypto::{sign_submission, SgxPrivateKey};
use log::debug;
use sgx_types::sgx_status_t::{
    SGX_ERROR_INVALID_PARAMETER, SGX_ERROR_SERVICE_UNAVAILABLE, SGX_ERROR_UNEXPECTED,
};
use sgx_types::SgxResult;
use sha2::Digest;
use sha2::Sha256;
use std::convert::TryFrom;
use std::env;
use std::prelude::v1::*;
use unseal::SealInto;

use ed25519_dalek::PublicKey;

fn check_reservation(
    server_sig_pks: &[PublicKey],
    round: u32,
    prev_round_output: &RoundOutput,
    cur_slot: usize,
    cur_fp: u32,
) -> SgxResult<()> {
    // validate the request
    if round != prev_round_output.round + 1 {
        error!("wrong round #");
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }

    // verify server's signatures on previous output
    let verified_index = prev_round_output
        .verify_multisig(server_sig_pks)
        .expect("verify server's signature failed");

    if verified_index.is_empty() {
        error!("❌ sigs in prev_round_output can't be verified");
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }

    info!("✅ prev_round_output verified against {:?}", verified_index);

    // now that sigs on prev_round_output are checked we check the footprints therein
    if prev_round_output.dc_msg.scheduling_msg[cur_slot] != cur_fp {
        error!(
            "❌ Collision in slot {} for round {}. sent fp {} != received fp {}. ",
            cur_slot,
            prev_round_output.round,
            prev_round_output.dc_msg.scheduling_msg[cur_slot],
            cur_fp,
        );
        return Err(SGX_ERROR_SERVICE_UNAVAILABLE);
    }

    Ok(())
}

/// Selects the slot that will be used for this message. Since the scheduling vector is potentially
/// a lot larger than the dc net message vector (to avoid collision), we expect many slots in the
/// scheduling vector to be empty. To save bandwidth we compact the DC net message by skipping
/// slots that are not scheduled. In short the zeros are discounted from the vector and all the
/// reserved slots are moved up.
fn derive_msg_slot(cur_slot: usize, prev_round_output: &RoundOutput) -> SgxResult<usize> {
    let num_zeros = prev_round_output.dc_msg.scheduling_msg[..cur_slot]
        .into_iter()
        .filter(|b| **b == 0)
        .count();
    let msg_slot = cur_slot - num_zeros;
    let dc_net_n_slots = if PARAMETER_FLAG {
        env::var("DC_NET_N_SLOTS")
            .unwrap_or_else(|_| "100".to_string())
            .parse::<usize>()
            .expect("Invalid DC_NET_N_SLOTS value")
    } else {
        DC_NET_N_SLOTS
    };

    // Do a bounds check
    if msg_slot > dc_net_n_slots {
        error!(
            "❌ can't send. scheduling failure. you need to wait for the next round.
            \tcur_slot: {}, num_zeros: {}, msg_slot: {}, DC_NET_N_SLOTS:{}",
            cur_slot, num_zeros, msg_slot, dc_net_n_slots
        );
        Err(SGX_ERROR_SERVICE_UNAVAILABLE)
    } else {
        Ok(msg_slot)
    }
}

/// Return deterministically derived footprint reservation for the given parameter
///
/// ```
/// if epoch == 0:
///         Let prev_slot_idx = H("first-slot-idx", usk, anytrust_group_id)
///         Let prev_slot_val = H("first-slot-val", usk, anytrust_group_id)
/// else:
///         Let prev_slot_idx = H("sched-slot-idx", usk, anytrust_group_id, round-1)
///         Let prev_slot_val = H("sched-slot-val", usk, anytrust_group_id, round-1)
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

        LittleEndian::read_u32(&hash)
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

    let (prev_slot_idx, prev_slot_val) = round
        .checked_sub(1)
        .map(|r| {
            (
                h4_to_u32(SCHED_SLOT_IDX, usk, anytrust_group_id, r) as usize,
                h4_to_u32(SCHED_SLOT_VAL, usk, anytrust_group_id, r),
            )
        })
        .unwrap_or((
            h3_to_u32(FIRST_SLOT_IDX, usk, anytrust_group_id) as usize,
            h3_to_u32(FIRST_SLOT_VAL, usk, anytrust_group_id),
        ));

    let next_slot_idx = h4_to_u32(SCHED_SLOT_IDX, usk, anytrust_group_id, round) as usize;
    let next_slot_val = h4_to_u32(SCHED_SLOT_VAL, usk, anytrust_group_id, round);
    let dc_net_n_slots = if PARAMETER_FLAG {
        env::var("DC_NET_N_SLOTS")
            .unwrap_or_else(|_| "100".to_string())
            .parse::<usize>()
            .expect("Invalid DC_NET_N_SLOTS value")
    } else {
        DC_NET_N_SLOTS
    };
    let footprint_n_slots = if PARAMETER_FLAG {
        env::var("FOOTPRINT_N_SLOTS")
            .unwrap_or_else(|_| "100".to_string())
            .parse::<usize>()
            .expect("Invalid FOOTPRINT_N_SLOTS value")
    } else {
        FOOTPRINT_N_SLOTS
    };

    (
        prev_slot_idx % footprint_n_slots,
        prev_slot_val % (dc_net_n_slots as u32),
        next_slot_idx % footprint_n_slots,
        next_slot_val % (dc_net_n_slots as u32),
    )
}

use crypto::ed25519pk_from_secret;

/// process user submission request
/// returns a submission and the ratcheted shared secrets
pub fn user_submit_internal(
    (send_request, signing_sk): &(UserSubmissionReq, SealedSigPrivKey),
) -> SgxResult<(UserSubmissionBlob, SealedSharedSecretsDbClient)> {
    let UserSubmissionReq {
        user_id,
        anytrust_group_id,
        round,
        msg,
        shared_secrets,
        server_pks,
    } = send_request;
    let round = *round;

    // unseal user's sk
    let signing_sk = signing_sk.unseal_into()?;
    //check user signing key matches user_id
    if EntityId::from(&ed25519pk_from_secret(&signing_sk)?) != *user_id {
        error!("user id mismatch");
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }

    let uid = &user_id;
    debug!("✅ user id {} matches user signing key", uid);

    let mut server_sig_pks: Vec<PublicKey> = Vec::new();
    let mut server_kem_pks: Vec<SgxProtectedKeyPub> = Vec::new();
    // check anytrust group id matches server pubkeys
    for pk_pkg in server_pks.iter() {
        server_sig_pks.push(pk_pkg.sig);
        server_kem_pks.push(SgxProtectedKeyPub(pk_pkg.kem.to_bytes()));
    }

    // check anytrust_group_id against the kem keys
    if *anytrust_group_id != compute_anytrust_group_id(server_kem_pks.as_slice()) {
        error!("reserver_req.anytrust_group_id != EntityId::from(server_sig_pks");
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }

    debug!("✅ shared secrets matches anytrust group id");

    // Derive the pseudorandom rate-limit nonce
    let rate_limit_nonce = crypto::derive_round_nonce(anytrust_group_id, round, &signing_sk, msg)?;

    // Get the last footprint and make a new one. If this message is cover traffic, this info won't
    // be used at all
    let (cur_slot, cur_fp, next_slot, next_fp) =
        derive_reservation(&signing_sk, anytrust_group_id, round);

    // If this user is talking and it's not the first round, check the reservation. Otherwise don't
    if let UserMsg::TalkAndReserve {
        ref prev_round_output,
        ..
    } = msg
    {
        let msg_slot = derive_msg_slot(cur_slot, prev_round_output)?;
        if round > 0 {
            check_reservation(&server_sig_pks, round, prev_round_output, cur_slot, cur_fp)?;
            debug!(
                "✅ user {} is permitted to send msg at slot {} for round {}",
                uid, msg_slot, round
            );
        } else {
            info!(
                "✅ user is permitted to send at slot {} because it's round 0",
                msg_slot
            );
        }
    } else {
        debug!("✅ user {} is not talking this round", uid);
    }

    if !msg.is_cover() {
        info!(
            "✅ user is scheduled for slot {} for next round with fp {}",
            next_slot, next_fp,
        );
    }

    // Write to the round message. It's all zeros by default
    let mut round_msg = DcRoundMessage::default();
    match msg {
        // If the user is talking and reserving, write to message and reservation slots
        UserMsg::TalkAndReserve {
            msg,
            ref prev_round_output,
            ..
        } => {
            let msg_slot = derive_msg_slot(cur_slot, prev_round_output)?;
            debug!("✅ slot {} will include msg {:?}", msg_slot, msg,);

            round_msg.scheduling_msg[next_slot] = next_fp;
            // Copy the message into the 2d array
            for (i, b) in msg.0.iter().enumerate() {
                round_msg.aggregated_msg.set(msg_slot, i, *b).unwrap();
            }
        }
        // If the user is just reserving, write to reservation slots
        UserMsg::Reserve { .. } => {
            round_msg.scheduling_msg[next_slot] = next_fp;
        }
        // If this is cover traffic, the round message is all zeros
        UserMsg::Cover => (),
    };

    // Now we encrypt the round message

    // Derive the round key from shared secrets
    let shared_secrets = shared_secrets.unseal_into()?;
    if shared_secrets.round != round {
        error!(
            "shared_secrets.round {} != send_request.round {}",
            shared_secrets.round, round
        );
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }
    if shared_secrets.anytrust_group_id() != *anytrust_group_id {
        error!("shared_secrets.anytrust_group_id() != send_request.anytrust_group_id");
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }

    let round_key = match crypto::derive_round_secret_client(round, &shared_secrets, None) {
        Ok(k) => k,
        Err(e) => {
            error!("can't derive round secret {}", e);
            return Err(SGX_ERROR_INVALID_PARAMETER);
        }
    };

    // Encrypt the message with round_key
    let encrypted_msg = round_key.xor(&round_msg);

    // Construct the output blob
    let mut agg_msg = UserSubmissionMessage {
        user_id: *user_id,
        anytrust_group_id: *anytrust_group_id,
        round,
        rate_limit_nonce: Some(rate_limit_nonce),
        tee_sig: Default::default(),
        tee_pk: Default::default(),
        aggregated_msg: encrypted_msg,
    };

    // Sign
    let (sig, pk) = sign_submission(&agg_msg, &signing_sk).map_err(|e| {
        log::error!("crypto error {}", e);
        SGX_ERROR_UNEXPECTED
    })?;
    agg_msg.tee_pk = pk;
    agg_msg.tee_sig = sig;

    // If everything is fine, we are ready to ratchet
    Ok((agg_msg, shared_secrets.ratchet().seal_into()?))
}
