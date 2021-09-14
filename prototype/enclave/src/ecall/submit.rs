extern crate interface;
extern crate sgx_types;

use self::interface::*;
use crate::crypto::Xor;
use crate::messages_types::AggregatedMessage;
use crate::types::UnsealableAs;
use core::convert::TryInto;
use crypto;
use crypto::{MultiSignable, SgxPrivateKey, SharedSecretsDb, SignMutable};
use interface::UserSubmissionReq;
use sgx_status_t::{SGX_ERROR_INVALID_PARAMETER, SGX_ERROR_UNEXPECTED};
use sgx_types::{SgxError, SgxResult};
use std::collections::BTreeSet;
use std::convert::TryFrom;
use std::debug;
use std::iter::FromIterator;
use std::prelude::v1::*;
use utils::serialize_to_vec;

pub fn user_submit_internal(
    input: &(UserSubmissionReq, SealedSigPrivKey),
) -> SgxResult<RoundSubmissionBlob> {
    let send_request = &input.0;

    // unseal user's sk
    let signing_sk = (&input.1).unseal()?;

    // validate the request
    // 1. Check the signature on the preivous round output against a signing key (might have to change API a bit for that)
    // 2. Check that the current round is prev_round+1
    validate_submission_req(&signing_sk, send_request)?;

    // make a new footprint
    let (cur_slot, cur_fp, next_slot, next_fp) = derive_reservation(
        &signing_sk,
        &send_request.anytrust_group_id,
        send_request.round,
    );

    // for all but the first round, check the ticket from the previous round
    if send_request.round > 0 {
        if send_request.prev_round_output.dc_msg.scheduling_msg[cur_slot] != cur_fp {
            error!("fp mismatch. can't send in this round");
            return Err(SGX_ERROR_INVALID_PARAMETER);
        }
    }

    // Put use message in the designated slot of the round message
    let mut round_msg = DcRoundMessage::default();
    round_msg.scheduling_msg[next_slot] = next_fp;
    round_msg.aggregated_msg[cur_slot] = send_request.msg.clone();

    // 3) derive the round key from shared secrets
    let shared_secrets = send_request.shared_secrets.unseal()?;
    if shared_secrets.anytrust_group_id() != send_request.anytrust_group_id {
        error!("shared_secrets.anytrust_group_id() != send_request.anytrust_group_id");
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }

    let round_key = crypto::derive_round_secret(send_request.round, &shared_secrets)
        .map_err(|_e| SGX_ERROR_INVALID_PARAMETER)?;

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

    // serialized
    Ok(mutable.marshal()?)
}

use bitvec::prelude::*;
use byteorder::ByteOrder;
use byteorder::LittleEndian;
use sgx_tcrypto::SgxEccHandle;
use sha2::Digest;
use sha2::Sha256;
use types::MarshallAs;

pub struct FootprintMap {
    fps: Vec<SlotValue>,
}

impl FootprintMap {
    fn new_footprint_map() -> SgxResult<Self> {
        if FOOTPRINT_BIT_SIZE > 32 {
            error!("FOOTPRINT_BIT_SIZE {} > 32", FOOTPRINT_BIT_SIZE);
            return Err(SGX_ERROR_INVALID_PARAMETER);
        }
        Ok(Self {
            fps: vec![0u32; DC_NET_N_SLOTS],
        })
    }

    fn set(&mut self, i: usize, footprint: SlotValue) -> SgxError {
        if i > self.fps.len() {
            error!("i > self.fps.len()");
            return Err(SGX_ERROR_INVALID_PARAMETER);
        }
        self.fps[i] = footprint;

        Ok(())
    }

    fn get(&self, i: usize) -> SgxResult<SlotValue> {
        if i > self.fps.len() {
            error!("i > self.fps.len()");
            return Err(SGX_ERROR_INVALID_PARAMETER);
        }

        Ok(self.fps[i])
    }

    /// return map[i] == expected
    fn test(&self, i: usize, expected: SlotValue) -> SgxResult<bool> {
        Ok(self.get(i)? == expected)
    }

    fn from_bytes(bytes: &[u8]) -> SgxResult<Self> {
        let bits = BitSlice::<Msb0, u8>::from_slice(bytes);
        if bits.len() % FOOTPRINT_BIT_SIZE != 0 {
            error!("bits.len() % FOOTPRINT_BIT_SIZE != 0");
            return Err(SGX_ERROR_INVALID_PARAMETER);
        }

        let n_fps = bits.len() / FOOTPRINT_BIT_SIZE;
        let mut fps: Vec<u32> = Vec::with_capacity(n_fps);
        for i in 0..n_fps {
            fps.push(bits[i * FOOTPRINT_BIT_SIZE..(i + 1) * FOOTPRINT_BIT_SIZE].load());
        }

        Ok(Self { fps })
    }

    fn to_bytes(&self) -> SgxResult<Vec<u8>> {
        let mut bits = bitvec![Msb0, u8; 0; FOOTPRINT_BIT_SIZE * self.fps.len()];
        for (i, fp) in self.fps.iter().enumerate() {
            bits[i * FOOTPRINT_BIT_SIZE..(i + 1) * FOOTPRINT_BIT_SIZE].store(fp.to_owned());
        }

        Ok(bits.into_vec())
    }
}

pub type SlotValue = u32;

/// Return a deterministically derived footprint reservation for the given parameter
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
fn derive_reservation(
    usk: &SgxPrivateKey,
    anytrust_group_id: &EntityId,
    next_round: u32,
) -> (usize, SlotValue, usize, SlotValue) {
    const FIRST_SLOT_IDX: &[u8; 14] = b"first-slot-idx";
    const FIRST_SLOT_VAL: &[u8; 14] = b"first-slot-val";
    const SCHED_SLOT_IDX: &[u8; 14] = b"sched-slot-idx";
    const SCHED_SLOT_VAL: &[u8; 14] = b"sched-slot-val";

    let hash_three_things =
        |label: &[u8; 14], usk: &SgxPrivateKey, anytrust_group_id: &EntityId| {
            let mut h = Sha256::new();
            h.input(label);
            h.input(usk);
            h.input(anytrust_group_id);

            let hash = h.result().to_vec();

            (LittleEndian::read_u32(&hash))
        };

    let hash_four_things =
        |label: &[u8; 14], usk: &SgxPrivateKey, anytrust_group_id: &EntityId, round: u32| {
            let mut h = Sha256::new();
            h.input(label);
            h.input(usk);
            h.input(anytrust_group_id);
            h.input(round.to_le_bytes());

            let hash = h.result().to_vec();

            LittleEndian::read_u32(&hash)
        };

    let mut prev_slot_idx: usize = 0;
    let mut prev_slot_val: SlotValue = 0;
    if next_round == 0 {
        prev_slot_idx =
            hash_three_things(FIRST_SLOT_IDX, usk, anytrust_group_id) as usize % DC_NET_N_SLOTS;
        prev_slot_val = hash_three_things(FIRST_SLOT_VAL, usk, anytrust_group_id);
    } else {
        prev_slot_idx = hash_four_things(SCHED_SLOT_IDX, usk, anytrust_group_id, next_round - 1)
            as usize
            % DC_NET_N_SLOTS;
        prev_slot_val = hash_four_things(SCHED_SLOT_VAL, usk, anytrust_group_id, next_round - 1);
    }

    let next_slot_idx = hash_four_things(SCHED_SLOT_IDX, usk, anytrust_group_id, next_round)
        as usize
        % DC_NET_N_SLOTS;
    let next_slot_val = hash_four_things(SCHED_SLOT_VAL, usk, anytrust_group_id, next_round);

    (prev_slot_idx, prev_slot_val, next_slot_idx, next_slot_val)
}

fn validate_reservation_req(signing_sk: &SgxPrivateKey, req: &UserReservationReq) -> SgxError {
    let req = req.clone();
    // a reservation request is a degenerated submission req so we use the same validate function
    validate_submission_req(
        signing_sk,
        &UserSubmissionReq {
            user_id: req.user_id,
            anytrust_group_id: req.anytrust_group_id,
            round: req.round,
            msg: Default::default(),
            prev_round_output: req.prev_round_output,
            shared_secrets: req.shared_secrets,
        },
    )
}

fn validate_submission_req(signing_sk: &SgxPrivateKey, req: &UserSubmissionReq) -> SgxError {
    // 0.
    if req.round != req.prev_round_output.round + 1 {
        error!("wrong round #");
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }

    // 1. Check user key matches with user_id
    if EntityId::from(&SgxSigningPubKey::try_from(signing_sk)?) != req.user_id {
        error!("user id mismatch");
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }

    // 2. check anytrust group id against server pubkeys
    // TODO: these pub keys are untrustworthy
    let server_sig_pks: Vec<SgxSigningPubKey> = req.shared_secrets.db.keys().cloned().collect();
    if req.anytrust_group_id != compute_anytrust_group_id(&server_sig_pks) {
        error!("reserve_req.anytrust_group_id != EntityId::from(server_sig_pks)");
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }

    // 3. verify server's signatures
    let verified_index = req.prev_round_output.verify_multisig(&server_sig_pks)?;
    info!("round output verified against {:?}", verified_index);

    // 4. check ticket
    /*
    if epoch == 0:
        Let cur_slot_idx = H("first-slot-idx", usk, anytrust_group_id)
        Let cur_slot_val = H("first-slot-val", usk, anytrust_group_id)
    else:
        Let cur_slot_idx = H("sched-slot-idx", usk, anytrust_group_id, epoch-1)
        Let cur_slot_val = H("sched-slot-val", usk, anytrust_group_id, epoch-1)
        Check signed_prev_round is signed by an anytrust server
        Let R = signed_prev_round[..RESERVATION_BLOCKLEN]
        // Treat R as a sequence of FOOTPRINT_SIZE chunks
        Check R[cur_slot_idx] = cur_slot_val
     */

    Ok(())
}

fn submit(
    usk: SgxPrivateKey,
    msg: &DcMessage,
    anytrust_group_id: EntityId,
    prev_round: &RoundOutput,
) {
    unimplemented!()
}

///
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
            prev_round_output: req.prev_round_output,
            shared_secrets: req.shared_secrets,
        },
        signing_sk,
    ))
}
