extern crate interface;
extern crate sgx_types;

use self::interface::*;
use crate::messages_types::AggregatedMessage;
use crate::types::UnsealableAs;
use crate::types::Xor;
use core::convert::TryInto;
use crypto;
use crypto::{MultiSignable, SgxPrivateKey, SharedSecretsDb, SignMutable};
use interface::UserSubmissionReq;
use sgx_status_t::{SGX_ERROR_INVALID_PARAMETER, SGX_ERROR_UNEXPECTED};
use sgx_types::SgxResult;
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

    debug!("submitting {:?}", send_request);

    // 1) TODO: check ticket first
    warn!("we are not checking user_submission.ticket ATM");

    // 2) unseal signing key
    let sk = input.1.unseal()?;
    let pk = SgxProtectedKeyPub::try_from(&sk)?;
    debug!("using user signing (pub) key {}", pk);

    if send_request.user_id != EntityId::from(&pk) {
        error!("send_request.user_id != EntityId::from(&pk)");
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }

    // 3) derive the round key from shared secrets
    let shared_secrets = send_request.shared_secrets.unseal()?;
    if shared_secrets.anytrust_group_id() != send_request.anytrust_group_id {
        error!("shared_secrets.anytrust_group_id() != send_request.anytrust_group_id");
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }

    let round_key = crypto::derive_round_secret(send_request.round, &shared_secrets)
        .map_err(|_e| SGX_ERROR_INVALID_PARAMETER)?;

    // encrypt the message with round_key
    let encrypted_msg = round_key.xor(&send_request.msg);

    // FIXME: add missing default fields
    let mut mutable = AggregatedMessage {
        user_ids: BTreeSet::from_iter(vec![send_request.user_id].into_iter()),
        anytrust_group_id: send_request.anytrust_group_id,
        round: send_request.round,
        tee_sig: Default::default(),
        tee_pk: Default::default(),
        aggregated_msg: encrypted_msg,
    };

    // sign
    if mutable.sign_mut(&sk).is_err() {
        error!("can't sign");
        return Err(SGX_ERROR_UNEXPECTED);
    }

    debug!("encrypted msg: {:?}", mutable);

    // serialized
    Ok(RoundSubmissionBlob(serialize_to_vec(&mutable)?))
}

use bitvec;
use bitvec::prelude::{BitVec, Local};
use byteorder::ByteOrder;
use byteorder::LittleEndian;
use sha2::Digest;
use sha2::Sha256;

pub struct FootprintMap {
    fp_bit_len: usize,
    n_slot: usize,
    pub fp: BitVec<Local, u8>,
}

impl FootprintMap {
    fn new_footprint_map(fp_bit_len: usize, n_slot: usize) -> SgxResult<Self> {
        if (fp_bit_len * n_slot) % 32 != 0 {
            error!("(fp_bit_len * n_slot) % 32 != 0");
            return Err(SGX_ERROR_INVALID_PARAMETER);
        }

        Ok(Self {
            fp_bit_len,
            n_slot,
            fp: BitVec::with_capacity(fp_bit_len * n_slot),
        })
    }

    fn set(i: usize, footprint: u32) {
        unimplemented!()
    }

    fn get(i: usize, footprint: u32) {
        unimplemented!()
    }

    fn from_bytes(fp_bit_len: usize, n_slot: usize, bytes: Vec<u8>) -> SgxResult<Self> {
        unimplemented!()
    }

    fn to_bytes() -> Vec<u8> {
        unimplemented!()
    }
}

/// Return a deterministically derived footprint reservation for the given parameter
///
/// if epoch == 0:
///   Let cur_slot_idx = H("first-slot-idx", usk, anytrust_group_id)
///   Let cur_slot_val = H("first-slot-val", usk, anytrust_group_id)
/// else:
///   Let cur_slot_idx = H("sched-slot-idx", usk, anytrust_group_id, epoch-1)
///   Let cur_slot_val = H("sched-slot-val", usk, anytrust_group_id, epoch-1)
fn derive_reservation(usk: SgxPrivateKey, round: u32, anytrust_group_id: EntityId) {
    let mut hasher = Sha256::new();
    hasher.input(if round == 0 {
        "first-slot-idx"
    } else {
        "sched-slot-idx"
    });
    hasher.input(&usk);
    hasher.input(&anytrust_group_id.0);
    let cur_slot_idx = hasher.result().to_vec();

    LittleEndian::read_u16(&cur_slot_idx);

    unimplemented!()
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
    let reserve_req = &input.0;
    let sealed_sig_sk = &input.1;

    let prev_output = &reserve_req.prev_round_output;

    // check anytrust group id against server pubkeys
    let server_sig_pks: Vec<SgxSigningPubKey> =
        reserve_req.shared_secrets.db.keys().cloned().collect();
    if reserve_req.anytrust_group_id != compute_anytrust_group_id(&server_sig_pks) {
        error!("reserve_req.anytrust_group_id != EntityId::from(server_sig_pks)");
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }

    // verify server's signatures
    let verified_index = prev_output.verify(&server_sig_pks)?;
    info!("round output verified against {:?}", verified_index);

    // unseal user's sk
    let sk = sealed_sig_sk.unseal()?;

    // 1. Check the signature on the preivous round output against a signing key
    unimplemented!()
}
