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
use sgx_types::{SgxResult, SgxError};
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

use bitvec::prelude::*;
use byteorder::ByteOrder;
use byteorder::LittleEndian;
use sha2::Digest;
use sha2::Sha256;
use sha2::digest::DynDigest;

pub struct FootprintMap {
    fp_bit_len: usize,
    fps: Vec<SlotValue>,
}

impl FootprintMap {
    fn new_footprint_map(n_slots: usize, fp_bit_len: usize) -> SgxResult<Self> {
        Ok(Self {
            fp_bit_len,
            fps: vec![0u32; n_slots],
        })
    }

    fn set(&mut self, i: usize, footprint: SlotValue) -> SgxError{
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

    fn from_bytes(fp_bit_len: usize, bytes: &[u8]) -> SgxResult<Self> {
        let bits = BitSlice::<Msb0, u8>::from_slice(bytes);
        if bits.len() % fp_bit_len != 0 {
            error!("bits.len() % fp_bit_len != 0");
            return Err(SGX_ERROR_INVALID_PARAMETER);
        }

        let n_fps = bits.len() / fp_bit_len;
        let mut fps: Vec<u32> = Vec::with_capacity(n_fps);
        for i in 0..n_fps{
            fps.push(bits[i*fp_bit_len..(i+1)*fp_bit_len].load());
        }

        Ok(Self{
            fp_bit_len,
            fps
        })
    }

    fn to_bytes(&self) -> SgxResult<Vec<u8>> {
        let mut bits = bitvec![Msb0, u8; 0; self.fp_bit_len * self.fps.len()];
        for (i, fp) in self.fps.iter().enumerate() {
            bits[i * self.fp_bit_len.. (i+1)*self.fp_bit_len].store(fp.to_owned());
        }

        Ok(bits.into_vec())
    }
}

pub type SlotValue = u32;

/// Return a deterministically derived footprint reservation for the given parameter
///
/// if epoch == 0:
///   Let cur_slot_idx = H("first-slot-idx", usk, anytrust_group_id)
///   Let cur_slot_val = H("first-slot-val", usk, anytrust_group_id)
/// else:
///   Let cur_slot_idx = H("sched-slot-idx", usk, anytrust_group_id, epoch-1)
///   Let cur_slot_val = H("sched-slot-val", usk, anytrust_group_id, epoch-1)
fn derive_reservation(usk: SgxPrivateKey, round: u32, anytrust_group_id: EntityId) -> (u32, SlotValue) {
    let mut hasher_idx = Sha256::new();
    hasher_idx.input(if round == 0 {
        "first-slot-idx"
    } else {
        "sched-slot-idx"
    });
    hasher_idx.input(&usk);
    hasher_idx.input(&anytrust_group_id.0);
    if round > 0 {
        hasher_idx.input(round - 1);
    }

    let hasher_val = Sha256::new();
    hasher_val.input(if round == 0 {
        "first-slot-val"
    } else {
        "sched-slot-val"
    });
    hasher_val.input(&usk);
    hasher_val.input(&anytrust_group_id.0);
    if round > 0 {
        hasher_val.input(round - 1);
    }

    (LittleEndian::read_u32(&hasher_idx.result().to_vec()),
     LittleEndian::read_u32(&hasher_val.result().to_vec()))
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
