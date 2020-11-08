extern crate sgx_types;

use sgx_status_t;

extern crate interface;

use std::prelude::v1::*;
use self::interface::*;

use sgx_types::*;

use crypto;
use error::{DcNetError};

// the safe version
fn submit(request: SendRequest,
          tee_sk: PrvKey,  // TODO: this should be sealed/unsealed
          ) -> Result<SignedUserMessage, DcNetError>{
    // 1. compute the round secret
    match crypto::derive_round_secret(request.round, &request.server_keys) {
        Ok(round_secret) => {
            let encrypted_msg = crypto::xor(&round_secret.secret, &request.message);

            let mutable = SignedUserMessage {
                round: request.round,
                message: request.message,
                tee_sig: Default::default(),
                tee_pk: Default::default()
            };

            return match crypto::sign_dc_message(&mutable, tee_sk) {
                Ok(signed) => Ok(signed),
                Err(e) => return Err(DcNetError::Crypto(e)),
            };
        },
        Err(e) => {return Err(DcNetError::Crypto(e)); }
    }
}


// Client: Send plaintext in the round specified
// A round of dc-nets is run i.e., shared secrets are xored with the plaintext to compute client's
// output for the round. Output is serialized and signed before returning
// scheduling_data: Data that needs to be persisted between rounds
// raw_schedule_tokens: Schedule token data for the current round
#[no_mangle]
pub extern "C" fn client_submit(plaintext: u8, round: u32,
                                sealed_state: *mut u8, sealed_state_size: u32,
                                sealed_identity: *mut u8, sealed_identity_size: u32,
                                scheduling_data: *mut u8, scheduling_data_size: u32,
                                raw_schedule_tokens: *mut u8, raw_schedule_tokens_size: u32,
                                output: *mut u8, output_size: u32) -> sgx_status_t {
    unimplemented!()
    // let mut start = Instant::now();
    // let mut round_share = match dc_round(&[], sealed_state, sealed_state_size, true) {
    //     Ok(x) => x,
    //     Err(x) => return x
    // };
    // let identity = match unseal::<IdentityData>(sealed_identity, sealed_identity_size) {
    //     Ok(x) => x,
    //     Err(x) => return x
    // };
    // let dc_round_duration = Instant::now().duration_since(start);
    //
    // start = Instant::now();
    // // add the client's plaintext
    // let plaintext = vec![0; SHARE_SIZE];
    // let slice_build_duration = Instant::now().duration_since(start);
    //
    // start = Instant::now();
    // xor(&mut round_share, plaintext.as_slice());
    // let xor_duration = Instant::now().duration_since(start);
    // let dc_msg = DCMessage {
    //     share: round_share.as_slice(),
    //     client_id: PubKey {
    //         gx: identity.pub_key.gx,
    //         gy: identity.pub_key.gy
    //     },
    //     round: round
    // };
    // // println!("{:?}", dc_msg);
    // assert!(output_size == DC_MESSAGE_SIZE + SIGNATURE_SIZE);
    //
    // start = Instant::now();
    // serialize_and_sign::<DCMessage>(&dc_msg,
    //                                 output,
    //                                 &identity.prv_key,
    //                                 DC_MESSAGE_SIZE as usize,
    //                                 SIGNATURE_SIZE as usize);
    // let dc_ser_duration = Instant::now().duration_since(start);
    // println!("Sub-Times(client_submit): {} {} {} {} {}",
    //          SHARE_SIZE,
    //          to_ms(slice_build_duration),
    //          to_ms(xor_duration),
    //          to_ms(dc_round_duration),
    //          to_ms(dc_ser_duration));
    // SGX_SUCCESS
}