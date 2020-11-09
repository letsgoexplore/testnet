extern crate sgx_types;

use sgx_status_t;

extern crate interface;

use self::interface::*;
use std::convert::TryInto;
use std::prelude::v1::*;

use sgx_types::*;

use crypto;
use error::DcNetError;

// the safe version
fn submit(
    request: &SendRequest,
    tee_sk: &PrvKey, // TODO: this should be sealed/unsealed
) -> Result<SignedUserMessage, DcNetError> {
    let round_key = crypto::derive_round_secret(request.round, &request.server_keys)?;

    println!("round key");

    let encrypted_msg = round_key.encrypt(&request.message);

    println!("encrypt");

    let mutable = SignedUserMessage {
        round: request.round,
        message: encrypted_msg,
        tee_sig: Default::default(),
        tee_pk: Default::default(),
    };

    println!("signing");

    crypto::sign_dc_message(&mutable, tee_sk).map_err(DcNetError::from)
}

use std::slice;
use std::string;

use serde;
use serde_json;
use sgx_status_t::{SGX_ERROR_INVALID_PARAMETER, SGX_ERROR_UNEXPECTED};

macro_rules! unwrap_or_return {
    ( $e:expr ) => {
        match $e {
            Ok(x) => x,
            Err(e) => {
                println!("Err {}", e);
                return SGX_ERROR_INVALID_PARAMETER;
            }
        }
    };
}

#[no_mangle]
pub extern "C" fn client_submit(
    send_request: *const u8,
    send_request_len: usize,
    sealed_tee_prv_key: *const u8,
    sealed_tee_prv_key_len: usize,
    output: *mut u8,
    output_size: usize,
    output_bytes_written: *mut usize,
) -> sgx_status_t {
    let send_request: SendRequest = match serde_json::from_slice(unsafe {
        slice::from_raw_parts(send_request, send_request_len)
    }) {
        Ok(j) => j,
        Err(e) => {
            println!("Err: {}", e);
            return SGX_ERROR_INVALID_PARAMETER;
        }
    };

    println!("deser request {:?}", send_request);

    let tee_prv_key: PrvKey = match serde_json::from_slice(unsafe {
        slice::from_raw_parts(sealed_tee_prv_key, sealed_tee_prv_key_len)
    }) {
        Ok(k) => k,
        Err(e) => {
            println!("Err: {}", e);
            return SGX_ERROR_INVALID_PARAMETER;
        }
    };

    println!("deser prv key: {:?}", tee_prv_key);

    match submit(&send_request, &tee_prv_key) {
        Ok(signed_msg) => {
            let serialized: Vec<u8> = match serde_json::to_vec(&signed_msg) {
                Ok(vec) => vec,
                Err(e) => {
                    println!("err {}", e);
                    return SGX_ERROR_UNEXPECTED;
                }
            };

            if serialized.len() > output_size {
                println!("not enough output space. need {}", serialized.len());
                return SGX_ERROR_INVALID_PARAMETER;
            }

            unsafe {
                output.copy_from(serialized.as_ptr(), serialized.len());
                output_bytes_written.write(serialized.len())
            }

            sgx_status_t::SGX_SUCCESS
        }
        Err(e) => {
            println!("Err: {}", e);
            sgx_status_t::SGX_ERROR_UNEXPECTED
        }
    }

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
