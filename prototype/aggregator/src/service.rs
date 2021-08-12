use crate::agg_state::AggregatorState;
use interface::KemPubKey;

use std::{error::Error, sync::Mutex};

use common::enclave_wrapper::DcNetEnclave;
use interface::RoundSubmissionBlob;

use rouille::{post_input, router, try_or_400, Request, Response};

/// Starts the HTTP service for this aggregator. The API is:
///
/// `POST /submit { submission_bytes: [u8] }`
/// Submit a new round message blob to this aggregator
///
/// `GET /get-agg -> [u8]`
/// Get the current running aggregate as a blob
pub(crate) fn start_service(mut state: AggregatorState) {
    let global_state = Mutex::new(state);

    rouille::start_server("0.0.0.0:8080", move |request| {
        let mut state_handle = global_state.lock().expect("couldn't acquire state");

        let res = router!(request,
            (POST) (/submit) => {
                submit(&mut *state_handle, request)
            },

            (GET) (/get-agg) => {
                get_agg(&*state_handle)
            },

            _ => {
                Ok(Response::empty_404())
            }
        );

        match res {
            Ok(r) => r,
            Err(e) => Response::text(format!("{}", e)).with_status_code(400),
        }
    });
}

/// Wrapper around `AggregatorState::add_to_aggregate`
pub(crate) fn submit(
    state: &mut AggregatorState,
    request: &Request,
) -> Result<Response, Box<dyn Error>> {
    let input = post_input!(request, {
        submission_bytes: Vec<u8>,
    })?;

    let round_submission = RoundSubmissionBlob(input.submission_bytes);
    state.add_to_aggregate(&round_submission)?;

    Ok(Response::empty_204())
}

/// Wrapper around `AggregatorState::finalize`
pub(crate) fn get_agg(state: &AggregatorState) -> Result<Response, Box<dyn Error>> {
    let msg = state.finalize_aggregate()?;
    Ok(Response::from_data("application/octet-stream", msg.payload))
}
