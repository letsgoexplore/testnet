use crate::{util::ServerError, ServerState};
use common::{cli_util, enclave_wrapper::DcNetEnclave};
use interface::{RoundOutput, RoundSubmissionBlob, UnblindedAggregateShareBlob};

use core::ops::DerefMut;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use actix_rt::Arbiter;
use actix_web::{
    client::Client,
    get,
    http::{StatusCode, Uri},
    post, rt as actix_rt, web, App, HttpResponse, HttpServer, ResponseError,
};
use log::{error, info};
use thiserror::Error;

#[derive(Debug, Error)]
enum ApiError {
    #[error("internal error")]
    Internal(#[from] ServerError),
    #[error("base64 encoding error")]
    Encoding(#[from] base64::DecodeError),
    #[error("error in serialization/deserialization")]
    Ser(#[from] cli_util::SerializationError),
}
impl ResponseError for ApiError {}

#[derive(Clone)]
pub(crate) struct ServiceState {
    pub(crate) server_state: ServerState,
    pub(crate) round_shares: Vec<UnblindedAggregateShareBlob>,
    pub(crate) enclave: DcNetEnclave,
    pub(crate) round: u32,
    /// Contains the URL of the anytrust leader. If `None`, it's you.
    pub(crate) leader_url: Option<String>,
    /// A map from round number to the round's output
    pub(crate) round_outputs: BTreeMap<u32, RoundOutput>,
    pub(crate) anytrust_group_size: usize,
}

/// Finish the round as the anytrust leader. This means computing the round output and clearing the
/// caches.
fn leader_finish_round(state: &mut ServiceState) {
    let ServiceState {
        ref server_state,
        ref mut round_outputs,
        ref mut round_shares,
        ref mut round,
        ref enclave,
        ..
    } = state;

    // Derive the round output and save it to the state. This can be queries in the round_result
    // function. If this fails, use the default value. The last thing we want to do is get stuck in
    // a state that cannot progres.
    let output = server_state
        .derive_round_output(enclave, &round_shares)
        .unwrap_or(RoundOutput::default());
    round_outputs.insert(*round, output);

    // Clear the state and increment the round
    round_outputs.clear();
    round_shares.clear();
    *round += 1;
}

/// Sends the given unblinded share to `base_url/submit-share`
async fn send_share_to_leader(base_url: String, share: UnblindedAggregateShareBlob) {
    // Serialize the share
    let mut body = Vec::new();
    cli_util::save(&mut body, &share).expect("could not serialize share");

    // Send the serialized contents as an HTTP POST to leader/submit-share
    let client = Client::builder().timeout(Duration::from_secs(20)).finish();
    let post_path: Uri = [&base_url, "/submit-share"]
        .concat()
        .parse()
        .expect("Couldn't not append '/submit-share' to forward URL");
    match client.post(post_path).send_body(body).await {
        Ok(res) => {
            if res.status() == StatusCode::OK {
                info!("Successfully sent share");
            } else {
                error!("Could not send share: {:?}", res);
            }
        }
        Err(e) => error!("Could not send share: {:?}", e),
    }
}

/// Receives an aggregate from a top-level aggregator
#[post("/submit-agg")]
async fn submit_agg(
    (payload, state): (String, web::Data<Arc<Mutex<ServiceState>>>),
) -> Result<HttpResponse, ApiError> {
    // Parse aggregation
    let agg_data: RoundSubmissionBlob = cli_util::load(&mut payload.as_bytes())?;

    // Unblind the input
    let mut state_handle = state.get_ref().lock().unwrap();
    let share = state_handle
        .server_state
        .unblind_aggregate(&state_handle.enclave, &agg_data)?;

    match &state_handle.leader_url {
        // We're the leader
        None => {
            // Since we're the leader, add this share to the current round's shares
            let round_shares = &mut state_handle.round_shares;
            round_shares.push(share);

            // If all the shares are in, that's the end of the round
            if round_shares.len() == state_handle.server_state.anytrust_group_size {
                leader_finish_round(state_handle.deref_mut());
            }
        }
        // We're a follower. Send the unblinded aggregate to the leader
        Some(url) => {
            // This might take a while so do it in a separate thread
            Arbiter::spawn(send_share_to_leader(url.clone(), share));
        }
    }

    Ok(HttpResponse::Ok().body("OK\n"))
}

/// Receives an unblinded share from another anytrust server
#[post("/submit-share")]
async fn submit_share(
    (payload, state): (String, web::Data<Arc<Mutex<ServiceState>>>),
) -> Result<HttpResponse, ApiError> {
    // Unpack state
    let mut handle = state.get_ref().lock().unwrap();
    let ServiceState {
        ref leader_url,
        ref mut round_shares,
        anytrust_group_size,
        ..
    } = handle.deref_mut();

    // We are not the leader. We should not be receiving a share
    if leader_url.is_some() {
        let msg = "followers aren't supposed to receive anytrust shares";
        error!("{}", msg);
        return Ok(HttpResponse::BadRequest().body(msg));
    }

    // Parse the share and add it to our shares
    let share: UnblindedAggregateShareBlob = cli_util::load(&mut payload.as_bytes())?;
    round_shares.push(share);

    // If all the shares are in, that's the end of the round
    if round_shares.len() == *anytrust_group_size {
        leader_finish_round(handle.deref_mut());
    }

    Ok(HttpResponse::Ok().body("OK\n"))
}

/// Returns the output of the specified round
#[get("/round-result/{orund}")]
async fn round_result(
    (round, state): (web::Path<u32>, web::Data<Arc<Mutex<ServiceState>>>),
) -> Result<HttpResponse, ApiError> {
    // Unwrap the round
    let web::Path(round) = round;

    // Unpack state
    let handle = state.get_ref().lock().unwrap();
    let ServiceState {
        ref round_outputs, ..
    } = *handle;

    // Try to get the requested output
    let res = match round_outputs.get(&round) {
        // If the given round's output exists in memory, return it
        Some(blob) => {
            let mut body = Vec::new();
            cli_util::save(&mut body, blob)?;
            HttpResponse::Ok().body(body)
        }
        // If the given round's output doesn't exist in memory, error out
        None => {
            info!("received request for invalid round {}", round);
            HttpResponse::NotFound().body("Invalid round")
        }
    };

    Ok(res)
}

#[actix_rt::main]
pub(crate) async fn start_service(bind_addr: String, state: ServiceState) -> std::io::Result<()> {
    let state = Arc::new(Mutex::new(state));

    // Start the web server
    HttpServer::new(move || {
        App::new().data(state.clone()).configure(|cfg| {
            cfg.service(submit_agg);
            cfg.service(submit_share);
            cfg.service(round_result);
        })
    })
    .bind(bind_addr)
    .expect("could not bind")
    .run()
    .await
}
