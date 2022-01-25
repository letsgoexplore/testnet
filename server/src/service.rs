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
use log::{debug, error, info};
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
    /// Contains the URL of the anytrust leader. If `None`, it's you.
    pub(crate) leader_url: Option<String>,
    /// A map from round+window to the round's output
    pub(crate) round_outputs: BTreeMap<u32, RoundOutput>,
}

impl ServiceState {
    pub(crate) fn new(
        server_state: ServerState,
        enclave: DcNetEnclave,
        leader_url: Option<String>,
    ) -> ServiceState {
        ServiceState {
            server_state,
            enclave,
            leader_url,
            round_outputs: BTreeMap::new(),
            round_shares: Vec::new(),
        }
    }
}

/// Finish the round as the anytrust leader. This means computing the round output and clearing the
/// caches.
fn leader_finish_round(state: &mut ServiceState) {
    let ServiceState {
        ref server_state,
        ref mut round_outputs,
        ref mut round_shares,
        ref enclave,
        ..
    } = state;

    // Derive the round output and save it to the state. This can be queries in the round_result
    // function. If this fails, use the default value. The last thing we want to do is get stuck in
    // a state that cannot progress
    let output = server_state
        .derive_round_output(enclave, &round_shares)
        .unwrap();
    let round = output.round;
    round_outputs.insert(round, output);
    info!("Output of round {} now available", round);

    // Clear the state and increment the round
    round_shares.clear();
}

/// Sends the given unblinded share to `base_url/submit-share`
async fn send_share_to_leader(base_url: String, share: UnblindedAggregateShareBlob) {
    // Serialize the share
    let mut body = Vec::new();
    cli_util::save(&mut body, &share).expect("could not serialize share");

    // Send the serialized contents as an HTTP POST to leader/submit-share
    let timeout_sec = 20;
    debug!(
        "Sending share to {} with timeout {}s",
        base_url, timeout_sec
    );
    let client = Client::builder()
        .timeout(Duration::from_secs(timeout_sec))
        .finish();
    let post_path: Uri = [&base_url, "/submit-share"]
        .concat()
        .parse()
        .expect("Couldn't not append '/submit-share' to forward URL");
    match client.post(post_path).send_body(body).await {
        Ok(res) => {
            if res.status() == StatusCode::OK {
                debug!("Share sent successfully");
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
    // Strip whitespace from the payload
    let payload = payload.split_whitespace().next().unwrap_or("");
    // Parse aggregation
    let agg_data: RoundSubmissionBlob = cli_util::load(&mut payload.as_bytes())?;

    // Unpack the state
    let mut state_handle = state.get_ref().lock().unwrap();
    let ServiceState {
        ref leader_url,
        ref mut round_shares,
        ref enclave,
        ref mut server_state,
        ..
    } = state_handle.deref_mut();
    let group_size = server_state.anytrust_group_size;

    // Unblind the input
    let share = server_state.unblind_aggregate(enclave, &agg_data)?;

    match leader_url {
        // We're the leader
        None => {
            // Since we're the leader, add this share to the current round's shares
            round_shares.push(share);
            info!(
                "I now have {}/{} round shares",
                round_shares.len(),
                group_size
            );

            // If all the shares are in, that's the end of the round
            if round_shares.len() == group_size {
                info!("Finishing round");
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
    let group_size = handle.server_state.anytrust_group_size;
    let ServiceState {
        ref leader_url,
        ref mut round_shares,
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
    info!("Got share. Number of shares is now {}", round_shares.len());

    // If all the shares are in, that's the end of the round
    if round_shares.len() == group_size {
        info!("Finishing round");
        leader_finish_round(handle.deref_mut());
    }

    Ok(HttpResponse::Ok().body("OK\n"))
}

/// Returns the output of the specified round+window
#[get("/round-result/{round}")]
async fn round_result(
    (window, round, state): (
        web::Path<u32>,
        web::Path<u32>,
        web::Data<Arc<Mutex<ServiceState>>>,
    ),
) -> Result<HttpResponse, ApiError> {
    // Unwrap the round+window and make it a struct
    let web::Path(round) = round;

    // Unpack state
    let handle = state.get_ref().lock().unwrap();
    let ServiceState {
        ref round_outputs,
        ref leader_url,
        ..
    } = *handle;

    // I am not the leader. Don't ask me for round results
    if leader_url.is_some() {
        return Ok(HttpResponse::NotFound().body("Followers don't store round results"));
    }

    // Try to get the requested output
    let res = match round_outputs.get(&round) {
        // If the given round's output exists in memory, return it
        Some(round_output) => {
            // Give the signed round output, not just the raw payload
            /*
            let blob = round_output
                .dc_msg
                .aggregated_msg
                .iter()
                .flat_map(|msg| msg.0.to_vec())
                .collect::<Vec<u8>>();
            cli_util::save(&mut body, &blob)?;
            */
            let mut body = Vec::new();
            cli_util::save(&mut body, &round_output)?;
            HttpResponse::Ok().body(body)
        }
        // If the given round's output doesn't exist in memory, error out
        None => {
            info!("received request for invalid round r{}w{}", round, window);
            HttpResponse::NotFound().body("Invalid round")
        }
    };

    Ok(res)
}

#[actix_rt::main]
pub(crate) async fn start_service(bind_addr: String, state: ServiceState) -> std::io::Result<()> {
    info!(
        "Server group size is {}",
        state.server_state.anytrust_group_size
    );
    let state = Arc::new(Mutex::new(state));

    info!("Making new server on {}", bind_addr);

    // Start the web server
    HttpServer::new(move || {
        App::new().data(state.clone()).configure(|cfg| {
            cfg.service(submit_agg);
            cfg.service(submit_share);
            cfg.service(round_result);
        })
    })
    .workers(1)
    .bind(bind_addr)
    .expect("could not bind")
    .run()
    .await
}
