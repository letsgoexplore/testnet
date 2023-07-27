use crate::{
    util::{save_state, save_output, ServerError},
    ServerState,
};
use common::{cli_util, log_time::log_server_time};
use interface::RoundOutputUpdated;

use common::types_nosgx::{
    RoundSubmissionBlobNoSGX,
    UnblindedAggregateShareBlobNoSGX,
};

use core::ops::DerefMut;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use actix_rt::Arbiter;
use actix_web::{
    client::Client,
    get,
    http::{StatusCode, Uri},
    post, rt as actix_rt, web, App, HttpResponse, HttpServer, ResponseError, Result, dev, error, FromRequest,
    middleware::errhandlers::{ErrorHandlerResponse, ErrorHandlers},
};

// use futures_util::future::ok;
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

// #[derive(Clone)]
pub(crate) struct ServiceState {
    pub(crate) server_state: ServerState,
    pub(crate) round_shares: Vec<UnblindedAggregateShareBlobNoSGX>,
    /// Contains the URL of the anytrust leader. If `None`, it's you.
    pub(crate) leader_url: Option<String>,
    /// A map from round to the round's output
    pub(crate) round_outputs: BTreeMap<u32, RoundOutputUpdated>,
    /// The path to this server's state file. If `None`, state is not persisted to disk
    pub(crate) server_state_path: Option<String>,
}

impl ServiceState {
    pub(crate) fn new(
        server_state: ServerState,
        server_state_path: Option<String>,
        leader_url: Option<String>,
    ) -> ServiceState {
        ServiceState {
            server_state,
            server_state_path,
            leader_url,
            round_outputs: BTreeMap::new(),
            round_shares: Vec::new(),
        }
    }
}

// struct AppConfig {
//     max_payload_size: usize,
// }

// impl fmt::Display for PayloadTooLarge {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         write!(f, "Payload Too Large")
//     }
// }

// #[derive(Debug, Error)]
// struct PayloadTooLarge;
// impl From<PayloadError> for PayloadTooLarge {
//     fn from(_: PayloadError) -> Self {
//         PayloadTooLarge
//     }
// }

// async fn check_payload_size(
//     req: ServiceRequest,
//     pl: Payload,
// ) -> Result<ServiceRequest, PayloadTooLarge> {
//     // Get the max payload size from the AppConfig data
//     let max_payload_size = req.app_data::<web::Data<AppConfig>>().unwrap().max_payload_size;

//     // Manually read and calculate the payload size
//     let mut size: usize = 0;
//     let mut payload = pl;
//     while let Some(chunk) = payload.next().await {
//         let chunk = chunk.map_err(|_| PayloadTooLarge)?;
//         size += chunk.len();
//         if size > max_payload_size {
//             return Err(PayloadTooLarge);
//         }
//     }

//     Ok(req)
// }

fn render_500<B>(mut res: actix_web::dev::ServiceResponse<B>) -> actix_web::Result<actix_web::middleware::errhandlers::ErrorHandlerResponse<B>> {
    res.response_mut()
       .headers_mut()
       .insert(actix_web::http::header::CONTENT_TYPE, actix_web::http::HeaderValue::from_static("Error"));
    Ok(actix_web::middleware::errhandlers::ErrorHandlerResponse::Response(res))
}

fn render_413<B>(mut res: actix_web::dev::ServiceResponse<B>) -> actix_web::Result<actix_web::middleware::errhandlers::ErrorHandlerResponse<B>> {
    res.response_mut()
       .headers_mut()
       .insert(actix_web::http::header::CONTENT_TYPE, actix_web::http::HeaderValue::from_static("413 Error"));
    let req = res.request();
    let res = res.map_body(|_, _| actix_web::body::ResponseBody::Body(actix_web::dev::Body::from("{\"code\":413,\"error\":\"413 Payload Too Large\",\"message\":\"You've sent more data than expected\"}")).into_body());//alter the the response body see "https://users.rust-lang.org/t/actix-web-using-a-custom-error-handler-to-alter-the-response-body/41068"
    Ok(actix_web::middleware::errhandlers::ErrorHandlerResponse::Response(res))
}

/// Finish the round as the anytrust leader. This means computing the round output and clearing the
/// caches.
fn leader_finish_round(state: &mut ServiceState) {
    let start = Instant::now();

    let ServiceState {
        ref server_state,
        ref mut round_outputs,
        ref mut round_shares,
        ..
    } = state;

    // Derive the round output and save it to the state. This can be queries in the round_result
    // function. If this fails, use the default value. The last thing we want to do is get stuck in
    // a state that cannot progress
    let output = server_state
        .derive_round_output(&round_shares)
        .unwrap();
    let round = output.round;

    // debug!("output: {:?}", output);
    
    let mut output_path = "../server/round_output.txt".to_owned();
    output_path.insert(22, std::char::from_digit(round, 10).unwrap());
    debug!("output path: {:?}", output_path);
    match save_output(&output_path[..], &output) {
        Err(e) => error!("failed to save round output: {:?}", e),
        _ => (),
    };
    
    round_outputs.insert(round, output);
    info!("Output of round {} now available", round);

    // Clear the state
    round_shares.clear();

    let duration = start.elapsed();
    debug!("[server] leader_finish_round: {:?}", duration);
}

/// Sends the given unblinded share to `base_url/submit-share`
async fn send_share_to_leader(base_url: String, share: UnblindedAggregateShareBlobNoSGX) {
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
    match client.post(post_path).send_body(body.clone()).await {
        Ok(res) => {
            if res.status() == StatusCode::OK {
                debug!("Share sent successfully");
            } else {
                error!("Could not send share N0.1: {:?}", res);
            }
        }
        Err(e) => error!("Could not send share No.2: {:?}", e),
    }
}

/// Receives an aggregate from a top-level aggregator
#[post("/submit-agg")]
async fn submit_agg(
    (payload, state): (String, web::Data<Arc<Mutex<ServiceState>>>),
) -> Result<HttpResponse, ApiError> {
    let start = Instant::now();
    log_server_time("msg in");
    // Strip whitespace from the payload
    let payload = payload.split_whitespace().next().unwrap_or("");
    // Parse aggregation
    let agg_data: RoundSubmissionBlobNoSGX = cli_util::load(&mut payload.as_bytes())?;

    // Do the processing step. Unblind the input, add the share, and if we're the leader we finish
    // the round by combining the shares
    let mut state_handle = state.get_ref().lock().unwrap();
    {
        let ServiceState {
            ref leader_url,
            ref mut round_shares,
            ref mut server_state,
            ..
        } = state_handle.deref_mut();
        let group_size = server_state.anytrust_group_size;

        let unblind_start = Instant::now();
        // Unblind the input
        let share = server_state.unblind_aggregate(&agg_data)?;
        let unblind_duration = unblind_start.elapsed();
        debug!("[server] unblind_aggregate: {:?}", unblind_duration);
        log_server_time("finish unblind");

        // debug!("unblinded share: {:?}", share);

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
                    log_server_time("");
                }
            }
            // We're a follower. Send the unblinded aggregate to the leader
            Some(url) => {
                // This might take a while so do it in a separate thread
                Arbiter::spawn(send_share_to_leader(url.clone(), share));
            }
        }
    }

    // Save the state if a path is specified
    let server_state = &state_handle.server_state;
    let server_state_path = &state_handle.server_state_path;
    log_server_time("begin to save");
    server_state_path.as_ref().map(|path| {
        info!("Saving state");
        match save_state(path, server_state) {
            Err(e) => error!("failed to save server state {:?}", e),
            _ => (),
        }
    });
    log_server_time("AFTER save")
    let duration = start.elapsed();
    debug!("[server] submit_agg: {:?}", duration);

    Ok(HttpResponse::Ok().body("OK\n"))
}

/// Receives an unblinded share from another anytrust server
#[post("/submit-share")]
async fn submit_share(
    (payload, state): (String, web::Data<Arc<Mutex<ServiceState>>>),
) -> Result<HttpResponse, ApiError> {
    // Unpack state
    log_server_time("start unpacking")
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
    log_server_time("before merging");
    let share: UnblindedAggregateShareBlobNoSGX = cli_util::load(&mut payload.as_bytes())?;
    round_shares.push(share);
    info!("Got share. Number of shares is now {}", round_shares.len());
    log_server_time("after merging");
    // If all the shares are in, that's the end of the round
    if round_shares.len() == group_size {
        info!("Finishing round");
        leader_finish_round(handle.deref_mut());
        log_server_time("finish round");
    }

    Ok(HttpResponse::Ok().body("OK\n"))
}

/// Returns the output of the specified round
#[get("/round-result/{round}")]
async fn round_result(
    (round, state): (web::Path<u32>, web::Data<Arc<Mutex<ServiceState>>>),
) -> Result<HttpResponse, ApiError> {
    // Unwrap the round and make it a struct
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
            info!("received request for invalid round {}", round);
            HttpResponse::NotFound().body("Invalid round")
        }
    };

    Ok(res)
}

/// Returns just the base64-encoded message of the specified round
#[get("/round-msg/{round}")]
async fn round_msg(
    (round, state): (web::Path<u32>, web::Data<Arc<Mutex<ServiceState>>>),
) -> Result<HttpResponse, ApiError> {
    // Unwrap the round and make it a struct
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
            // Give the raw payload
            let blob = round_output.dc_msg.aggregated_msg.as_row_major();
            debug!("round-msg: {:?}", blob);

            let body = base64::encode(&blob);
            // let body = match str::from_utf8(&blob) {
            //     Ok(v) => v,
            //     Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
            // };
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
    info!(
        "Server group size is {}",
        state.server_state.anytrust_group_size
    );
    let state = Arc::new(Mutex::new(state));

    // Create the AppConfig with the desired max_payload_size (e.g., 10 MB)
    // let config = AppConfig {
    //     max_payload_size: 1024 * 1024 * 10,
    // };

    info!("Making new server on {}", bind_addr);
    let json_cfg = Arc::new(web::JsonConfig::default()
    // limit request payload size
    .limit(1024 * 1024 * 10)
    // only accept text/plain content type
    // .content_type(|mime| mime == mime::TEXT_PLAIN)
    // use custom error handler
    .error_handler(|err, req| {
        error::InternalError::from_response(err, HttpResponse::Conflict().into()).into()
    }));
    
    // Start the web server
    HttpServer::new(move || {
        App::new().data(state.clone())
        .data(web::PayloadConfig::new(10 << 21))
        .configure(|cfg| {
            cfg.service(submit_agg)
                .service(submit_share)
                .service(round_result)
                .service(round_msg);
        })
    })
    .workers(1)
    .bind(bind_addr)
    .expect("could not bind")
    .run()
    .await
}
