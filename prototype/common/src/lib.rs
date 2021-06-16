extern crate interface;
extern crate serde_cbor;
extern crate sgx_types;
extern crate sgx_urts;
extern crate tonic;

pub mod enclave_wrapper;

use enclave_wrapper::{DcNetEnclave, EnclaveResult};
use interface::{EntityId, DC_NET_MESSAGE_LENGTH};

use dc_proto::{
    aggregator_server::{Aggregator, AggregatorServer},
    Empty, SgxMsg,
};
use tonic::{transport::Server, Request, Response, Status};
pub mod dc_proto {
    tonic::include_proto!("dc_proto");
}

extern crate pretty_env_logger;
#[macro_use]
extern crate log;
