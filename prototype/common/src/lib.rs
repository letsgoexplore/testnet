extern crate interface;
extern crate serde_cbor;
extern crate sgx_types;
extern crate sgx_urts;
extern crate tonic;

pub mod enclave_wrapper;

use enclave_wrapper::{DcNetEnclave, EnclaveResult};
use interface::{EntityId, ServerSecret, DC_NET_MESSAGE_LENGTH};

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

#[derive(Debug, Default)]
pub struct MyAggregator {
    sgx_key_sealed: Vec<u8>,
    enclave: DcNetEnclave,
}

impl MyAggregator {
    fn init(enclave_path: &'static str) -> EnclaveResult<MyAggregator> {
        return Ok(MyAggregator {
            enclave: DcNetEnclave::init(enclave_path)?,
            // for testing purposes
            sgx_key_sealed: base64::decode(
                "BAACAAAAAABIIPM3auay8gNNO3pLSKd4CwAAAAAAAP8AAAAAAAAAAIaOkrL+G/tjwqpYb2cPLagU2yBuV\
                 2gTFnrQR1YRijjLAAAA8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
                 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
                 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
                 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
                 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
                 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
                 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
                 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAJAAAAAAAAAAAAAAAAAAAAMcwv\
                 JUTIR5owP6OfXybb09woO+S2ZZ1DHRXUFLcu7GfdV+AQ6ddvsqjCZpdA0X+BQECAwQ=",
            )
            .unwrap(),
        });
    }
}

#[tonic::async_trait]
impl Aggregator for MyAggregator {
    async fn submit_round_msg(
        &self,
        request: Request<SgxMsg>,
    ) -> Result<Response<Empty>, tonic::Status> {
        println!("Got a request to send message: {:?}", request);

        /*
        self.enclave
            .client_submit(&send_request, &self.sgx_key_sealed)
            .map_err(|e| Status::unknown(e.to_string()))?;
        */

        Ok(Response::new(Empty {}))
    }
}
