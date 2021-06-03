extern crate interface;
extern crate serde_cbor;
extern crate sgx_types;
extern crate sgx_urts;
extern crate tonic;

pub mod enclave_wrapper;

use enclave_wrapper::{DcNetEnclave, EnclaveResult};
use interface::{RawMessage, SendRequest, ServerSecret, UserId, DC_NET_MESSAGE_LENGTH};

use tonic::{transport::Server, Request, Response, Status};

use aggregator::aggregator_server::{Aggregator, AggregatorServer};
use aggregator::{AggMsgSgxBlob, AggReq, DcMsgSgxBlob, SendMessageReply, SendMessageRequest};

pub mod aggregator {
    tonic::include_proto!("aggregator");
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
    async fn submit_message(
        &self,
        request: Request<DcMsgSgxBlob>, // Accept request of type SendMessageRequest
    ) -> Result<Response<SendMessageReply>, Status> {
        // Return an instance of type SendMessageReply

        println!("Got a request to send message: {:?}", request);

        let send_request = SendRequest {
            user_id: UserId::default(),
            message: [9 as u8; DC_NET_MESSAGE_LENGTH],
            round: 0,
            server_keys: vec![ServerSecret::gen_test(1), ServerSecret::gen_test(2)],
        };

        let error = match self
            .enclave
            .client_submit(&send_request, &self.sgx_key_sealed)
        {
            Ok(m) => {
                println!("{:?}", m);
                "".to_string()
            }
            Err(e) => {
                error!("Err {}", e);
                e.to_string()
            }
        };

        println!("bye-bye");

        let reply = SendMessageReply { error };

        Ok(Response::new(reply)) // Send back our formatted greeting
    }

    async fn get_aggregate(
        &self,
        request: Request<AggReq>,
    ) -> Result<Response<AggMsgSgxBlob>, Status> {
        unimplemented!()
    }
}
