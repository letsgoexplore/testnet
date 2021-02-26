extern crate interface;
extern crate serde_cbor;
extern crate sgx_types;
extern crate sgx_urts;
extern crate tonic;

mod client;
mod enclave_wrapper;

use enclave_wrapper::*;
use interface::*;

use tonic::{transport::Server, Request, Response, Status};

use aggregator::aggregator_server::{Aggregator, AggregatorServer};
use aggregator::{SendMessageReply, SendMessageRequest};

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
            sgx_key_sealed: base64::decode("BAACAAAAAABIIPM3auay8gNNO3pLSKd4CwAAAAAAAP8AAAAAAAAAAIaOkrL+G/tjwqpYb2cPLagU2yBuV2gTFnrQR1YRijjLAAAA8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAJAAAAAAAAAAAAAAAAAAAAMcwvJUTIR5owP6OfXybb09woO+S2ZZ1DHRXUFLcu7GfdV+AQ6ddvsqjCZpdA0X+BQECAwQ=").unwrap(),
        });
    }
}

#[tonic::async_trait]
impl Aggregator for MyAggregator {
    async fn say_message(
        &self,
        request: Request<SendMessageRequest>, // Accept request of type SendMessageRequest
    ) -> Result<Response<SendMessageReply>, Status> {
        // Return an instance of type SendMessageReply

        let success;
        let error;

        println!("Got a request to send message: {:?}", request);

        let send_request = SendRequest {
            user_id: UserId::default(),
            message: [9 as u8; DC_NET_MESSAGE_LENGTH],
            round: 0,
            server_keys: vec![ServerSecret::gen_test(1), ServerSecret::gen_test(2)],
        };

        match self
            .enclave
            .client_submit(&send_request, &self.sgx_key_sealed)
        {
            Ok(m) => {
                println!("{:?}", m);
                error = format!("{:?}", m);
                success = true
            }
            Err(e) => {
                error!("Err {}", e);
                error = e.to_string();
                success = false
            }
        }

        println!("bye-bye");

        let reply = SendMessageReply { success, error };

        Ok(Response::new(reply)) // Send back our formatted greeting
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init();

    let addr = "127.0.0.1:1338".parse()?;
    let aggregator = MyAggregator::init("enclave.signed.so").map_err(|e| {
        error!("[-] Init Enclave Failed {}!", e);
        e
    })?;

    Server::builder()
        .add_service(AggregatorServer::new(aggregator))
        .serve(addr)
        .await?;

    Ok(())
}
