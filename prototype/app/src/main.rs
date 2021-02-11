extern crate sgx_types;
extern crate sgx_urts;

use sgx_types::*;

extern crate interface;
extern crate serde_cbor;
extern crate tonic;

mod client;
mod enclave_wrapper;

use enclave_wrapper::*;
use interface::*;

use tonic::{transport::Server, Request, Response, Status};

use self::aggregator_server::{Aggregator, AggregatorServer};
use self::{SendMessageReply, SendMessageRequest};

pub mod aggregator {
    tonic::include_proto!("aggregator");
}

extern crate pretty_env_logger;
#[macro_use]
extern crate log;

fn main() {
    pretty_env_logger::init();

    let dc_enclave = match DcNetEnclave::init("enclave.signed.so") {
        Ok(r) => {
            println!("[+] Init Enclave Successful {}!", r.geteid());
            r
        }
        Err(x) => {
            error!("[-] Init Enclave Failed {}!", x.as_str());
            return;
        }
    };

    let send_request = SendRequest {
        user_id: UserId::default(),
        message: [9 as u8; DC_NET_MESSAGE_LENGTH],
        round: 0,
        server_keys: vec![ServerSecret::gen_test(1), ServerSecret::gen_test(2)],
    };

    let sgx_key_sealed = base64::decode("BAACAAAAAABIIPM3auay8gNNO3pLSKd4CwAAAAAAAP8AAAAAAAAAAIaOkrL+G/tjwqpYb2cPLagU2yBuV2gTFnrQR1YRijjLAAAA8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAJAAAAAAAAAAAAAAAAAAAAMcwvJUTIR5owP6OfXybb09woO+S2ZZ1DHRXUFLcu7GfdV+AQ6ddvsqjCZpdA0X+BQECAwQ=").unwrap();

    match dc_enclave.client_submit(&send_request, &sgx_key_sealed) {
        Ok(m) => println!("{:?}", m),
        Err(e) => error!("Err {}", e),
    }

    println!("bye-bye");

    dc_enclave.destroy();
}
