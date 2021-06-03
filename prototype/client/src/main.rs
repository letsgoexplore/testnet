extern crate common;
extern crate interface;

use interface::*;

use aggregator::aggregator_client::AggregatorClient;
use aggregator::SendMessageRequest;
use common::enclave_wrapper::DcNetEnclave;

pub mod aggregator {
    tonic::include_proto!("aggregator");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // let mut client = AggregatorClient::connect("http://127.0.0.1:1338").await?;

    // TODO: maybe not hardcode the enclave path
    let enclave = DcNetEnclave::init("/sgxdcnet/lib/enclave.signed.so")?;
    enclave.run_enclave_tests();
    enclave.destroy();

    // let request = tonic::Request::new(SendMessageRequest {
    //     user_id: "null".into(),
    //     messages: [9 as u8; DC_NET_MESSAGE_LENGTH].into(),
    //     round: 0,
    //     server_keys_hash: "test".into(),
    // });
    //
    // let response = client.submit_message(request).await?;
    //
    // println!("RESPONSE={:?}", response);

    Ok(())
}
