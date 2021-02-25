extern crate interface;

use interface::*;

use aggregator::aggregator_client::AggregatorClient;
use aggregator::SendMessageRequest;

pub mod aggregator {
    tonic::include_proto!("aggregator");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = AggregatorClient::connect("http://127.0.0.1:1338").await?;

    let request = tonic::Request::new(SendMessageRequest {
        user_id: "null".into(),
        messages: [9 as u8; DC_NET_MESSAGE_LENGTH].into(),
        round: 0,
        server_keys_hash: "test".into(),
    });

    let response = client.say_message(request).await?;

    println!("RESPONSE={:?}", response);

    Ok(())
}
