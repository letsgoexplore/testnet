use aggregator::aggregator_client::AggregatorClient;
use aggregator::HelloRequest;

pub mod hello_world {
    tonic::include_proto!("aggregator");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = AggregatorClient::connect("http://127.0.0.1:1338").await?;

    let request = tonic::Request::new(SendMessageRequest {
        name: "Tonic".into(),
    });

    let response = client.send_message(request).await?;

    println!("RESPONSE={:?}", response);

    Ok(())
}
