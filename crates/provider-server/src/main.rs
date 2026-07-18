#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    provider_server::run().await
}
