//! Read the active policy: NA_URL=http://127.0.0.1:9443 cargo run --example get_policy
use genesis_mesh_sdk::{ClientOptions, GenesisMeshClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::var("NA_URL").unwrap_or_else(|_| "http://127.0.0.1:9443".into());
    let client = GenesisMeshClient::new(ClientOptions::new(url))?;
    println!("{:#}", client.data_usage.get_policy().await?);
    Ok(())
}
