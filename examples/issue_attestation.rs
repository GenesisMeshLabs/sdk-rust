//! Requires NA_URL, OPERATOR_KEY, and an operator key registered on the NA.
use genesis_mesh_sdk::{json, ClientOptions, GenesisMeshClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = GenesisMeshClient::new(
        ClientOptions::new(std::env::var("NA_URL")?)
            .with_signing_key(std::env::var("OPERATOR_KEY")?)
            .with_key_id(
                std::env::var("OPERATOR_KEY_ID").unwrap_or_else(|_| "operator-local".into()),
            ),
    )?;
    let attestation = client
        .attestation
        .issue(json!({
            "subject_id": "node-example",
            "roles": ["role:client"],
            "validity_hours": 24
        }))
        .await?;
    println!("{attestation:#}");
    Ok(())
}
