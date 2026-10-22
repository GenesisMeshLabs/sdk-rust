//! What an operator issues to an edge node, for the edge agent walkthrough
//! (docs/examples/edge-agent.md): an active policy and an attestation for
//! the node's sovereign ID, then a grant to its executor key.
//!
//! ```text
//! cargo run --example edge_site -- attest <sovereign-id> <capability>...
//! cargo run --example edge_site -- grant <executor-key-id> <attestation-id> <capability>
//! ```
//!
//! Requires `NA_URL` and `OPERATOR_KEY` (the base64 seed of a privileged
//! operator key), and optionally `OPERATOR_KEY_ID` (default
//! `operator-local`). `attest` prints the attestation ID, `grant` the grant
//! ID. The NA needs `EVIDENCE_GRANTS=on` for `grant`.
use genesis_mesh_sdk::{canonical::python_timestamp, json, ClientOptions, GenesisMeshClient};

const USAGE: &str = "usage: edge_site attest <sovereign-id> <capability>...\n       \
                     edge_site grant <executor-key-id> <attestation-id> <capability>";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let client = GenesisMeshClient::new(
        ClientOptions::new(std::env::var("NA_URL")?)
            .with_signing_key(std::env::var("OPERATOR_KEY")?)
            .with_key_id(
                std::env::var("OPERATOR_KEY_ID").unwrap_or_else(|_| "operator-local".into()),
            ),
    )?;
    let now = chrono::Utc::now();
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["attest", sovereign, capabilities @ ..] if !capabilities.is_empty() => {
            // Decisions need an active policy over the capabilities: here, a
            // lifetime of at most 90 days.
            let policy = client
                .policy
                .publish(json!({
                    "policy_id": format!("edge-{sovereign}"),
                    "valid_from": (now - chrono::Duration::minutes(1)).to_rfc3339(),
                    "valid_until": (now + chrono::Duration::days(30)).to_rfc3339(),
                    "selector": {"capabilities": capabilities},
                    "gates": [{"gate_id": "lifetime", "gate_type": "max_value.v1", "order": 0,
                               "config": {"path": "request_parameters.lifetime_days", "max": 90}}],
                }))
                .await?;
            let policy_id = policy["policy_id"].as_str().ok_or("no policy_id")?;
            let version = policy["version"].as_u64().ok_or("no version")?;
            client.policy.activate(policy_id, version).await?;
            // The NA decides the node's requests only under attestations
            // issued to its sovereign ID.
            let attestation = client
                .attestation
                .issue(json!({
                    "subject_id": sovereign,
                    "roles": ["role:client"],
                    "claims": {"capabilities": capabilities},
                }))
                .await?;
            println!(
                "{}",
                attestation["attestation_id"]
                    .as_str()
                    .ok_or("no attestation_id")?
            );
        }
        ["grant", executor_key_id, attestation_id, capability] => {
            // Ten uses over two hours, five per time token, for a lifetime
            // of 1 to 60 days.
            let issued = client
                .grants
                .issue(json!({
                    "bearer_key_id": executor_key_id,
                    "capabilities": [capability],
                    "attestation_id": attestation_id,
                    "valid_until": python_timestamp(now + chrono::Duration::hours(2)),
                    "max_uses": 10,
                    "max_uses_per_time_token": 5,
                    "parameter_envelope": {"lifetime_days": {"number_range": {
                        "number_type": "integer", "minimum": 1, "maximum": 60}}},
                }))
                .await?;
            println!(
                "{}",
                issued["grant"]["grant_id"].as_str().ok_or("no grant_id")?
            );
        }
        _ => return Err(USAGE.into()),
    }
    Ok(())
}
