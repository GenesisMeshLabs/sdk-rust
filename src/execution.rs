//! Execution evidence: build and sign records exactly as the Python reference
//! `record_execution` does, and refuse secret material before anything is
//! signed.

use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::{
    auth::{load_signing_key, sign_canonical},
    canonical::{execution_canonical, execution_digest, python_timestamp},
    errors::{GenesisMeshError, Result},
    evidence_store::ResourceHead,
};

/// Limit on `execution_parameters` plus `outcome_detail`, as enforced by the NA.
pub const MAX_METADATA_BYTES: usize = 16 * 1024;

const SECRET_KEYS: [&str; 18] = [
    "value",
    "secret",
    "secretvalue",
    "password",
    "passwd",
    "passphrase",
    "token",
    "accesstoken",
    "refreshtoken",
    "bearer",
    "privatekey",
    "keymaterial",
    "credential",
    "credentials",
    "clientsecret",
    "apikey",
    "pem",
    "connectionstring",
];

fn normalise_key(key: &str) -> String {
    key.chars()
        .filter(|c| !matches!(c, '-' | '_' | '.'))
        .flat_map(char::to_lowercase)
        .collect()
}

fn token_chars(part: &str) -> bool {
    part.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn looks_like_key_material(value: &str) -> bool {
    let long_opaque = value.len() >= 120
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+/=_-".contains(&b));
    let jwt = value.strip_prefix("eyJ").is_some_and(|rest| {
        let parts: Vec<&str> = rest.split('.').collect();
        parts.len() == 3
            && !parts[0].is_empty()
            && !parts[1].is_empty()
            && parts.iter().all(|p| token_chars(p))
    });
    long_opaque || jwt
}

fn secret_material(value: &Value, path: &str) -> Option<String> {
    match value {
        Value::Array(items) => items
            .iter()
            .enumerate()
            .find_map(|(i, item)| secret_material(item, &format!("{path}{i}."))),
        Value::Object(map) => map.iter().find_map(|(key, inner)| {
            if SECRET_KEYS.contains(&normalise_key(key).as_str()) {
                Some(format!(
                    "field '{path}{key}' is not allowed in evidence metadata"
                ))
            } else {
                secret_material(inner, &format!("{path}{key}."))
            }
        }),
        Value::String(text) => {
            let field = path.strip_suffix('.').unwrap_or(path);
            if text.contains("-----BEGIN") {
                Some(format!("field '{field}' contains a PEM block"))
            } else if looks_like_key_material(text) {
                Some(format!("field '{field}' looks like key or token material"))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Why the metadata would be refused as secret material, or `None`. A guard,
/// not a guarantee: send identifiers, versions and timestamps, never secret
/// values.
pub fn check_metadata_only(
    execution_parameters: &Value,
    outcome_detail: Option<&str>,
) -> Option<String> {
    let size = serde_json::to_vec(&json!({
        "execution_parameters": execution_parameters,
        "outcome_detail": outcome_detail,
    }))
    .map_or(usize::MAX, |bytes| bytes.len());
    if size > MAX_METADATA_BYTES {
        return Some(format!(
            "metadata is {size} bytes, over the {MAX_METADATA_BYTES}-byte limit"
        ));
    }
    secret_material(execution_parameters, "").or_else(|| {
        outcome_detail.and_then(|detail| secret_material(&json!({"outcome_detail": detail}), ""))
    })
}

pub(crate) fn ensure_metadata_only(
    execution_parameters: &Value,
    outcome_detail: Option<&str>,
) -> Result<()> {
    match check_metadata_only(execution_parameters, outcome_detail) {
        Some(reason) => Err(GenesisMeshError::SecretMaterial(reason)),
        None => Ok(()),
    }
}

/// The previous record of a resource: the record itself, or its head (from
/// the NA's resource-head lookup or a retention checkpoint).
#[derive(Debug, Clone, PartialEq)]
pub enum PriorResource {
    /// The previous ExecutionEvidence record for the resource.
    Record(Value),
    /// The head of the resource chain.
    Head(ResourceHead),
}

impl PriorResource {
    fn head(&self) -> Result<ResourceHead> {
        match self {
            Self::Head(head) => Ok(head.clone()),
            Self::Record(record) => Ok(ResourceHead {
                resource_sequence: record
                    .get("resource_sequence")
                    .and_then(Value::as_u64)
                    .unwrap_or_default(),
                record_digest: execution_digest(record)?,
            }),
        }
    }
}

/// What to record about one execution.
#[derive(Debug, Clone, Default)]
pub struct RecordExecution {
    /// The decision that authorized this execution (its `decision_id`,
    /// `context_id` and `agreement_id` are copied).
    pub decision: Value,
    /// The capability executed.
    pub executed_capability: String,
    /// `success`, `failure` or another executor outcome. Defaults to `success`.
    pub outcome: Option<String>,
    /// Identifiers and versions only, never secret values.
    pub execution_parameters: Option<Value>,
    /// Short outcome detail.
    pub outcome_detail: Option<String>,
    /// Previous record under the same decision (sets `sequence_no` and `prev_evidence_digest`).
    pub prior_record: Option<Value>,
    /// Resource acted on, e.g. `kv:<vault>/<secret>`. An identifier, never a value.
    pub resource_id: Option<String>,
    /// `create`, `rotate`, `revoke`, `update` or `delete`; required with `resource_id`.
    pub resource_action: Option<String>,
    /// Previous record for the same resource, from any decision; `None` for its first record.
    pub prior_resource: Option<PriorResource>,
    /// Execution time. Defaults to now.
    pub executed_at: Option<DateTime<Utc>>,
    /// Record id. Defaults to a random UUID.
    pub evidence_id: Option<String>,
}

/// Builds and signs ExecutionEvidence for one executor.
#[derive(Clone)]
pub struct ExecutionRecorder {
    executor_sovereign_id: String,
    key_id: String,
    signing_key: SigningKey,
}

impl std::fmt::Debug for ExecutionRecorder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecutionRecorder")
            .field("executor_sovereign_id", &self.executor_sovereign_id)
            .field("key_id", &self.key_id)
            .field("signing_key", &"[REDACTED]")
            .finish()
    }
}

impl ExecutionRecorder {
    /// A recorder for `executor_sovereign_id`, signing with the base64 seed
    /// of the executor key registered with the NA as `key_id`.
    pub fn new(
        executor_sovereign_id: impl Into<String>,
        key_id: impl Into<String>,
        seed_base64: &str,
    ) -> Result<Self> {
        Ok(Self {
            executor_sovereign_id: executor_sovereign_id.into(),
            key_id: key_id.into(),
            signing_key: load_signing_key(seed_base64)?,
        })
    }

    /// The executor sovereign this recorder signs for.
    pub fn executor_sovereign_id(&self) -> &str {
        &self.executor_sovereign_id
    }

    /// The registered executor key id.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Build and sign one ExecutionEvidence record.
    pub fn record(&self, params: RecordExecution) -> Result<Value> {
        if params.resource_id.is_some() != params.resource_action.is_some() {
            return Err(GenesisMeshError::Configuration(
                "resource_id and resource_action go together".into(),
            ));
        }
        let execution_parameters = params.execution_parameters.unwrap_or_else(|| json!({}));
        if !execution_parameters.is_object() {
            return Err(GenesisMeshError::Configuration(
                "execution_parameters must be a JSON object".into(),
            ));
        }
        ensure_metadata_only(&execution_parameters, params.outcome_detail.as_deref())?;
        let decision_field = |key: &str| {
            params
                .decision
                .get(key)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| GenesisMeshError::Configuration(format!("decision has no {key}")))
        };

        let prior = params.prior_record.as_ref();
        let mut record = Map::new();
        record.insert(
            "evidence_id".into(),
            json!(params
                .evidence_id
                .unwrap_or_else(|| Uuid::new_v4().to_string())),
        );
        record.insert(
            "sequence_no".into(),
            json!(prior
                .and_then(|p| p.get("sequence_no")?.as_u64())
                .map_or(1, |n| n + 1)),
        );
        record.insert("decision_id".into(), json!(decision_field("decision_id")?));
        record.insert("context_id".into(), json!(decision_field("context_id")?));
        record.insert(
            "agreement_id".into(),
            json!(decision_field("agreement_id")?),
        );
        record.insert(
            "executor_sovereign_id".into(),
            json!(self.executor_sovereign_id),
        );
        record.insert(
            "executed_capability".into(),
            json!(params.executed_capability),
        );
        record.insert("execution_parameters".into(), execution_parameters);
        record.insert(
            "executed_at".into(),
            json!(python_timestamp(
                params.executed_at.unwrap_or_else(Utc::now)
            )),
        );
        record.insert(
            "outcome".into(),
            json!(params.outcome.unwrap_or_else(|| "success".into())),
        );
        record.insert("outcome_detail".into(), json!(params.outcome_detail));
        record.insert(
            "prev_evidence_digest".into(),
            match prior {
                Some(prior) => json!(execution_digest(prior)?),
                None => Value::Null,
            },
        );
        if let (Some(resource_id), Some(action)) = (params.resource_id, params.resource_action) {
            let head = params
                .prior_resource
                .as_ref()
                .map(PriorResource::head)
                .transpose()?;
            record.insert("resource_id".into(), json!(resource_id));
            record.insert("resource_action".into(), json!(action));
            record.insert(
                "resource_sequence".into(),
                json!(head.as_ref().map_or(1, |h| h.resource_sequence + 1)),
            );
            record.insert(
                "prev_resource_digest".into(),
                json!(head.map(|h| h.record_digest)),
            );
        }
        record.insert("signature".into(), Value::Null);
        let mut record = Value::Object(record);
        let signature = sign_canonical(
            &execution_canonical(&record)?,
            &self.key_id,
            &self.signing_key,
        );
        record["signature"] = signature;
        Ok(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_secret_metadata_and_allows_identifiers() {
        assert!(
            check_metadata_only(&json!({"secret_version": "v3", "vault": "kv-pilot"}), None)
                .is_none()
        );
        for bad in [
            json!({"Client-Secret": "x"}),
            json!({"nested": [{"api_key": "x"}]}),
            json!({"cert": "-----BEGIN PRIVATE KEY-----"}),
            json!({"blob": "A".repeat(120)}),
            json!({"jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"}),
        ] {
            assert!(check_metadata_only(&bad, None).is_some(), "{bad}");
        }
        assert!(check_metadata_only(&json!({}), Some("-----BEGIN KEY")).is_some());
        assert!(
            check_metadata_only(&json!({"note": "x".repeat(MAX_METADATA_BYTES)}), None)
                .unwrap()
                .contains("byte limit")
        );
        assert_eq!(
            check_metadata_only(&json!({"items": [{"token": 1}]}), None).unwrap(),
            "field 'items.0.token' is not allowed in evidence metadata"
        );
    }
}
