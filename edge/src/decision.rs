//! The decision order's rules, without I/O (docs/edge.md, "Decision order"):
//! what an NA error means, which grant decides, and what follows when no
//! grant does. The agent's `decide` calls these between its NA and grant
//! steps; the table tests below cover them.

use genesis_mesh_sdk::{evaluation_failure, EvaluationFailure, GenesisMeshError, Value};

/// What a failed request to the NA tells the agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// The NA answered and refused: final. No grant, no break-glass.
    Refused,
    /// The NA answered `429` or `5xx`, with or without its own error body,
    /// and the answer is not a gateway's own page: it is there but
    /// throttling or failing. Grants (bounded by the operator) may be used;
    /// break-glass may not.
    Throttled {
        /// The HTTP status.
        status: u16,
        /// The NA's code.
        code: String,
    },
    /// No answer from the NA: no connection, a timeout, or a proxy's own
    /// error page (`502`, `503`, `504`, `520` to `527` without the NA's JSON
    /// error body). Grants, then break-glass with a justification.
    Unreachable(EvaluationFailure),
}

/// The HTTP status of an error that carries one.
pub fn status_of(err: &GenesisMeshError) -> Option<u16> {
    Some(match err {
        GenesisMeshError::BadRequest { .. } => 400,
        GenesisMeshError::Unauthorized { .. } => 401,
        GenesisMeshError::NotFound { .. } => 404,
        GenesisMeshError::Validation { .. } => 422,
        GenesisMeshError::RateLimit { .. } => 429,
        GenesisMeshError::Http { status, .. } => *status,
        GenesisMeshError::ResponseBodyUnreadable { status, .. } => *status,
        _ => return None,
    })
}

/// Whether an HTTP error carries the NA's JSON error body: the SDK names
/// the code `unknown` when the body is not one (a proxy's page).
fn na_body(err: &GenesisMeshError) -> bool {
    err.code() != "unknown"
}

/// A gateway's own failure statuses (nginx, load balancers, Cloudflare).
fn gateway_status(status: u16) -> bool {
    matches!(status, 502..=504 | 520..=527)
}

/// What a failed request to the NA means.
pub fn classify(err: &GenesisMeshError) -> Answer {
    if let GenesisMeshError::Network(_) = err {
        return match evaluation_failure(err) {
            Some(failure) => Answer::Unreachable(failure),
            // A request that could not be built never left the device.
            None => Answer::Refused,
        };
    }
    let Some(status) = status_of(err) else {
        // Verification failures, JSON this crate refuses: final.
        return Answer::Refused;
    };
    if matches!(err, GenesisMeshError::ResponseBodyUnreadable { .. }) {
        // The NA answered; it may have acted.
        return Answer::Refused;
    }
    if gateway_status(status) && !na_body(err) {
        return Answer::Unreachable(EvaluationFailure::ServerError);
    }
    if status == 429 || (500..=599).contains(&status) {
        return Answer::Throttled {
            status,
            code: err.code().to_owned(),
        };
    }
    Answer::Refused
}

/// The NA's state as `/v1/status` shows it, from the last exchange.
pub fn na_state(last: Option<&Answer>) -> &'static str {
    match last {
        None | Some(Answer::Refused) => "answering",
        Some(Answer::Throttled { status: 429, .. }) => "throttled",
        Some(Answer::Throttled { .. }) => "failing",
        Some(Answer::Unreachable(_)) => "unreachable",
    }
}

/// One grant as the decision order sees it: whether a holder can act within
/// it, and why it does not cover the request or cannot be used now (the
/// holder's check, or for a grant without a holder its envelope).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// A holder can act within it.
    pub held: bool,
    /// The check's code, `None` when the next use may be made.
    pub code: Option<String>,
}

/// The codes after which a grant can no longer be used (`GrantCheck::ends_use`).
const ENDED: [&str; 5] = [
    "grant_revoked",
    "grant_expired",
    "grant_budget_exhausted",
    "grant_bearer_key_retired",
    "grant_time_token_exhausted",
];

/// Which grant decides a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantChoice {
    /// Act within the candidate at this index.
    Use(usize),
    /// A grant names the capability but does not cover the request.
    Outside(String),
    /// A covering grant can no longer be used (its code).
    Ended(String),
    /// No grant names the capability.
    None,
}

/// Choose among the candidates, soonest end first. A covering grant that
/// can be used wins; then a grant that names the capability but does not
/// cover the request refuses it (`outside_grant`), even over an ended one;
/// then an ended covering grant gives its code. A spent time token counts
/// as usable (the holder asks for a fresh one). With the device's clock
/// behind the NA's, a grant "not valid yet" is taken as ended, never as
/// not covering, so break-glass stays possible.
pub fn choose(candidates: &[Candidate], clock_behind: bool) -> GrantChoice {
    let mut usable = None;
    let mut ended = None;
    let mut outside = None;
    for (index, candidate) in candidates.iter().enumerate() {
        match candidate.code.as_deref() {
            None if candidate.held => {
                return GrantChoice::Use(index);
            }
            // Covers the request, but no holder can act within it.
            None => {}
            Some("grant_time_token_exhausted") if candidate.held => {
                usable.get_or_insert(index);
            }
            Some("grant_capability_mismatch") => {}
            Some("grant_use_outside_validity") if clock_behind => {
                ended.get_or_insert_with(|| "grant_use_outside_validity".to_owned());
            }
            Some(code) if ENDED.contains(&code) => {
                ended.get_or_insert_with(|| code.to_owned());
            }
            Some(code) => {
                outside.get_or_insert_with(|| code.to_owned());
            }
        }
    }
    match (usable, outside, ended) {
        (Some(index), _, _) => GrantChoice::Use(index),
        (None, Some(code), _) => GrantChoice::Outside(code),
        (None, None, Some(code)) => GrantChoice::Ended(code),
        (None, None, None) => GrantChoice::None,
    }
}

/// The grant code a request goes on with when no grant acted: a covered
/// request under a stale snapshot is `snapshot_stale`.
pub fn grant_code(choice: &GrantChoice, fresh: bool) -> Option<String> {
    match choice {
        GrantChoice::Outside(_) => None,
        GrantChoice::Use(_) | GrantChoice::Ended(_) if !fresh => Some("snapshot_stale".into()),
        GrantChoice::Ended(code) => Some(code.clone()),
        GrantChoice::Use(_) | GrantChoice::None => Some("no_grant".into()),
    }
}

/// What follows when no grant acted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Next {
    /// Refuse with this code and its details.
    Refuse(&'static str, Value),
    /// Ask the NA (it was not asked yet), then break-glass if it does not answer.
    Ask,
    /// Break the glass: the NA did not answer.
    BreakGlass(EvaluationFailure),
}

/// After the grants: the NA throttling or failing refuses (never
/// break-glass); without a justification or an attestation, refuse; with
/// an expired certificate the NA is not asked; otherwise break the glass if
/// the NA did not answer, or ask it.
pub fn after_grants(
    asked: Option<&Answer>,
    grant_code: &str,
    justification: bool,
    attestation: bool,
    certificate_expired: bool,
) -> Next {
    if let Some(Answer::Throttled { status, code }) = asked {
        return Next::Refuse(
            "na_refused",
            serde_json::json!({"na_code": code, "na_status": status, "grant_code": grant_code}),
        );
    }
    if !justification {
        return Next::Refuse(
            "justification_required",
            serde_json::json!({"grant_code": grant_code}),
        );
    }
    if !attestation {
        return Next::Refuse(
            "no_attestation",
            serde_json::json!({"grant_code": grant_code}),
        );
    }
    if certificate_expired {
        return Next::BreakGlass(EvaluationFailure::NetworkError);
    }
    match asked {
        Some(Answer::Unreachable(failure)) => Next::BreakGlass(*failure),
        _ => Next::Ask,
    }
}

/// The snapshot's freshness at `age` seconds: `(fresh, clock_behind)`. A
/// device clock more than `skew` seconds behind the NA's signing time makes
/// it stale.
pub fn freshness(age: Option<i64>, max_age: i64, skew: i64) -> (bool, bool) {
    match age {
        None => (false, false),
        Some(age) if age < -skew => (false, true),
        Some(age) => (age <= max_age, false),
    }
}

/// Whether a `/node/state` answer says the node's executor key is retired.
pub fn executor_key_retired(node_state: &Value) -> bool {
    !node_state["executor_key"]["retired_at"].is_null()
}

#[cfg(test)]
mod tests {
    use super::*;
    use genesis_mesh_sdk::json;

    fn http(status: u16, code: &str) -> GenesisMeshError {
        GenesisMeshError::Http {
            status,
            message: "m".into(),
            code: code.into(),
        }
    }

    #[test]
    fn three_answer_classes() {
        let cases: Vec<(GenesisMeshError, Answer)> = vec![
            // The NA's refusals: final.
            (
                GenesisMeshError::Unauthorized {
                    message: "m".into(),
                    code: "node_auth_failed".into(),
                },
                Answer::Refused,
            ),
            (http(403, "node_attestation_foreign"), Answer::Refused),
            (http(409, "conflict"), Answer::Refused),
            (
                GenesisMeshError::DecisionVerification("invalid_signature".into()),
                Answer::Refused,
            ),
            // The NA throttling or failing, with its own body.
            (
                GenesisMeshError::RateLimit {
                    message: "m".into(),
                    code: "rate_limit_exceeded".into(),
                },
                Answer::Throttled {
                    status: 429,
                    code: "rate_limit_exceeded".into(),
                },
            ),
            (
                http(503, "evidence_store_unavailable"),
                Answer::Throttled {
                    status: 503,
                    code: "evidence_store_unavailable".into(),
                },
            ),
            (
                http(500, "internal_error"),
                Answer::Throttled {
                    status: 500,
                    code: "internal_error".into(),
                },
            ),
            // A proxy's own page: unreachable.
            (
                http(502, "unknown"),
                Answer::Unreachable(EvaluationFailure::ServerError),
            ),
            (
                http(504, "unknown"),
                Answer::Unreachable(EvaluationFailure::ServerError),
            ),
            (
                http(522, "unknown"),
                Answer::Unreachable(EvaluationFailure::ServerError),
            ),
            // A 500 page without the NA's body is the NA failing, not a gateway.
            (
                http(500, "unknown"),
                Answer::Throttled {
                    status: 500,
                    code: "unknown".into(),
                },
            ),
        ];
        for (err, expected) in cases {
            assert_eq!(classify(&err), expected, "{err}");
        }
        assert_eq!(na_state(None), "answering");
        assert_eq!(
            na_state(Some(&Answer::Throttled {
                status: 429,
                code: "x".into()
            })),
            "throttled"
        );
        assert_eq!(
            na_state(Some(&Answer::Throttled {
                status: 503,
                code: "x".into()
            })),
            "failing"
        );
        assert_eq!(
            na_state(Some(&Answer::Unreachable(EvaluationFailure::Timeout))),
            "unreachable"
        );
    }

    fn held(code: Option<&str>) -> Candidate {
        Candidate {
            held: true,
            code: code.map(str::to_owned),
        }
    }

    #[test]
    fn which_grant_decides() {
        let cases: Vec<(Vec<Candidate>, bool, GrantChoice)> = vec![
            (vec![], false, GrantChoice::None),
            (
                vec![held(Some("grant_capability_mismatch"))],
                false,
                GrantChoice::None,
            ),
            (vec![held(None)], false, GrantChoice::Use(0)),
            // A covering usable grant wins over one that does not cover.
            (
                vec![held(Some("grant_envelope_mismatch")), held(None)],
                false,
                GrantChoice::Use(1),
            ),
            // Not covering wins over ended (the docs' rule).
            (
                vec![
                    held(Some("grant_expired")),
                    held(Some("grant_envelope_mismatch")),
                ],
                false,
                GrantChoice::Outside("grant_envelope_mismatch".into()),
            ),
            (
                vec![held(Some("grant_revoked"))],
                false,
                GrantChoice::Ended("grant_revoked".into()),
            ),
            // A spent time token: usable (the holder asks for a fresh one).
            (
                vec![held(Some("grant_time_token_exhausted"))],
                false,
                GrantChoice::Use(0),
            ),
            // Not valid yet: not covering, unless the clock is behind.
            (
                vec![held(Some("grant_use_outside_validity"))],
                false,
                GrantChoice::Outside("grant_use_outside_validity".into()),
            ),
            (
                vec![held(Some("grant_use_outside_validity"))],
                true,
                GrantChoice::Ended("grant_use_outside_validity".into()),
            ),
            // A grant without a holder still refuses what it does not cover.
            (
                vec![Candidate {
                    held: false,
                    code: Some("grant_envelope_mismatch".into()),
                }],
                false,
                GrantChoice::Outside("grant_envelope_mismatch".into()),
            ),
            (
                vec![Candidate {
                    held: false,
                    code: None,
                }],
                false,
                GrantChoice::None,
            ),
        ];
        for (candidates, clock_behind, expected) in cases {
            assert_eq!(
                choose(&candidates, clock_behind),
                expected,
                "{candidates:?} clock_behind={clock_behind}"
            );
        }
    }

    #[test]
    fn what_follows_the_grants() {
        let unreachable = Answer::Unreachable(EvaluationFailure::NetworkError);
        let throttled = Answer::Throttled {
            status: 429,
            code: "rate_limit_exceeded".into(),
        };
        // fresh/stale x covered/not/ended feed the grant code.
        assert_eq!(
            grant_code(&GrantChoice::Use(0), false).as_deref(),
            Some("snapshot_stale")
        );
        assert_eq!(
            grant_code(&GrantChoice::Ended("grant_expired".into()), false).as_deref(),
            Some("snapshot_stale")
        );
        assert_eq!(
            grant_code(&GrantChoice::Ended("grant_expired".into()), true).as_deref(),
            Some("grant_expired")
        );
        assert_eq!(
            grant_code(&GrantChoice::None, false).as_deref(),
            Some("no_grant")
        );
        assert_eq!(grant_code(&GrantChoice::Outside("x".into()), true), None);
        let cases: Vec<(Option<&Answer>, bool, bool, bool, Next)> = vec![
            // Throttled: refused, whatever the justification.
            (
                Some(&throttled),
                true,
                true,
                false,
                Next::Refuse(
                    "na_refused",
                    json!({"na_code": "rate_limit_exceeded", "na_status": 429, "grant_code": "no_grant"}),
                ),
            ),
            (
                None,
                false,
                true,
                false,
                Next::Refuse("justification_required", json!({"grant_code": "no_grant"})),
            ),
            (
                None,
                true,
                false,
                false,
                Next::Refuse("no_attestation", json!({"grant_code": "no_grant"})),
            ),
            (
                Some(&unreachable),
                true,
                true,
                false,
                Next::BreakGlass(EvaluationFailure::NetworkError),
            ),
            (None, true, true, false, Next::Ask),
            (
                None,
                true,
                true,
                true,
                Next::BreakGlass(EvaluationFailure::NetworkError),
            ),
        ];
        for (asked, justification, attestation, expired, expected) in cases {
            assert_eq!(
                after_grants(asked, "no_grant", justification, attestation, expired),
                expected
            );
        }
    }

    #[test]
    fn freshness_and_the_clock() {
        assert_eq!(freshness(None, 60, 300), (false, false));
        assert_eq!(freshness(Some(10), 60, 300), (true, false));
        assert_eq!(freshness(Some(61), 60, 300), (false, false));
        assert_eq!(freshness(Some(-100), 60, 300), (true, false));
        assert_eq!(freshness(Some(-301), 60, 300), (false, true));
        assert!(executor_key_retired(
            &json!({"executor_key": {"retired_at": "2026-10-14T00:00:00+00:00"}})
        ));
        assert!(!executor_key_retired(
            &json!({"executor_key": {"retired_at": null}})
        ));
    }
}
