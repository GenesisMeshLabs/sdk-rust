//! A record's own time picks the NA keys of a key history that may have
//! signed it (1.5.0). A record without that time is dated nowhere, so no key
//! of a history signs it, as the reference judges it: its models require the
//! time. Taking every key of the history instead let a succeeded key sign an
//! undated record that verified forever. A plain list of keys is still valid
//! at every time.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{Duration, Utc};
use genesis_mesh_sdk::{
    canonical::{anchor_canonical, attestation_canonical, policy_canonical, python_timestamp},
    json,
    key_history::{NaKey, NaKeyHistory, NaKeys},
    load_signing_key, public_key_from_seed, sign_canonical,
    verify::{verify_record, verify_record_for_present, verify_store_anchors, VerifyRecordOptions},
    Value,
};

const OLD_SEED: [u8; 32] = [3; 32];
const NEW_SEED: [u8; 32] = [9; 32];
/// The old key handed over three days ago: past any vouching horizon.
const SUCCEEDED_DAYS_AGO: i64 = 3;

fn key_of(seed: [u8; 32]) -> String {
    public_key_from_seed(&STANDARD.encode(seed)).unwrap()
}

fn signature(canonical: &str, seed: [u8; 32], key_id: &str) -> Value {
    sign_canonical(
        canonical,
        key_id,
        &load_signing_key(&STANDARD.encode(seed)).unwrap(),
    )
}

fn succeeded_at() -> i64 {
    (Utc::now() - Duration::days(SUCCEEDED_DAYS_AGO)).timestamp_micros()
}

fn history() -> NaKeyHistory {
    let succeeded = succeeded_at();
    NaKeyHistory {
        sovereign_id: "sovereign-c".into(),
        root_public_key: None,
        keys: vec![
            NaKey {
                key_sequence: 1,
                public_key: key_of(OLD_SEED),
                key_id: Some("na-1".into()),
                valid_from: None,
                succeeded_at: Some(succeeded),
                valid_to: None,
                valid_to_enforced: false,
            },
            NaKey {
                key_sequence: 2,
                public_key: key_of(NEW_SEED),
                key_id: Some("na-2".into()),
                valid_from: Some(succeeded),
                succeeded_at: None,
                valid_to: Some(succeeded + 365 * 86_400_000_000),
                valid_to_enforced: true,
            },
        ],
        succession_digests: vec![],
    }
}

fn days_ago(days: i64) -> Value {
    json!(python_timestamp(Utc::now() - Duration::days(days)))
}

fn attestation(issued_at: Value, seed: [u8; 32], key_id: &str) -> Value {
    let mut record = json!({
        "attestation_id": "00000000-0000-4000-8000-000000000810",
        "issuer_sovereign_id": "sovereign-c",
        "subject_id": "vendor-acme",
        "subject_public_key": null,
        "roles": ["role:client"],
        "status": "active",
        "issued_at": issued_at,
        "valid_from": days_ago(10),
        "expires_at": python_timestamp(Utc::now() + Duration::days(300)),
        "issued_by": key_id,
        "claims": {},
    });
    let canonical = attestation_canonical(&record).unwrap();
    record["signatures"] = json!([signature(&canonical, seed, key_id)]);
    record
}

fn policy(issued_at: Value, seed: [u8; 32], key_id: &str) -> Value {
    let mut record = json!({
        "policy_id": "00000000-0000-4000-8000-000000000820",
        "version": 1,
        "issuer_sovereign_id": "sovereign-c",
        "issued_by": key_id,
        "issued_at": issued_at,
        "valid_from": days_ago(10),
        "valid_until": python_timestamp(Utc::now() + Duration::days(300)),
        "selector": {"capabilities": ["secret.rotate"]},
        "gates": [],
        "description": "a policy",
    });
    let canonical = policy_canonical(&record).unwrap();
    record["signature"] = signature(&canonical, seed, key_id);
    record
}

fn anchor(anchored_at: Value, seed: [u8; 32], key_id: &str) -> Value {
    let mut record = json!({
        "anchor_sequence": 1,
        "store_sequence": 5,
        "entry_digest": "1".repeat(64),
        "anchored_at": anchored_at,
        "sovereign_id": "sovereign-c",
        "issued_by": key_id,
    });
    let canonical = anchor_canonical(&record).unwrap();
    record["signature"] = signature(&canonical, seed, key_id);
    record
}

fn with_history() -> VerifyRecordOptions {
    VerifyRecordOptions {
        key_history: Some(history()),
        ..VerifyRecordOptions::default()
    }
}

fn verified(kind: &str, record: &Value, options: &VerifyRecordOptions) -> bool {
    verify_record(kind, record, options).verified
}

#[test]
fn the_setup_verifies_a_dated_record_by_the_key_valid_at_its_time() {
    let options = with_history();
    for (kind, make) in [
        ("attestation", attestation as fn(_, _, _) -> _),
        ("policy", policy),
    ] {
        // The old key at a time it was valid, the new key now: verified.
        assert!(
            verified(kind, &make(days_ago(5), OLD_SEED, "na-1"), &options),
            "{kind} old"
        );
        assert!(
            verified(kind, &make(days_ago(0), NEW_SEED, "na-2"), &options),
            "{kind} new"
        );
        // The old key after its succession: refused by name.
        let late = verify_record(kind, &make(days_ago(1), OLD_SEED, "na-1"), &options);
        assert!(!late.verified, "{kind} late");
        assert_eq!(late.reason, "na_key_not_valid_at_time", "{kind}");
    }
}

#[test]
fn an_undated_record_is_signed_by_no_key_of_a_history() {
    let options = with_history();
    for (kind, make) in [
        ("attestation", attestation as fn(_, _, _) -> _),
        ("policy", policy),
    ] {
        for undated in [json!(null), json!("not a time"), json!(17)] {
            for (seed, key_id) in [(OLD_SEED, "na-1"), (NEW_SEED, "na-2")] {
                let record = make(undated.clone(), seed, key_id);
                let checked = verify_record(kind, &record, &options);
                assert!(
                    !checked.verified,
                    "{kind} {undated} by {key_id}: {checked:?}"
                );
                assert_eq!(
                    checked.reason, "invalid_signature",
                    "{kind} {undated} by {key_id}"
                );
                let present = verify_record_for_present(kind, &record, &options, Utc::now(), 0);
                assert!(
                    !present.verified,
                    "{kind} {undated} by {key_id} for the present"
                );
            }
        }
        // Absent altogether, as null.
        let mut record = make(json!(null), OLD_SEED, "na-1");
        record.as_object_mut().unwrap().remove("issued_at");
        assert!(
            !verified(kind, &record, &options),
            "{kind} without issued_at"
        );
    }
}

#[test]
fn a_list_of_keys_is_valid_at_every_time() {
    let options = VerifyRecordOptions {
        na_public_keys: vec![key_of(OLD_SEED)],
        ..VerifyRecordOptions::default()
    };
    for (kind, make) in [
        ("attestation", attestation as fn(_, _, _) -> _),
        ("policy", policy),
    ] {
        assert!(
            verified(kind, &make(json!(null), OLD_SEED, "na-1"), &options),
            "{kind}"
        );
    }
}

#[test]
fn at_record_gives_an_undated_record_no_key_of_a_history() {
    let keys = NaKeys::History(history());
    let now = Utc::now().timestamp_micros();
    assert!(keys.at_record(None).is_empty());
    assert!(keys.vouching_at(None, now, 0).is_empty());
    // Every key is still every key, and a dated record its keys.
    assert_eq!(keys.all().len(), 2);
    assert_eq!(keys.at(None).len(), 2);
    assert_eq!(keys.at_record(Some(now)), vec![key_of(NEW_SEED)]);
    // A list of keys is valid at every time.
    let any = NaKeys::Any(vec![key_of(OLD_SEED)]);
    assert_eq!(any.at_record(None), vec![key_of(OLD_SEED)]);
    assert_eq!(any.vouching_at(None, now, 0), vec![key_of(OLD_SEED)]);
}

#[test]
fn an_undated_anchor_is_signed_by_no_key_of_a_history() {
    let keys = NaKeys::History(history());
    let dated = verify_store_anchors(&[anchor(days_ago(5), OLD_SEED, "na-1")], Some(&keys), None);
    assert!(dated.verified, "{dated:?}");
    // An anchor's canonical form refuses an `anchored_at` that is not a time,
    // so null is the undated anchor a key can sign.
    for undated in [json!(null)] {
        for (seed, key_id) in [(OLD_SEED, "na-1"), (NEW_SEED, "na-2")] {
            let checked =
                verify_store_anchors(&[anchor(undated.clone(), seed, key_id)], Some(&keys), None);
            assert!(!checked.verified, "{undated} by {key_id}");
            assert_eq!(
                checked.failures[0].reason, "anchor_invalid_signature",
                "{undated} by {key_id}"
            );
        }
    }
    // A list of keys is valid at every time.
    let any = NaKeys::Any(vec![key_of(OLD_SEED)]);
    assert!(
        verify_store_anchors(&[anchor(json!(null), OLD_SEED, "na-1")], Some(&any), None).verified
    );
}
