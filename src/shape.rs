//! Structural checks of signed JSON (no coercion or mutation): the
//! combinators the record validators are built from, shared by `verify`
//! and the record modules (`remediation`) so neither imports the other.

use serde_json::Value;

use crate::canonical::parse_timestamp;

pub(crate) type Check = Box<dyn Fn(Option<&Value>) -> bool + Send + Sync>;

const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

pub(crate) fn string() -> Check {
    Box::new(|v| matches!(v, Some(Value::String(_))))
}
pub(crate) fn boolean() -> Check {
    Box::new(|v| matches!(v, Some(Value::Bool(_))))
}
pub(crate) fn int_where(predicate: fn(i64) -> bool) -> Check {
    Box::new(move |v| {
        v.and_then(Value::as_i64)
            .is_some_and(|n| n.abs() <= MAX_SAFE_INTEGER && predicate(n))
    })
}
pub(crate) fn integer() -> Check {
    int_where(|_| true)
}
pub(crate) fn positive() -> Check {
    int_where(|n| n > 0)
}
pub(crate) fn nonnegative() -> Check {
    int_where(|n| n >= 0)
}
pub(crate) fn object() -> Check {
    Box::new(|v| matches!(v, Some(Value::Object(_))))
}
pub(crate) fn timestamp() -> Check {
    Box::new(|v| {
        v.and_then(Value::as_str)
            .is_some_and(|s| parse_timestamp(s).is_ok())
    })
}
pub(crate) fn nullable(check: Check) -> Check {
    Box::new(move |v| matches!(v, Some(Value::Null)) || check(v))
}
pub(crate) fn optional(check: Check) -> Check {
    Box::new(move |v| v.is_none() || check(v))
}
pub(crate) fn array(check: Check) -> Check {
    Box::new(
        move |v| matches!(v, Some(Value::Array(items)) if items.iter().all(|i| check(Some(i)))),
    )
}
pub(crate) fn one_of(values: &'static [&'static str]) -> Check {
    Box::new(move |v| {
        v.and_then(Value::as_str)
            .is_some_and(|s| values.contains(&s))
    })
}
pub(crate) fn dictionary(check: Check) -> Check {
    Box::new(move |v| matches!(v, Some(Value::Object(map)) if map.values().all(|i| check(Some(i)))))
}
pub(crate) fn shape(fields: Vec<(&'static str, Check)>, exact: bool) -> Check {
    Box::new(move |v| {
        let Some(Value::Object(map)) = v else {
            return false;
        };
        fields.iter().all(|(key, check)| check(map.get(*key)))
            && (!exact || map.keys().all(|k| fields.iter().any(|(f, _)| f == k)))
    })
}
pub(crate) fn signature() -> Check {
    nullable(shape(vec![("key_id", string()), ("sig", string())], false))
}
/// Absent, `null` (read as absent) or valid. Since 1.3.1 also for a field
/// the reference always writes, `null` when it has no value: a record without
/// it is then refused by its signature or its form, as the reference refuses
/// it, not as `payload_invalid`.
pub(crate) fn absent(check: Check) -> Check {
    optional(nullable(check))
}
/// A string of `min..=max` characters.
pub(crate) fn bounded(max: usize, min: usize) -> Check {
    Box::new(move |v| {
        v.and_then(Value::as_str)
            .is_some_and(|s| (min..=max).contains(&s.chars().count()))
    })
}
pub(crate) fn sha256() -> Check {
    bounded(64, 64)
}
pub(crate) fn action() -> Check {
    one_of(&["create", "rotate", "revoke", "update", "delete"])
}
pub(crate) fn verdict() -> Check {
    one_of(&["allow", "deny", "indeterminate"])
}
/// v1.3.0 records' timestamps are UTC, as the reference requires.
pub(crate) fn utc_timestamp() -> Check {
    Box::new(|v| {
        v.and_then(Value::as_str).is_some_and(|s| {
            parse_timestamp(s).is_ok()
                && (s.ends_with('Z') || s.ends_with("+00:00") || s.ends_with("-00:00"))
        })
    })
}
/// A field the reference fills when absent: left out, the record is not in
/// the form the reference writes (`non_canonical_form`), not malformed.
pub(crate) fn filled(check: Check) -> Check {
    optional(check)
}

pub(crate) fn present(record: &Value, key: &str) -> bool {
    record.get(key).is_some_and(|v| !v.is_null())
}

pub(crate) fn str_field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

/// A validator: `$name(value)` builds its check once, on first use.
macro_rules! validator {
    ($vis:vis $name:ident, $build:expr) => {
        $vis fn $name(value: Option<&serde_json::Value>) -> bool {
            static CHECK: std::sync::OnceLock<$crate::shape::Check> =
                std::sync::OnceLock::new();
            CHECK.get_or_init(|| $build)(value)
        }
    };
}
pub(crate) use validator;
