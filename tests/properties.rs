//! Property tests for the strict JSON reader and the canonical form
//! (proptest): what every implementation must read alike is read back
//! exactly, and what they read differently is refused by its reason. They
//! complement the conformance vectors (`canonical`), which fix the cases the
//! core chose; these draw new inputs on every run. `PROPTEST_CASES` raises
//! the count (256 by default).

use genesis_mesh_sdk::{canonical_json, check_strict_json, parse_strict_json, GenesisMeshError};
use proptest::prelude::*;
use serde_json::{Map, Number, Value};

/// The reason strict JSON gives for refusing `text`, or `""` when it reads it.
fn refusal(text: &str) -> String {
    match check_strict_json(text) {
        Ok(()) => String::new(),
        Err(GenesisMeshError::StrictJson { reason, .. }) => reason,
        Err(other) => panic!("not a strict JSON refusal: {other:?}"),
    }
}

/// Any JSON value strict JSON accepts: finite numbers, integers within 64
/// bits, any Unicode text, nested at most a few levels.
fn value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(Value::from),
        any::<u64>().prop_map(Value::from),
        any::<f64>()
            .prop_filter("finite", |f| f.is_finite())
            .prop_map(|f| Value::Number(Number::from_f64(f).unwrap())),
        any::<String>().prop_map(Value::String),
    ];
    leaf.prop_recursive(6, 64, 8, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..8).prop_map(Value::Array),
            prop::collection::btree_map(any::<String>(), inner, 0..8)
                .prop_map(|m| Value::Object(m.into_iter().collect::<Map<_, _>>())),
        ]
    })
}

/// A non-empty object, with its keys.
fn object() -> impl Strategy<Value = Map<String, Value>> {
    prop::collection::btree_map(any::<String>(), value(), 1..8)
        .prop_map(|m| m.into_iter().collect::<Map<_, _>>())
}

/// An object's JSON text with its members in reverse key order.
fn reversed_text(map: &Map<String, Value>) -> String {
    let members: Vec<String> = map
        .iter()
        .rev()
        .map(|(k, v)| format!("{}:{}", serde_json::to_string(k).unwrap(), v))
        .collect();
    format!("{{{}}}", members.join(","))
}

proptest! {
    // Failures print their minimal input; nothing is written to the tree.
    #![proptest_config(ProptestConfig {
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    // ── Round trip ──────────────────────────────────────────────────────

    #[test]
    fn json_text_reads_back_as_its_value(v in value()) {
        let compact = serde_json::to_string(&v).unwrap();
        prop_assert_eq!(parse_strict_json(&compact).unwrap(), v.clone());
        let pretty = serde_json::to_string_pretty(&v).unwrap();
        prop_assert_eq!(parse_strict_json(&pretty).unwrap(), v);
    }

    // ── Canonical form ──────────────────────────────────────────────────

    #[test]
    fn the_canonical_form_is_ascii_strict_json_of_the_same_value(v in value()) {
        let canonical = canonical_json(&v).unwrap();
        prop_assert!(canonical.is_ascii(), "{}", canonical);
        let read = parse_strict_json(&canonical).unwrap();
        prop_assert_eq!(&read, &v);
        // Idempotent: the canonical form of what it reads is itself.
        prop_assert_eq!(canonical_json(&read).unwrap(), canonical);
    }

    #[test]
    fn the_canonical_form_ignores_member_order(map in object()) {
        let forward = Value::Object(map.clone());
        let reversed = parse_strict_json(&reversed_text(&map)).unwrap();
        prop_assert_eq!(canonical_json(&reversed).unwrap(), canonical_json(&forward).unwrap());
    }

    #[test]
    fn the_canonical_form_has_no_whitespace_outside_strings(v in value()) {
        let canonical = canonical_json(&v).unwrap();
        // Strings are escaped ASCII, so a space can only be inside one:
        // removing the strings leaves no whitespace.
        let mut outside = String::new();
        let mut in_string = false;
        let mut escaped = false;
        for c in canonical.chars() {
            if in_string {
                if escaped { escaped = false } else if c == '\\' { escaped = true } else if c == '"' { in_string = false }
            } else if c == '"' {
                in_string = true;
            } else {
                outside.push(c);
            }
        }
        prop_assert!(!outside.chars().any(char::is_whitespace), "{}", canonical);
    }

    // ── Duplicate keys ──────────────────────────────────────────────────

    #[test]
    fn a_duplicate_key_is_refused(map in object(), pick in any::<prop::sample::Index>(), again in value()) {
        let key = map.keys().nth(pick.index(map.len())).unwrap().clone();
        let text = reversed_text(&map);
        let duplicated = format!(
            "{},{}:{}}}",
            &text[..text.len() - 1],
            serde_json::to_string(&key).unwrap(),
            again
        );
        prop_assert_eq!(refusal(&duplicated), "duplicate_key");
        // Nested anywhere, the same.
        prop_assert_eq!(refusal(&format!("[{{\"a\":{duplicated}}}]")), "duplicate_key");
    }

    #[test]
    fn keys_equal_only_after_unescaping_are_duplicates(key in "[a-z]{1,8}") {
        let escaped: String = key.chars().map(|c| format!("\\u{:04x}", c as u32)).collect();
        let text = format!("{{\"{key}\":1,\"{escaped}\":2}}");
        prop_assert_eq!(refusal(&text), "duplicate_key");
    }

    // ── Number lexemes ──────────────────────────────────────────────────

    #[test]
    fn integers_within_64_bits_read_exactly(n in any::<i64>(), m in any::<u64>()) {
        prop_assert_eq!(parse_strict_json(&n.to_string()).unwrap(), Value::from(n));
        prop_assert_eq!(parse_strict_json(&m.to_string()).unwrap(), Value::from(m));
    }

    #[test]
    fn integers_beyond_64_bits_are_refused(
        over in (u64::MAX as u128 + 1)..=u128::MAX,
        under in i128::MIN..(i64::MIN as i128),
    ) {
        prop_assert_eq!(refusal(&over.to_string()), "integer_out_of_range");
        prop_assert_eq!(refusal(&under.to_string()), "integer_out_of_range");
    }

    #[test]
    fn a_float_lexeme_reads_as_its_nearest_double(
        negative in any::<bool>(),
        int in "0|[1-9][0-9]{0,15}",
        frac in "[0-9]{1,17}",
        exp in ("[eE]", "[+-]?", -280_i32..280),
        // A fraction, an exponent, or both.
        parts in prop_oneof![Just((true, false)), Just((false, true)), Just((true, true))],
    ) {
        let frac = parts.0.then_some(frac);
        let exp = parts.1.then_some(exp);
        let mut lexeme = format!("{}{int}", if negative { "-" } else { "" });
        if let Some(f) = &frac {
            lexeme.push('.');
            lexeme.push_str(f);
        }
        if let Some((e, sign, n)) = &exp {
            let sign = if *n < 0 { "-" } else { sign.as_str() };
            lexeme.push_str(&format!("{e}{sign}{}", n.unsigned_abs()));
        }
        let read = parse_strict_json(&lexeme).unwrap();
        prop_assert_eq!(read.as_f64(), Some(lexeme.parse::<f64>().unwrap()), "{}", lexeme);
    }

    #[test]
    fn an_exponent_past_the_double_range_is_refused(digits in "[1-9][0-9]{0,5}", exp in 400_u32..100_000) {
        prop_assert_eq!(refusal(&format!("{digits}e{exp}")), "non_finite_number");
        prop_assert_eq!(refusal(&format!("-{digits}.5E+{exp}")), "non_finite_number");
    }

    #[test]
    fn malformed_number_lexemes_are_refused(digits in "[0-9]{1,6}") {
        for text in [
            format!("0{digits}"),
            format!("+{digits}"),
            format!(".{digits}"),
            format!("{digits}."),
            format!("{digits}e"),
            format!("-.{digits}"),
            format!("{digits}.e1"),
        ] {
            prop_assert_eq!(refusal(&text), "invalid_json", "{}", text);
        }
    }

    // ── Unicode ─────────────────────────────────────────────────────────

    #[test]
    fn any_text_reads_back_escaped_or_not(s in any::<String>()) {
        prop_assert_eq!(parse_strict_json(&serde_json::to_string(&s).unwrap()).unwrap(), Value::String(s.clone()));
        let escaped: String = s
            .encode_utf16()
            .map(|unit| format!("\\u{unit:04x}"))
            .collect();
        prop_assert_eq!(parse_strict_json(&format!("\"{escaped}\"")).unwrap(), Value::String(s));
    }

    #[test]
    fn a_lone_surrogate_is_refused(unit in 0xd800_u32..0xe000, before in "[a-z]{0,4}", after in "[a-z]{0,4}") {
        let text = format!("\"{before}\\u{unit:04x}{after}\"");
        prop_assert_eq!(refusal(&text), "lone_surrogate");
    }

    #[test]
    fn a_reversed_surrogate_pair_is_refused(c in any::<char>().prop_filter("outside the BMP", |c| (*c as u32) > 0xffff)) {
        let mut units = [0_u16; 2];
        c.encode_utf16(&mut units);
        let text = format!("\"\\u{:04x}\\u{:04x}\"", units[1], units[0]);
        prop_assert_eq!(refusal(&text), "lone_surrogate");
    }

    #[test]
    fn a_control_character_must_be_escaped(c in 0_u8..0x20) {
        let raw = format!("\"a{}b\"", c as char);
        prop_assert_eq!(refusal(&raw), "invalid_json");
        let escaped = format!("\"a\\u{c:04x}b\"");
        prop_assert_eq!(parse_strict_json(&escaped).unwrap(), Value::String(format!("a{}b", c as char)));
    }

    // ── Nesting ─────────────────────────────────────────────────────────

    #[test]
    fn nesting_past_64_levels_is_refused(depth in 1_usize..160, object in any::<bool>()) {
        let (open, close) = if object { ("{\"k\":", "}") } else { ("[", "]") };
        let text = format!("{}0{}", open.repeat(depth), close.repeat(depth));
        let expected = if depth > 64 { "invalid_json" } else { "" };
        prop_assert_eq!(refusal(&text), expected, "depth {}", depth);
    }
}

#[test]
fn the_integer_negative_zero_is_refused_and_the_float_is_not() {
    assert_eq!(refusal("-0"), "negative_zero");
    assert_eq!(refusal("[-0]"), "negative_zero");
    assert_eq!(refusal("-0.0"), "");
}
