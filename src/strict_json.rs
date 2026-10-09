//! Strict JSON input (v1.2.0): refuse what parsers read differently.
//!
//! The canonical form of a signed record is computed from parsed JSON, so
//! every implementation must parse a record to the same value. Some JSON does
//! not parse alike: `serde_json` keeps the last of two duplicate keys where
//! .NET keeps both, and reads an integer beyond 64 bits as a float, which the
//! other implementations keep exact. Such input is refused here, as in every
//! implementation, by a named reason (the conformance suite `canonical`):
//! `invalid_json` (not JSON, including `NaN`, a byte order mark, text that is
//! not UTF-8, and arrays or objects nested more than 64 deep), `duplicate_key`,
//! `non_finite_number` (`1e400`), `integer_out_of_range` (outside
//! `-2**63 .. 2**64 - 1`), `negative_zero` (the integer `-0`) and
//! `lone_surrogate`.

use std::collections::HashSet;

use serde_json::Value;

use crate::errors::{GenesisMeshError, Result};

fn refuse(reason: &str, detail: impl Into<String>) -> GenesisMeshError {
    GenesisMeshError::StrictJson {
        reason: reason.to_owned(),
        detail: detail.into(),
    }
}

struct Scanner<'a> {
    src: &'a str,
    text: &'a [u8],
    at: usize,
    depth: usize,
}

/// Arrays and objects nested deeper are refused as `invalid_json`, as in every
/// implementation (.NET's reader stops there by default).
pub const MAX_DEPTH: usize = 64;

impl Scanner<'_> {
    fn peek(&self) -> Option<u8> {
        self.text.get(self.at).copied()
    }

    fn space(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn hex4(&mut self) -> Result<u16> {
        let digits = self
            .text
            .get(self.at..self.at + 4)
            .and_then(|h| std::str::from_utf8(h).ok())
            .filter(|h| h.bytes().all(|b| b.is_ascii_hexdigit()))
            .ok_or_else(|| refuse("invalid_json", "a malformed \\u escape"))?;
        self.at += 4;
        Ok(u16::from_str_radix(digits, 16).expect("four hex digits"))
    }

    /// A string at `at` (on its quote); its text when `keep`, so keys can be compared.
    fn string(&mut self, keep: bool) -> Result<String> {
        self.at += 1;
        let mut units: Vec<u16> = Vec::new();
        let mut pending: Option<u16> = None;
        loop {
            let byte = self
                .peek()
                .ok_or_else(|| refuse("invalid_json", "a string is not closed"))?;
            let mut buf = [0_u16; 2];
            let unit_list: &[u16] = match byte {
                b'"' => {
                    self.at += 1;
                    break;
                }
                0x00..=0x1f => {
                    return Err(refuse("invalid_json", "a control character in a string"))
                }
                b'\\' => {
                    let escape = self.text.get(self.at + 1).copied();
                    self.at += 2;
                    buf[0] = match escape {
                        Some(b'u') => self.hex4()?,
                        Some(b'"') => 0x22,
                        Some(b'\\') => 0x5c,
                        Some(b'/') => 0x2f,
                        Some(b'b') => 8,
                        Some(b'f') => 12,
                        Some(b'n') => 10,
                        Some(b'r') => 13,
                        Some(b't') => 9,
                        _ => return Err(refuse("invalid_json", "an unknown escape")),
                    };
                    &buf[..1]
                }
                _ => {
                    // `at` is always on a character boundary of the source text.
                    let c = self.src[self.at..].chars().next().expect("a character");
                    self.at += c.len_utf8();
                    c.encode_utf16(&mut buf)
                }
            };
            for &unit in unit_list {
                if let Some(high) = pending.take() {
                    if !(0xdc00..=0xdfff).contains(&unit) {
                        return Err(refuse(
                            "lone_surrogate",
                            "a high surrogate without its low half",
                        ));
                    }
                    if keep {
                        units.extend([high, unit]);
                    }
                } else if (0xd800..=0xdbff).contains(&unit) {
                    pending = Some(unit);
                } else if (0xdc00..=0xdfff).contains(&unit) {
                    return Err(refuse(
                        "lone_surrogate",
                        "a low surrogate without its high half",
                    ));
                } else if keep {
                    units.push(unit);
                }
            }
        }
        if pending.is_some() {
            return Err(refuse(
                "lone_surrogate",
                "a high surrogate without its low half",
            ));
        }
        Ok(String::from_utf16(&units).unwrap_or_default())
    }

    fn number(&mut self) -> Result<()> {
        let start = self.at;
        let digits = |s: &mut Self| {
            let from = s.at;
            while matches!(s.peek(), Some(b'0'..=b'9')) {
                s.at += 1;
            }
            s.at > from
        };
        if self.peek() == Some(b'-') {
            self.at += 1;
        }
        match self.peek() {
            Some(b'0') => self.at += 1,
            Some(b'1'..=b'9') => {
                digits(self);
            }
            _ => return Err(refuse("invalid_json", "a malformed number")),
        }
        let mut integer = true;
        if self.peek() == Some(b'.') {
            self.at += 1;
            integer = false;
            if !digits(self) {
                return Err(refuse("invalid_json", "a malformed number"));
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.at += 1;
            integer = false;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.at += 1;
            }
            if !digits(self) {
                return Err(refuse("invalid_json", "a malformed number"));
            }
        }
        let literal = std::str::from_utf8(&self.text[start..self.at]).expect("ASCII");
        if integer {
            if literal == "-0" {
                return Err(refuse("negative_zero", "the integer -0"));
            }
            if literal.parse::<i64>().is_err() && literal.parse::<u64>().is_err() {
                return Err(refuse(
                    "integer_out_of_range",
                    format!("{literal} is outside the 64-bit range"),
                ));
            }
        } else if !literal.parse::<f64>().is_ok_and(f64::is_finite) {
            return Err(refuse(
                "non_finite_number",
                format!("{literal} overflows a 64-bit float"),
            ));
        }
        Ok(())
    }

    fn value(&mut self) -> Result<()> {
        self.space();
        match self.peek() {
            Some(b'{') => {
                self.nest()?;
                self.at += 1;
                self.space();
                if self.peek() == Some(b'}') {
                    self.at += 1;
                    self.depth -= 1;
                    return Ok(());
                }
                let mut keys = HashSet::new();
                loop {
                    self.space();
                    if self.peek() != Some(b'"') {
                        return Err(refuse("invalid_json", "expected a key"));
                    }
                    let key = self.string(true)?;
                    if !keys.insert(key.clone()) {
                        return Err(refuse(
                            "duplicate_key",
                            format!("key {key:?} appears twice"),
                        ));
                    }
                    self.space();
                    if self.peek() != Some(b':') {
                        return Err(refuse("invalid_json", "expected \":\""));
                    }
                    self.at += 1;
                    self.value()?;
                    self.space();
                    match self.peek() {
                        Some(b',') => self.at += 1,
                        Some(b'}') => {
                            self.at += 1;
                            self.depth -= 1;
                            return Ok(());
                        }
                        _ => return Err(refuse("invalid_json", "expected \",\" or \"}\"")),
                    }
                }
            }
            Some(b'[') => {
                self.nest()?;
                self.at += 1;
                self.space();
                if self.peek() == Some(b']') {
                    self.at += 1;
                    self.depth -= 1;
                    return Ok(());
                }
                loop {
                    self.value()?;
                    self.space();
                    match self.peek() {
                        Some(b',') => self.at += 1,
                        Some(b']') => {
                            self.at += 1;
                            self.depth -= 1;
                            return Ok(());
                        }
                        _ => return Err(refuse("invalid_json", "expected \",\" or \"]\"")),
                    }
                }
            }
            Some(b'"') => self.string(false).map(|_| ()),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => {
                for literal in [&b"true"[..], b"false", b"null"] {
                    if self.text[self.at..].starts_with(literal) {
                        self.at += literal.len();
                        return Ok(());
                    }
                }
                Err(refuse("invalid_json", "an unexpected token"))
            }
        }
    }

    fn nest(&mut self) -> Result<()> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(refuse(
                "invalid_json",
                format!("arrays or objects nested more than {MAX_DEPTH} deep"),
            ));
        }
        Ok(())
    }
}

/// `Ok` when `text` is JSON every implementation reads alike; otherwise
/// [`GenesisMeshError::StrictJson`] with the reason.
pub fn check_strict_json(text: &str) -> Result<()> {
    let mut scanner = Scanner {
        src: text,
        text: text.as_bytes(),
        at: 0,
        depth: 0,
    };
    scanner.value()?;
    scanner.space();
    if scanner.at != scanner.text.len() {
        return Err(refuse("invalid_json", "text after the value"));
    }
    Ok(())
}

/// Parse JSON read strictly ([`check_strict_json`]), for a record that will
/// be verified or digested.
pub fn parse_strict_json(text: &str) -> Result<Value> {
    check_strict_json(text)?;
    Ok(serde_json::from_str(text)?)
}

/// [`parse_strict_json`] for bytes, which must be UTF-8.
pub(crate) fn parse_strict_json_bytes(bytes: &[u8]) -> Result<Value> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| refuse("invalid_json", "text that is not UTF-8"))?;
    parse_strict_json(text)
}
