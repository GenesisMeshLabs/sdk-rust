//! JSON lines on stderr: `ts`, `level`, `event` and `fields`. Never seeds or
//! keys, invite tokens, local tokens, parameter values or justification text.

use std::{
    io::Write as _,
    sync::atomic::{AtomicU8, Ordering},
};

use chrono::{SecondsFormat, Utc};
use serde_json::{json, Value};

use crate::config::Level;

static LEVEL: AtomicU8 = AtomicU8::new(1);

fn rank(level: Level) -> u8 {
    match level {
        Level::Debug => 0,
        Level::Info => 1,
        Level::Warn => 2,
        Level::Error => 3,
    }
}

/// Log at `level` and above from now on.
pub fn set_level(level: Level) {
    LEVEL.store(rank(level), Ordering::Relaxed);
}

/// One log line.
pub fn log(level: Level, event: &str, fields: Value) {
    if rank(level) < LEVEL.load(Ordering::Relaxed) {
        return;
    }
    let line = json!({
        "ts": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        "level": level.name(),
        "event": event,
        "fields": fields,
    });
    let mut err = std::io::stderr().lock();
    let _ = writeln!(err, "{line}");
}

/// Log at info.
pub fn info(event: &str, fields: Value) {
    log(Level::Info, event, fields);
}

/// Log at warn.
pub fn warn(event: &str, fields: Value) {
    log(Level::Warn, event, fields);
}

/// Log at error.
pub fn error(event: &str, fields: Value) {
    log(Level::Error, event, fields);
}

/// Log at debug.
pub fn debug(event: &str, fields: Value) {
    log(Level::Debug, event, fields);
}
