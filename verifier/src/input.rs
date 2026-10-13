//! Reading the inputs: keys, JSON documents, exports and held anchors. Files
//! only; nothing here opens a socket.

use std::{fs, path::Path};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use genesis_mesh_sdk::{
    parse_strict_json,
    verify::{check_anchors, parse_anchors},
    Value,
};

use crate::Stop;

/// Where a key is placed in the store: only registry records the NA signed
/// say so, never a key supplied on the command line.
const PLACEMENT_FIELDS: [&str; 4] = [
    "registered_sequence",
    "retired_sequence",
    "registered_at_time",
    "retired_at_time",
];

/// The file names `genesis-mesh evidence anchors fetch` writes.
const ANCHOR_FILE_PREFIX: &str = "anchor-";

fn unreadable(path: &Path, why: impl std::fmt::Display) -> Stop {
    Stop::Unreadable(format!("cannot read {}: {why}", path.display()))
}

/// A file's text, which must be UTF-8.
pub fn text(path: &Path) -> Result<String, Stop> {
    let bytes = fs::read(path).map_err(|e| unreadable(path, e))?;
    String::from_utf8(bytes).map_err(|_| unreadable(path, "not UTF-8"))
}

/// A JSON document, read strictly (no duplicate keys, no lone surrogates,
/// integers within 2^53).
pub fn json(path: &Path) -> Result<Value, Stop> {
    parse_strict_json(text(path)?.trim_matches([' ', '\t', '\r', '\n']))
        .map_err(|e| unreadable(path, e))
}

/// A JSON object.
pub fn object(path: &Path) -> Result<Value, Stop> {
    let value = json(path)?;
    if value.is_object() {
        Ok(value)
    } else {
        Err(unreadable(path, "not a JSON object"))
    }
}

/// A base64 Ed25519 public key given inline, or as a file of it ('#'
/// comment lines and blank lines ignored), as the reference CLI reads one.
pub fn public_key(value: &str) -> Result<String, Stop> {
    let path = Path::new(value);
    let key = if path.is_file() {
        text(path)?
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect::<String>()
    } else {
        value.to_owned()
    };
    match STANDARD.decode(&key) {
        Ok(bytes) if bytes.len() == 32 => Ok(key),
        _ => Err(Stop::Usage(format!(
            "{value:?} is not a base64 Ed25519 public key or a file holding one"
        ))),
    }
}

/// Every key given.
pub fn public_keys(values: &[String]) -> Result<Vec<String>, Stop> {
    values.iter().map(|v| public_key(v)).collect()
}

/// Registered keys from `GET /admin/evidence/executor-keys`: the response,
/// or its `executor_keys` list. Each names `key_id`, `public_key` and
/// `executor_sovereign_id`. A key supplied this way is not placed in the
/// store: any placement it carries (`registered_sequence`,
/// `retired_sequence`, `registered_at_time`, `retired_at_time`) is set aside,
/// as the reference's `--executor-keys` reads it; only the registry records
/// the NA signed place a key.
pub fn executor_keys(path: &Path) -> Result<Vec<Value>, Stop> {
    let value = json(path)?;
    let rows = match value {
        Value::Object(ref map) if map.contains_key("executor_keys") => map["executor_keys"].clone(),
        other => other,
    };
    let Value::Array(rows) = rows else {
        return Err(unreadable(path, "not a list of executor keys"));
    };
    let mut rows = rows;
    for row in &mut rows {
        if let Some(fields) = row.as_object_mut() {
            for key in PLACEMENT_FIELDS {
                fields.remove(key);
            }
        }
    }
    for row in &rows {
        let named = |key: &str| row.get(key).is_some_and(Value::is_string);
        if !(named("key_id") && named("public_key") && named("executor_sovereign_id")) {
            return Err(unreadable(
                path,
                "each executor key names key_id, public_key and executor_sovereign_id",
            ));
        }
    }
    Ok(rows)
}

/// Every file of an audit pack directory, by its `/`-separated path, as
/// bytes (the reference's `read_pack_dir`).
pub fn pack_files(dir: &Path) -> Result<std::collections::BTreeMap<String, Vec<u8>>, Stop> {
    fn walk(
        root: &Path,
        dir: &Path,
        files: &mut std::collections::BTreeMap<String, Vec<u8>>,
    ) -> Result<(), Stop> {
        for entry in fs::read_dir(dir).map_err(|e| unreadable(dir, e))? {
            let path = entry.map_err(|e| unreadable(dir, e))?.path();
            if path.is_dir() {
                walk(root, &path, files)?;
            } else if path.is_file() {
                let relative = path.strip_prefix(root).unwrap_or(&path);
                let name: Vec<String> = relative
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect();
                let data = fs::read(&path).map_err(|e| unreadable(&path, e))?;
                files.insert(name.join("/"), data);
            }
        }
        Ok(())
    }
    if !dir.is_dir() {
        return Err(unreadable(dir, "not a directory"));
    }
    let mut files = std::collections::BTreeMap::new();
    walk(dir, dir, &mut files)?;
    Ok(files)
}

/// Anchors held out of band: a directory written by `genesis-mesh evidence
/// anchors fetch` (`anchor-*.json`, an empty file is an interrupted write
/// and holds none), or a JSON or JSON Lines file. In `anchor_sequence`
/// order; at least one.
pub fn anchors(path: &Path) -> Result<Vec<Value>, Stop> {
    let anchors = if path.is_dir() {
        let mut files: Vec<_> = fs::read_dir(path)
            .map_err(|e| unreadable(path, e))?
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with(ANCHOR_FILE_PREFIX) && n.ends_with(".json"))
            })
            .collect();
        files.sort();
        let mut values = Vec::new();
        for file in files {
            let empty = fs::metadata(&file).map_err(|e| unreadable(&file, e))?.len() == 0;
            if !empty {
                values.push(json(&file)?);
            }
        }
        check_anchors(values).map_err(|e| unreadable(path, e))?
    } else {
        parse_anchors(&text(path)?).map_err(|e| unreadable(path, e))?
    };
    if anchors.is_empty() {
        return Err(Stop::Unreadable(format!(
            "no anchors found in {}",
            path.display()
        )));
    }
    Ok(anchors)
}
