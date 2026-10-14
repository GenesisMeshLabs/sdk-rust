//! The state directory (docs/edge.md, "State"): the node and executor keys,
//! the enrolment, the trust snapshot and the agent's database. Keys and JSON
//! files are 0600; JSON is written to a temporary file, synced, then renamed.

use std::{
    fs::{self, OpenOptions},
    io::{self, Write as _},
    os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::Value;

/// The node key.
pub const NODE_KEY: &str = "node.key";
/// The executor key.
pub const EXECUTOR_KEY: &str = "executor.key";
/// The enrolment.
pub const ENROLLMENT: &str = "enrollment.json";
/// The trust snapshot.
pub const SNAPSHOT: &str = "snapshot.json";
/// The agent's database.
pub const DATABASE: &str = "agent.db";
/// The lock `run` (and every command that changes the state) holds.
pub const LOCK: &str = "agent.lock";

/// Why the state directory cannot be used.
#[derive(Debug)]
pub enum StateError {
    /// A key file is group- or world-accessible, or the directory is
    /// group- or world-writable (exit 6).
    Insecure(String),
    /// Another process holds the state directory (exit 2).
    Busy(String),
    /// Reading or writing failed (exit 1).
    Io(String),
}

impl std::fmt::Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Insecure(m) | Self::Busy(m) | Self::Io(m) => f.write_str(m),
        }
    }
}

fn io_error(what: &str, path: &Path, err: io::Error) -> StateError {
    StateError::Io(format!("{what} {}: {err}", path.display()))
}

/// The state directory.
#[derive(Debug, Clone)]
pub struct StateDir {
    root: PathBuf,
}

impl StateDir {
    /// The directory at `root`, created 0700 when absent. Refuses key files
    /// any other user or group may read.
    pub fn open(root: &Path) -> Result<Self, StateError> {
        if !root.exists() {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(root)
                .map_err(|e| io_error("cannot create the state directory", root, e))?;
        }
        let dir = Self {
            root: root.to_path_buf(),
        };
        dir.check_permissions()?;
        Ok(dir)
    }

    /// A file in the directory.
    pub fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    /// Exit 6 when the directory is group- or world-writable, or a key file
    /// is group- or world-accessible.
    pub fn check_permissions(&self) -> Result<(), StateError> {
        let meta = fs::metadata(&self.root)
            .map_err(|e| io_error("cannot read the state directory", &self.root, e))?;
        if meta.permissions().mode() & 0o022 != 0 {
            return Err(StateError::Insecure(format!(
                "the state directory {} is writable by other users (mode {:04o}); it must be 0700",
                self.root.display(),
                meta.permissions().mode() & 0o777
            )));
        }
        for name in [NODE_KEY, EXECUTOR_KEY] {
            let path = self.path(name);
            match fs::metadata(&path) {
                Ok(meta) if meta.permissions().mode() & 0o077 != 0 => {
                    return Err(StateError::Insecure(format!(
                        "{} is accessible to other users (mode {:04o}); it must be 0600",
                        path.display(),
                        meta.permissions().mode() & 0o777
                    )));
                }
                Ok(_) => {}
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                Err(err) => return Err(io_error("cannot read", &path, err)),
            }
        }
        Ok(())
    }

    /// The base64 seed in a key file (`#` comment lines allowed), or `None`
    /// when the file does not exist.
    pub fn read_key(&self, name: &str) -> Result<Option<String>, StateError> {
        let path = self.path(name);
        match fs::read_to_string(&path) {
            Ok(text) => {
                let seed = text
                    .lines()
                    .map(str::trim)
                    .find(|line| !line.is_empty() && !line.starts_with('#'))
                    .unwrap_or_default()
                    .to_owned();
                genesis_mesh_sdk::public_key_from_seed(&seed).map_err(|_| {
                    StateError::Io(format!("{} is not a base64 Ed25519 seed", path.display()))
                })?;
                Ok(Some(seed))
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(io_error("cannot read", &path, err)),
        }
    }

    /// The key in `name`, generated (32 random bytes) and written 0600 with
    /// create-new semantics when absent.
    pub fn key(&self, name: &str) -> Result<String, StateError> {
        if let Some(seed) = self.read_key(name)? {
            return Ok(seed);
        }
        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes)
            .map_err(|e| StateError::Io(format!("cannot generate a key: {e}")))?;
        let seed = STANDARD.encode(bytes);
        let path = self.path(name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| io_error("cannot create", &path, e))?;
        file.write_all(format!("# genesis-mesh-edge {name}\n{seed}\n").as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|e| io_error("cannot write", &path, e))?;
        self.sync_dir();
        Ok(seed)
    }

    /// A JSON file, or `None` when it does not exist.
    pub fn read_json(&self, name: &str) -> Result<Option<Value>, StateError> {
        let path = self.path(name);
        match fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text)
                .map(Some)
                .map_err(|e| StateError::Io(format!("{} does not parse: {e}", path.display()))),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(io_error("cannot read", &path, err)),
        }
    }

    /// Write a JSON file 0600: a temporary file, synced, then renamed.
    pub fn write_json(&self, name: &str, value: &Value) -> Result<(), StateError> {
        let path = self.path(name);
        let temporary = self.path(&format!(".{name}.tmp"));
        let _ = fs::remove_file(&temporary);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|e| io_error("cannot create", &temporary, e))?;
        let text = serde_json::to_vec_pretty(value)
            .map_err(|e| StateError::Io(format!("cannot serialize {name}: {e}")))?;
        file.write_all(&text)
            .and_then(|()| file.sync_all())
            .map_err(|e| io_error("cannot write", &temporary, e))?;
        fs::rename(&temporary, &path).map_err(|e| io_error("cannot replace", &path, e))?;
        self.sync_dir();
        Ok(())
    }

    fn sync_dir(&self) {
        if let Ok(dir) = fs::File::open(&self.root) {
            let _ = dir.sync_all();
        }
    }

    /// Take the state directory's lock, held until the returned file is
    /// dropped: one process changes the state at a time (`run`, `enroll`,
    /// `reset`, `init`).
    pub fn lock(&self) -> Result<fs::File, StateError> {
        let path = self.path(LOCK);
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| io_error("cannot open", &path, e))?;
        match file.try_lock() {
            Ok(()) => Ok(file),
            Err(fs::TryLockError::WouldBlock) => Err(StateError::Busy(format!(
                "another genesis-mesh-edge process holds {} (is the agent running? stop it first)",
                path.display()
            ))),
            Err(fs::TryLockError::Error(e)) => Err(io_error("cannot lock", &path, e)),
        }
    }

    /// Delete the keys and every state file (`reset`).
    pub fn reset(&self) -> Result<(), StateError> {
        for name in [
            NODE_KEY,
            EXECUTOR_KEY,
            ENROLLMENT,
            SNAPSHOT,
            DATABASE,
            "agent.db-wal",
            "agent.db-shm",
            "agent.db-journal",
        ] {
            let path = self.path(name);
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                Err(err) => return Err(io_error("cannot delete", &path, err)),
            }
        }
        self.sync_dir();
        Ok(())
    }

    /// What the directory holds.
    #[cfg(test)]
    pub fn entries(&self) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(&self.root)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary() -> PathBuf {
        let mut bytes = [0_u8; 8];
        getrandom::fill(&mut bytes).unwrap();
        let name: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        std::env::temp_dir().join(format!("gm-edge-state-{name}"))
    }

    #[test]
    fn keys_are_generated_once_0600_and_refused_when_readable_by_others() {
        let root = temporary();
        let dir = StateDir::open(&root).unwrap();
        assert_eq!(
            fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let seed = dir.key(NODE_KEY).unwrap();
        assert_eq!(dir.key(NODE_KEY).unwrap(), seed);
        let path = dir.path(NODE_KEY);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(matches!(
            StateDir::open(&root),
            Err(StateError::Insecure(_))
        ));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_writable_directory_is_refused_and_one_process_holds_the_lock() {
        let root = temporary();
        let dir = StateDir::open(&root).unwrap();
        let held = dir.lock().unwrap();
        assert!(matches!(dir.lock(), Err(StateError::Busy(_))));
        drop(held);
        dir.lock().unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o770)).unwrap();
        assert!(matches!(
            StateDir::open(&root),
            Err(StateError::Insecure(_))
        ));
        fs::set_permissions(&root, fs::Permissions::from_mode(0o750)).unwrap();
        StateDir::open(&root).unwrap();
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn json_is_replaced_whole() {
        let root = temporary();
        let dir = StateDir::open(&root).unwrap();
        dir.write_json(SNAPSHOT, &serde_json::json!({"a": 1}))
            .unwrap();
        dir.write_json(SNAPSHOT, &serde_json::json!({"a": 2}))
            .unwrap();
        assert_eq!(dir.read_json(SNAPSHOT).unwrap().unwrap()["a"], 2);
        assert_eq!(dir.entries(), [SNAPSHOT]);
        assert_eq!(
            fs::metadata(dir.path(SNAPSHOT))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        fs::remove_dir_all(&root).unwrap();
    }
}
