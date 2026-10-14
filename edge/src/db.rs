//! The agent's database (`agent.db`): SQLite in WAL mode with
//! `synchronous=FULL`. It holds the SDK's evidence and record outboxes, the
//! grant holders' state, the authorizations and a few values (`meta`).

use std::{
    fs::OpenOptions,
    io,
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::Path,
    sync::{Arc, Mutex},
};

use chrono::Utc;
use genesis_mesh_sdk::{
    EvidenceOutbox, OutboxEntry, OutboxFuture, OutboxState, RecordKind, RecordOutbox,
    RecordOutboxEntry,
};
use rusqlite::{params, Connection, OptionalExtension as _};
use serde_json::Value;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS evidence_outbox (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE NOT NULL, entry_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS record_outbox (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE NOT NULL, entry_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS grant_holders (
  grant_id TEXT PRIMARY KEY, state_json TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS authorizations (
  id TEXT PRIMARY KEY, created_at TEXT NOT NULL, state TEXT NOT NULL, authority TEXT,
  record_id TEXT);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
";

/// The database, shared by the outboxes and the agent.
#[derive(Debug, Clone)]
pub struct Db {
    connection: Arc<Mutex<Connection>>,
}

fn sql(err: rusqlite::Error) -> io::Error {
    io::Error::other(err)
}

impl Db {
    /// Open (or create, 0600) the database at `path`.
    pub fn open(path: &Path) -> io::Result<Self> {
        if !path.exists() {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
        }
        let connection = Connection::open(path).map_err(sql)?;
        connection
            .execute_batch(
                // Temporary tables in memory: the root file system may be
                // read-only (the container image), only the state directory
                // is writable.
                "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;
                 PRAGMA temp_store=MEMORY;",
            )
            .map_err(sql)?;
        connection.execute_batch(SCHEMA).map_err(sql)?;
        connection
            .execute(
                "INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', '1')",
                [],
            )
            .map_err(sql)?;
        // SQLite creates its WAL and shared-memory files with the umask's mode.
        for suffix in ["-wal", "-shm"] {
            let mut name = path.as_os_str().to_owned();
            name.push(suffix);
            let _ = std::fs::set_permissions(&name, std::fs::Permissions::from_mode(0o600));
        }
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    fn with<T>(&self, f: impl FnOnce(&Connection) -> rusqlite::Result<T>) -> io::Result<T> {
        let connection = self
            .connection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f(&connection).map_err(sql)
    }

    /// A value of `meta`.
    pub fn meta(&self, key: &str) -> io::Result<Option<String>> {
        self.with(|c| {
            c.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
                .optional()
        })
    }

    /// Set a value of `meta`.
    pub fn set_meta(&self, key: &str, value: &str) -> io::Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO meta (key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![key, value],
            )
            .map(drop)
        })
    }

    /// Every meta value whose key starts with `prefix`.
    pub fn meta_with_prefix(&self, prefix: &str) -> io::Result<Vec<(String, String)>> {
        self.with(|c| {
            let mut statement =
                c.prepare("SELECT key, value FROM meta WHERE substr(key, 1, ?1) = ?2")?;
            let rows = statement
                .query_map(params![prefix.len() as i64, prefix], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }

    /// Every grant holder's saved state.
    pub fn holders(&self) -> io::Result<Vec<(String, Value)>> {
        let rows: Vec<(String, String)> = self.with(|c| {
            let mut statement =
                c.prepare("SELECT grant_id, state_json FROM grant_holders ORDER BY grant_id")?;
            let rows = statement
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })?;
        rows.into_iter()
            .map(|(id, text)| {
                serde_json::from_str(&text)
                    .map(|state| (id, state))
                    .map_err(io::Error::other)
            })
            .collect()
    }

    /// Save a grant holder's state.
    pub fn save_holder(&self, grant_id: &str, state: &Value) -> io::Result<()> {
        let text = state.to_string();
        self.with(|c| {
            c.execute(
                "INSERT INTO grant_holders (grant_id, state_json, updated_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(grant_id) DO UPDATE SET state_json = excluded.state_json,
                   updated_at = excluded.updated_at",
                params![grant_id, text, Utc::now().to_rfc3339()],
            )
            .map(drop)
        })
    }

    /// Record an authorization's state.
    pub fn set_authorization(
        &self,
        id: &str,
        state: &str,
        authority: Option<&str>,
        record_id: Option<&str>,
    ) -> io::Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO authorizations (id, created_at, state, authority, record_id)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(id) DO UPDATE SET state = excluded.state,
                   authority = COALESCE(excluded.authority, authorizations.authority),
                   record_id = COALESCE(excluded.record_id, authorizations.record_id)",
                params![id, Utc::now().to_rfc3339(), state, authority, record_id],
            )
            .map(drop)
        })
    }

    /// An authorization's state.
    pub fn authorization_state(&self, id: &str) -> io::Result<Option<String>> {
        self.with(|c| {
            c.query_row(
                "SELECT state FROM authorizations WHERE id = ?1",
                [id],
                |r| r.get(0),
            )
            .optional()
        })
    }

    /// Mark authorizations left open by a previous run as lost; returns how
    /// many there are in all.
    pub fn lose_open_authorizations(&self) -> io::Result<u64> {
        self.with(|c| {
            c.execute(
                "UPDATE authorizations SET state = 'lost' WHERE state = 'open'",
                [],
            )?;
            c.query_row(
                "SELECT COUNT(*) FROM authorizations WHERE state = 'lost'",
                [],
                |r| r.get::<_, i64>(0),
            )
        })
        .map(|n| n as u64)
    }

    fn list<T: serde::de::DeserializeOwned>(&self, table: &str) -> io::Result<Vec<T>> {
        let texts: Vec<String> = self.with(|c| {
            let mut statement =
                c.prepare(&format!("SELECT entry_json FROM {table} ORDER BY seq"))?;
            let rows = statement
                .query_map([], |r| r.get(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })?;
        texts
            .iter()
            .map(|t| serde_json::from_str(t).map_err(io::Error::other))
            .collect()
    }

    fn add(&self, table: &str, id: &str, entry: String) -> io::Result<()> {
        let added = self.with(|c| {
            c.execute(
                &format!("INSERT OR IGNORE INTO {table} (id, entry_json) VALUES (?1, ?2)"),
                params![id, entry],
            )
        })?;
        if added == 0 {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("an entry with id {id} is stored"),
            ));
        }
        Ok(())
    }

    fn update(&self, table: &str, id: &str, entry: String) -> io::Result<()> {
        self.with(|c| {
            c.execute(
                &format!("UPDATE {table} SET entry_json = ?2 WHERE id = ?1"),
                params![id, entry],
            )
            .map(drop)
        })
    }

    fn remove(&self, table: &str, id: &str) -> io::Result<Option<String>> {
        self.with(|c| {
            let entry: Option<String> = c
                .query_row(
                    &format!("SELECT entry_json FROM {table} WHERE id = ?1"),
                    [id],
                    |r| r.get(0),
                )
                .optional()?;
            c.execute(&format!("DELETE FROM {table} WHERE id = ?1"), [id])?;
            Ok(entry)
        })
    }

    /// Pending entries and dead letters across both outboxes.
    pub fn outbox_counts(&self) -> io::Result<(u64, u64)> {
        let evidence: Vec<OutboxEntry> = self.list("evidence_outbox")?;
        let records: Vec<RecordOutboxEntry> = self.list("record_outbox")?;
        let dead = evidence
            .iter()
            .filter(|e| e.state == OutboxState::DeadLetter)
            .count()
            + records
                .iter()
                .filter(|e| e.state == OutboxState::DeadLetter)
                .count();
        let pending = evidence.len() + records.len() - dead;
        Ok((pending as u64, dead as u64))
    }

    /// The newest use of each grant this agent has made that the NA
    /// admitted (kept when the record outbox removes it), with the pending
    /// and dead-lettered uses still in the record outbox.
    pub fn grant_uses(&self) -> io::Result<Vec<Value>> {
        let mut uses: Vec<Value> = self
            .meta_with_prefix(ADMITTED_USE)?
            .into_iter()
            .filter_map(|(_, v)| serde_json::from_str(&v).ok())
            .collect();
        let records: Vec<RecordOutboxEntry> = self.list("record_outbox")?;
        uses.extend(
            records
                .into_iter()
                .filter(|e| e.kind == RecordKind::GrantExecution)
                .map(|e| e.record),
        );
        Ok(uses)
    }
}

/// The meta key prefix of each grant's newest admitted use.
const ADMITTED_USE: &str = "admitted_use:";

/// The SDK's evidence outbox over `evidence_outbox`.
#[derive(Debug, Clone)]
pub struct SqliteOutbox(pub Db);

/// The SDK's record outbox over `record_outbox`.
#[derive(Debug, Clone)]
pub struct SqliteRecordOutbox(pub Db);

fn text<T: serde::Serialize>(entry: &T) -> io::Result<String> {
    serde_json::to_string(entry).map_err(io::Error::other)
}

impl EvidenceOutbox for SqliteOutbox {
    fn add<'a>(&'a self, entry: &'a OutboxEntry) -> OutboxFuture<'a, ()> {
        Box::pin(async move { self.0.add("evidence_outbox", &entry.id, text(entry)?) })
    }

    fn update<'a>(&'a self, entry: &'a OutboxEntry) -> OutboxFuture<'a, ()> {
        Box::pin(async move { self.0.update("evidence_outbox", &entry.id, text(entry)?) })
    }

    fn remove<'a>(&'a self, id: &'a str) -> OutboxFuture<'a, ()> {
        Box::pin(async move { self.0.remove("evidence_outbox", id).map(drop) })
    }

    fn list(&self) -> OutboxFuture<'_, Vec<OutboxEntry>> {
        Box::pin(async move { self.0.list("evidence_outbox") })
    }
}

impl RecordOutbox for SqliteRecordOutbox {
    fn add<'a>(&'a self, entry: &'a RecordOutboxEntry) -> OutboxFuture<'a, ()> {
        Box::pin(async move { self.0.add("record_outbox", &entry.id, text(entry)?) })
    }

    fn update<'a>(&'a self, entry: &'a RecordOutboxEntry) -> OutboxFuture<'a, ()> {
        Box::pin(async move { self.0.update("record_outbox", &entry.id, text(entry)?) })
    }

    fn remove<'a>(&'a self, id: &'a str) -> OutboxFuture<'a, ()> {
        Box::pin(async move {
            let Some(removed) = self.0.remove("record_outbox", id)? else {
                return Ok(());
            };
            // A grant use the NA admitted stays known as its chain's newest,
            // so a restart can never sign a second use at its place.
            let entry: RecordOutboxEntry =
                serde_json::from_str(&removed).map_err(io::Error::other)?;
            if entry.kind == RecordKind::GrantExecution {
                let grant = entry.record["grant_id"].as_str().unwrap_or_default();
                let key = format!("{ADMITTED_USE}{grant}");
                let newer = match self.0.meta(&key)? {
                    Some(held) => serde_json::from_str::<Value>(&held)
                        .ok()
                        .and_then(|h| h["use_sequence"].as_u64())
                        .is_none_or(|held| entry.record["use_sequence"].as_u64() > Some(held)),
                    None => true,
                };
                if newer {
                    self.0.set_meta(&key, &entry.record.to_string())?;
                }
            }
            Ok(())
        })
    }

    fn list(&self) -> OutboxFuture<'_, Vec<RecordOutboxEntry>> {
        Box::pin(async move { self.0.list("record_outbox") })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn temporary() -> std::path::PathBuf {
        let mut bytes = [0_u8; 8];
        getrandom::fill(&mut bytes).unwrap();
        let name: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let dir = std::env::temp_dir().join(format!("gm-edge-db-{name}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn the_outboxes_list_in_the_order_added_and_keep_admitted_uses() {
        let dir = temporary();
        let db = Db::open(&dir.join(DB_NAME)).unwrap();
        let records = SqliteRecordOutbox(db.clone());
        let first =
            RecordOutboxEntry::new(json!({"use_id": "u1", "grant_id": "g", "use_sequence": 1}));
        let second =
            RecordOutboxEntry::new(json!({"use_id": "u2", "grant_id": "g", "use_sequence": 2}));
        records.add(&second).await.unwrap();
        records.add(&first).await.unwrap();
        assert!(records.add(&first).await.is_err());
        let ids: Vec<String> = records
            .list()
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.id)
            .collect();
        assert_eq!(ids, ["u2", "u1"]);
        records.remove("u2").await.unwrap();
        records.remove("u1").await.unwrap();
        assert!(records.list().await.unwrap().is_empty());
        let uses = db.grant_uses().unwrap();
        assert_eq!(uses.len(), 1);
        assert_eq!(uses[0]["use_sequence"], 2);
        assert_eq!(db.meta("schema_version").unwrap().as_deref(), Some("1"));
        assert_eq!(
            std::fs::metadata(dir.join(DB_NAME))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    const DB_NAME: &str = "agent.db";
}
