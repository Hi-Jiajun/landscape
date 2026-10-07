//! Versioned joint snapshots of the router configuration, and rollback to one.
//!
//! The rules, the DNS configuration and the firewall all live in the one SQLite
//! file the service stores its configuration in, so a consistent copy of that
//! file *is* a joint snapshot of all three: restoring it restores them together,
//! and there is no way to restore half of a change set.
//!
//! This is deliberately a command-line path that talks to the file directly. It
//! has to work when the thing that broke is the service itself — a bad rule set
//! that makes the network unusable, a DNS configuration that cannot resolve, a
//! proxy that will not start — so it cannot depend on the web UI, on DNS, or on
//! the proxy being up.
//!
//! Every restore takes a snapshot of the state it is about to replace first, so
//! the rollback is itself reversible.

use std::{
    fs,
    path::{Path, PathBuf},
};

use sea_orm::{ConnectionTrait, Database, DatabaseBackend, Statement};
use serde::{Deserialize, Serialize};

use landscape_common::database::error::DbError;

/// How many snapshots are kept before the oldest are pruned.
pub const DEFAULT_KEEP: usize = 20;

/// Subdirectory of the configuration directory that holds the snapshots.
const SNAPSHOT_DIR: &str = "snapshots";

/// Marks a configuration change that has been applied but not yet accepted.
///
/// While this exists, the change is provisional: the service rolls back to the
/// snapshot it names unless the change is committed first, and it does so on
/// startup too — a change that crashed the service is exactly the one that must
/// not survive. The file is the whole state, so the rule works across a restart
/// and can be inspected by hand.
const PENDING_FILE: &str = "pending_transaction.json";

/// A change that is applied but not yet accepted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingTransaction {
    /// Snapshot to return to if the change is not committed.
    pub snapshot_id: String,
    pub label: Option<String>,
    /// Unix milliseconds; after this the change is rolled back.
    pub expires_at_ms: f64,
    pub started_at_ms: f64,
}

impl PendingTransaction {
    pub fn is_expired(&self) -> bool {
        now_ms() > self.expires_at_ms
    }

    pub fn remaining_secs(&self) -> i64 {
        ((self.expires_at_ms - now_ms()) / 1000.0).round() as i64
    }

    pub fn describe(&self) -> String {
        let label = self.label.as_deref().unwrap_or("-");
        format!("snapshot {} ({label}), {}s remaining", self.snapshot_id, self.remaining_secs())
    }
}

/// One snapshot: the database copy plus what is known about it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotManifest {
    /// `YYYYMMDD-HHMMSS`, the snapshot's identity on the command line.
    pub id: String,
    /// Free-form label, e.g. `before-tproxy-change`.
    #[serde(default)]
    pub label: Option<String>,
    /// Unix milliseconds.
    pub taken_at: f64,
    /// The binary that took it, so a restore can tell versions apart.
    pub binary_version: String,
    /// Size of the database copy in bytes.
    pub size: u64,
    /// SHA-256 of the database copy.
    pub sha256: String,
    /// What the snapshot was taken before, when it is an automatic one.
    #[serde(default)]
    pub automatic: bool,
}

impl SnapshotManifest {
    pub fn describe(&self) -> String {
        let label = self.label.as_deref().unwrap_or("");
        let kind = if self.automatic { "auto" } else { "manual" };
        format!(
            "{}  {:<6} {:>9}  {}{}",
            self.id,
            kind,
            format_bytes(self.size),
            label,
            if self.label.is_some() { "" } else { "-" }
        )
    }
}

fn format_bytes(bytes: u64) -> String {
    const MIB: u64 = 1024 * 1024;
    const KIB: u64 = 1024;
    if bytes >= MIB {
        format!("{:.1}MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1}KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes}B")
    }
}

/// The snapshot store: a directory holding database copies and their manifests.
pub struct SnapshotStore {
    dir: PathBuf,
}

impl SnapshotStore {
    /// Snapshots live beside the database they came from.
    pub fn for_config_dir(config_dir: &Path) -> Self {
        Self { dir: config_dir.join(SNAPSHOT_DIR) }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn ensure_dir(&self) -> Result<(), DbError> {
        fs::create_dir_all(&self.dir)?;
        Ok(())
    }

    fn db_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.sqlite"))
    }

    fn manifest_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.json"))
    }

    /// Every manifest, newest first. A manifest that cannot be read is skipped
    /// with a warning rather than failing the listing: a damaged entry must not
    /// hide the good ones.
    pub fn list(&self) -> Result<Vec<SnapshotManifest>, DbError> {
        if !self.dir.is_dir() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for entry in fs::read_dir(&self.dir)? {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    tracing::warn!("skipping unreadable snapshot directory entry: {e}");
                    continue;
                }
            };
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            match fs::read_to_string(&path).map_err(DbError::from).and_then(|text| {
                serde_json::from_str::<SnapshotManifest>(&text)
                    .map_err(|e| DbError::Internal(format!("{}: {e}", path.display())))
            }) {
                Ok(manifest) => out.push(manifest),
                Err(e) => tracing::warn!("skipping unreadable snapshot manifest: {e}"),
            }
        }
        // Newest first by id, which is a sortable timestamp.
        out.sort_by(|a, b| b.id.cmp(&a.id));
        Ok(out)
    }

    pub fn find(&self, id: &str) -> Result<SnapshotManifest, DbError> {
        self.list()?
            .into_iter()
            .find(|manifest| manifest.id == id)
            .ok_or_else(|| DbError::Internal(format!("no snapshot with id '{id}'")))
    }

    /// The newest snapshot, which is what `rescue rollback` returns to.
    pub fn newest(&self) -> Result<SnapshotManifest, DbError> {
        self.list()?
            .into_iter()
            .next()
            .ok_or_else(|| DbError::Internal("there is no snapshot to roll back to".to_string()))
    }

    /// Copy `database_path` into a new snapshot.
    ///
    /// The copy is made by SQLite itself (`VACUUM INTO`), so it is consistent
    /// even while the service is running and writing.
    pub async fn create(
        &self,
        database_url: &str,
        label: Option<String>,
        automatic: bool,
        binary_version: &str,
    ) -> Result<SnapshotManifest, DbError> {
        self.ensure_dir()?;
        let id = self.next_id()?;
        let target = self.db_path(&id);

        // `VACUUM INTO` needs an absolute path with forward slashes and quotes
        // escaped, since the statement is plain SQL.
        let target_sql = sql_quote_path(&target);
        let database = connect(database_url).await?;
        database
            .execute(Statement::from_string(
                DatabaseBackend::Sqlite,
                format!("VACUUM INTO {target_sql}"),
            ))
            .await?;
        database.close().await.ok();

        let size = fs::metadata(&target)?.len();
        let sha256 = file_sha256(&target)?;
        let manifest = SnapshotManifest {
            id: id.clone(),
            label,
            taken_at: now_ms(),
            binary_version: binary_version.to_string(),
            size,
            sha256,
            automatic,
        };
        let text = serde_json::to_string_pretty(&manifest)
            .map_err(|e| DbError::Internal(format!("cannot serialise snapshot manifest: {e}")))?;
        // The manifest appears only once the copy is complete and hashed, so a
        // half-written snapshot is never offered for restore.
        fs::write(self.manifest_path(&id), text)?;
        Ok(manifest)
    }

    /// Replace the live database with a snapshot's copy.
    ///
    /// The caller must ensure nothing is using the database: this replaces the
    /// file and removes the old write-ahead log, which is only safe with the
    /// service stopped.
    /// `database_file` is the database **file path**, not its `sqlite://…` URL:
    /// this function replaces the file itself.
    pub fn restore(&self, id: &str, database_file: &Path) -> Result<PathBuf, DbError> {
        let manifest = self.find(id)?;
        let source = self.db_path(&manifest.id);
        if !source.is_file() {
            return Err(DbError::Internal(format!(
                "snapshot {} has a manifest but no database copy",
                manifest.id
            )));
        }
        let actual = file_sha256(&source)?;
        if actual != manifest.sha256 {
            return Err(DbError::Internal(format!(
                "snapshot {} is damaged (checksum {actual} does not match {})",
                manifest.id, manifest.sha256
            )));
        }

        let live = database_file.to_path_buf();
        // Stage the copy next to the live file so the final step is a rename,
        // which either happens or does not — it cannot leave a half-written
        // configuration in place.
        let staged = live.with_extension("restore-staging");
        fs::copy(&source, &staged)?;
        fs::rename(&staged, &live)?;

        // These belong to the database that was just replaced. Leaving them would
        // make SQLite replay an old write-ahead log over the restored file.
        for suffix in ["-wal", "-shm"] {
            let sidecar = live.with_file_name(format!(
                "{}{suffix}",
                live.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
            ));
            if sidecar.exists() {
                fs::remove_file(&sidecar)?;
            }
        }
        Ok(live)
    }

    /// Drop the oldest snapshots, keeping `keep` of them.
    pub fn prune(&self, keep: usize) -> Result<usize, DbError> {
        let snapshots = self.list()?;
        let mut removed = 0;
        for manifest in snapshots.into_iter().skip(keep) {
            for path in [self.db_path(&manifest.id), self.manifest_path(&manifest.id)] {
                match fs::remove_file(&path) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => tracing::warn!("cannot remove {}: {e}", path.display()),
                }
            }
            removed += 1;
        }
        Ok(removed)
    }

    // ── transactions ────────────────────────────────────────────────────────

    fn pending_path(&self) -> PathBuf {
        self.dir.join(PENDING_FILE)
    }

    /// The change that is applied but not yet accepted, if there is one.
    pub fn pending(&self) -> Option<PendingTransaction> {
        let text = fs::read_to_string(self.pending_path()).ok()?;
        match serde_json::from_str::<PendingTransaction>(&text) {
            Ok(pending) => Some(pending),
            Err(e) => {
                // A corrupt marker must not silently disable the safety net; the
                // caller is told so it can decide, and the file is left in place
                // for inspection.
                tracing::error!(
                    path = %self.pending_path().display(),
                    "pending-transaction marker is unreadable: {e}"
                );
                None
            }
        }
    }

    /// Start a transaction: snapshot the current state and mark it provisional.
    pub async fn begin_transaction(
        &self,
        database_url: &str,
        label: Option<String>,
        timeout_secs: u64,
        binary_version: &str,
    ) -> Result<PendingTransaction, DbError> {
        if let Some(existing) = self.pending() {
            return Err(DbError::Internal(format!(
                "a configuration transaction is already open ({}); commit or roll it back first",
                existing.describe()
            )));
        }
        let manifest = self.create(database_url, label.clone(), false, binary_version).await?;
        let started = now_ms();
        let pending = PendingTransaction {
            snapshot_id: manifest.id,
            label,
            started_at_ms: started,
            expires_at_ms: started + (timeout_secs as f64) * 1000.0,
        };
        let text = serde_json::to_string_pretty(&pending)
            .map_err(|e| DbError::Internal(format!("cannot serialise pending transaction: {e}")))?;
        fs::write(self.pending_path(), text)?;
        Ok(pending)
    }

    /// Accept the change: the snapshot stays as history, the marker goes.
    ///
    /// Returns the transaction that was open, so the caller can report what was
    /// accepted.
    pub fn commit_transaction(&self) -> Result<PendingTransaction, DbError> {
        let pending = self
            .pending()
            .ok_or_else(|| DbError::Internal("there is no open transaction".to_string()))?;
        match fs::remove_file(self.pending_path()) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        Ok(pending)
    }

    /// Give up the change: restore the snapshot the transaction started from.
    ///
    /// The marker is removed first, so a failure part-way through cannot leave a
    /// transaction that rolls back again on the next start.
    pub fn rollback_transaction(
        &self,
        database_file: &Path,
    ) -> Result<PendingTransaction, DbError> {
        let pending = self
            .pending()
            .ok_or_else(|| DbError::Internal("there is no open transaction".to_string()))?;
        match fs::remove_file(self.pending_path()) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        self.restore(&pending.snapshot_id, database_file)?;
        Ok(pending)
    }

    /// Roll back any transaction whose deadline has passed.
    ///
    /// Used by the background task and, with `force`, at startup: a change that
    /// was never committed is one nobody accepted, and an uncommitted change that
    /// took the service down is the case this exists for.
    pub fn rollback_expired(
        &self,
        database_file: &Path,
        force: bool,
    ) -> Result<Option<PendingTransaction>, DbError> {
        let Some(pending) = self.pending() else {
            return Ok(None);
        };
        if !force && !pending.is_expired() {
            return Ok(None);
        }
        match fs::remove_file(self.pending_path()) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        self.restore(&pending.snapshot_id, database_file)?;
        Ok(Some(pending))
    }

    /// An id no existing snapshot uses.
    ///
    /// The base form is the second, which is not unique on its own: a restore
    /// takes a safety snapshot moments after the one it is about to restore, and
    /// failing there would take the rescue path out of service exactly when it is
    /// needed. Later collisions within the same second get a `-2`, `-3`, … suffix,
    /// which still sorts after the base id and before the next second.
    fn next_id(&self) -> Result<String, DbError> {
        let seconds = (now_ms() / 1000.0) as i64;
        let base = format_timestamp(seconds);
        if !self.db_path(&base).exists() && !self.manifest_path(&base).exists() {
            return Ok(base);
        }
        for suffix in 2u32..1000 {
            let candidate = format!("{base}-{suffix}");
            if !self.db_path(&candidate).exists() && !self.manifest_path(&candidate).exists() {
                return Ok(candidate);
            }
        }
        Err(DbError::Internal(format!(
            "cannot find a free snapshot id for {base} (1000 taken in one second)"
        )))
    }
}

/// `YYYYMMDD-HHMMSS` in UTC, sortable as a string.
fn format_timestamp(unix_seconds: i64) -> String {
    // Deliberately dependency-free: this only has to be unique and sortable, and
    // it is compared against other ids of the same format.
    let days = unix_seconds.div_euclid(86_400);
    let time = unix_seconds.rem_euclid(86_400);
    let (hour, minute, second) = (time / 3600, (time % 3600) / 60, time % 60);
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}{month:02}{day:02}-{hour:02}{minute:02}{second:02}")
}

/// Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

fn now_ms() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as f64)
        .unwrap_or(0.0)
}

/// A SQLite string literal for a path: single quotes doubled.
fn sql_quote_path(path: &Path) -> String {
    let text = path.to_string_lossy().replace('\\', "/");
    format!("'{}'", text.replace('\'', "''"))
}

async fn connect(database_path: &str) -> Result<sea_orm::DatabaseConnection, DbError> {
    let options: migration::sea_orm::ConnectOptions = database_path.to_string().into();
    Ok(Database::connect(options).await?)
}

/// SHA-256 of a file, streamed so a large database is not read into memory.
fn file_sha256(path: &Path) -> Result<String, DbError> {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    // `sha2` 0.11 returns a generic array that does not implement `LowerHex`.
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    Ok(hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_are_sortable_and_well_formed() {
        // 2026-10-07T12:34:56Z, as `date -u -d "2026-10-07 12:34:56" +%s` reports.
        let id = format_timestamp(1_791_376_496);
        assert_eq!(id, "20261007-123456");
        // Later is lexicographically greater, which is what the listing relies on.
        assert!(format_timestamp(1_791_376_497) > id);
    }

    #[test]
    fn epoch_and_leap_days_are_handled() {
        assert_eq!(format_timestamp(0), "19700101-000000");
        // 2000-02-29T00:00:00Z (a leap day in a leap century)
        assert_eq!(format_timestamp(951_782_400), "20000229-000000");
    }

    #[test]
    fn a_path_with_a_quote_cannot_break_the_statement() {
        let quoted = sql_quote_path(Path::new("/tmp/o'brien/db.sqlite"));
        assert_eq!(quoted, "'/tmp/o''brien/db.sqlite'");
    }

    #[test]
    fn a_suffixed_id_still_sorts_between_its_second_and_the_next() {
        // The listing orders by id string, so a same-second collision must not
        // reorder the snapshots around it.
        let base = format_timestamp(1_791_376_496); // 20261007-123456
        let next = format_timestamp(1_791_376_497); // 20261007-123457
        let suffixed = format!("{base}-2");
        assert!(suffixed > base);
        assert!(suffixed < next);
    }

    #[test]
    fn byte_sizes_read_naturally() {
        assert_eq!(format_bytes(512), "512B");
        assert_eq!(format_bytes(2048), "2.0KiB");
        assert_eq!(format_bytes(3 * 1024 * 1024), "3.0MiB");
    }
}
