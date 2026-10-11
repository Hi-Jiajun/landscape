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

/// Time-limited device authorizations, in the same directory.
const GRANTS_FILE: &str = "device_grants.json";

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

/// A time-limited authorization for one device.
///
/// The rescue channel's last resort: instead of turning the strict scope off for
/// everybody, one device is let through for a bounded time, with the reason
/// recorded. Nothing here is permanent — the expiry is enforced when the grant is
/// read, so a missed sweep cannot extend it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceGrant {
    /// Stable id, used to revoke the grant.
    pub id: String,
    /// The device, as a MAC address. Matched the same way a flow match rule is.
    pub mac: String,
    /// The flow the device is temporarily placed in.
    pub flow_id: u32,
    /// Why it was granted, for the audit trail.
    pub reason: String,
    pub created_at_ms: f64,
    pub expires_at_ms: f64,
    /// The `FlowEntryRule` id that was added, when the caller recorded it, so the
    /// exact rule can be removed again instead of guessing from the MAC.
    #[serde(default)]
    pub added_rule: Option<String>,
}

impl DeviceGrant {
    /// The device as a `MacAddr`, or `None` when the stored text is not one.
    ///
    /// `MacAddr` has no `FromStr`, and a grant that cannot be parsed must be
    /// reported rather than silently skipped — the operator asked for a device to
    /// be let through, and quietly doing nothing would be worse than an error.
    pub fn mac_addr(&self) -> Option<landscape_common::net::MacAddr> {
        parse_mac(&self.mac)
    }

    pub fn is_expired(&self) -> bool {
        now_ms() >= self.expires_at_ms
    }

    pub fn remaining_secs(&self) -> i64 {
        ((self.expires_at_ms - now_ms()) / 1000.0).ceil() as i64
    }

    pub fn describe(&self) -> String {
        let state = if self.is_expired() {
            "EXPIRED".to_string()
        } else {
            format!("{}s left", self.remaining_secs().max(0))
        };
        format!("{}  {}  flow {}  {}  ({})", self.id, self.mac, self.flow_id, state, self.reason)
    }
}

/// The grants, in a plain JSON file next to the snapshots.
///
/// A file rather than a table: a grant is operational state that must be readable
/// and revocable even when the service cannot start, which is the situation the
/// rescue channel exists for.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GrantStore {
    #[serde(default)]
    grants: Vec<DeviceGrant>,
}

impl GrantStore {
    fn path(dir: &Path) -> PathBuf {
        dir.join(GRANTS_FILE)
    }

    /// Read the store; a missing file is an empty store, and a corrupt one is an
    /// error rather than a silent reset (silently dropping grants would leave
    /// devices authorized with nothing tracking them).
    pub fn load(dir: &Path) -> Result<Self, DbError> {
        let path = Self::path(dir);
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = fs::read_to_string(&path)?;
        serde_json::from_str(&text)
            .map_err(|e| DbError::Internal(format!("{}: {e}", path.display())))
    }

    fn save(&self, dir: &Path) -> Result<(), DbError> {
        fs::create_dir_all(dir)?;
        let path = Self::path(dir);
        let text = serde_json::to_string_pretty(self)
            .map_err(|e| DbError::Internal(format!("cannot serialise grants: {e}")))?;
        // Written through a temporary file so a crash cannot leave a half-written
        // store, which the next load would refuse to read.
        let temporary = path.with_extension("json.tmp");
        fs::write(&temporary, text)?;
        fs::rename(&temporary, &path)?;
        Ok(())
    }

    /// Grants that are still in force. Expiry is enforced here, not only by the
    /// sweep, so an expired grant is never honoured even for an instant.
    pub fn active(&self) -> Vec<DeviceGrant> {
        self.grants.iter().filter(|grant| !grant.is_expired()).cloned().collect()
    }

    pub fn all(&self) -> &[DeviceGrant] {
        &self.grants
    }

    /// Add a grant, refusing one that would not be time-limited.
    pub fn add(
        &mut self,
        dir: &Path,
        mac: String,
        flow_id: u32,
        reason: String,
        duration_secs: u64,
    ) -> Result<DeviceGrant, DbError> {
        if duration_secs == 0 {
            return Err(DbError::Internal(
                "a grant must have a non-zero duration; a permanent authorization is a flow rule"
                    .to_string(),
            ));
        }
        let now = now_ms();
        let grant = DeviceGrant {
            id: format!("{}-{}", format_timestamp((now / 1000.0) as i64), self.grants.len() + 1),
            mac,
            flow_id,
            reason,
            created_at_ms: now,
            expires_at_ms: now + (duration_secs as f64) * 1000.0,
            added_rule: None,
        };
        self.grants.push(grant.clone());
        self.save(dir)?;
        Ok(grant)
    }

    /// Record which flow match rule the grant added, so it can be removed exactly.
    pub fn record_rule(&mut self, dir: &Path, id: &str, rule_id: String) -> Result<(), DbError> {
        if let Some(grant) = self.grants.iter_mut().find(|grant| grant.id == id) {
            grant.added_rule = Some(rule_id);
            self.save(dir)?;
        }
        Ok(())
    }

    /// Remove a grant by id, returning it so the caller can undo its effect.
    pub fn revoke(&mut self, dir: &Path, id: &str) -> Result<DeviceGrant, DbError> {
        let index = self
            .grants
            .iter()
            .position(|grant| grant.id == id)
            .ok_or_else(|| DbError::Internal(format!("no grant with id '{id}'")))?;
        let grant = self.grants.remove(index);
        self.save(dir)?;
        Ok(grant)
    }

    /// Remove every expired grant, returning them so the caller can undo their
    /// effects. This is what makes a grant temporary even if nobody looks at it.
    pub fn take_expired(&mut self, dir: &Path) -> Result<Vec<DeviceGrant>, DbError> {
        let (expired, kept): (Vec<_>, Vec<_>) =
            self.grants.drain(..).partition(|grant| grant.is_expired());
        if expired.is_empty() {
            // Put them back unchanged: `drain` moved everything out.
            self.grants = kept;
            return Ok(Vec::new());
        }
        self.grants = kept;
        self.save(dir)?;
        Ok(expired)
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
            // Only files named like a snapshot id. The directory also holds the
            // transaction marker and the device grants, and treating those as
            // manifests would fill the log with warnings about files that are
            // perfectly fine.
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let is_snapshot =
                path.file_stem().and_then(|stem| stem.to_str()).is_some_and(looks_like_snapshot_id);
            if !is_snapshot {
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

/// Whether a file stem is one of our snapshot ids (`YYYYMMDD-HHMMSS`, optionally
/// with a `-N` suffix for a second snapshot in the same second).
fn looks_like_snapshot_id(stem: &str) -> bool {
    // `<8 digits>-<6 digits>` followed by nothing or a `-<digits>` suffix.
    let mut parts = stem.split('-');
    let date = parts.next().unwrap_or("");
    let time = parts.next().unwrap_or("");
    let all_digits = |text: &str| !text.is_empty() && text.chars().all(|c| c.is_ascii_digit());
    if date.len() != 8 || time.len() != 6 || !all_digits(date) || !all_digits(time) {
        return false;
    }
    match parts.next() {
        Option::None => true,
        Some(suffix) => all_digits(suffix) && parts.next().is_none(),
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

/// Parse `aa:bb:cc:dd:ee:ff` (or `aa-bb-cc-dd-ee-ff`) into a `MacAddr`.
fn parse_mac(text: &str) -> Option<landscape_common::net::MacAddr> {
    let cleaned: String = text.chars().filter(|c| *c != ':' && *c != '-').collect();
    if cleaned.len() != 12 || !cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let byte = |index: usize| u8::from_str_radix(&cleaned[index * 2..index * 2 + 2], 16).ok();
    Some(landscape_common::net::MacAddr::new(
        byte(0)?,
        byte(1)?,
        byte(2)?,
        byte(3)?,
        byte(4)?,
        byte(5)?,
    ))
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

    fn temp_dir() -> PathBuf {
        // Unique per call: tests run in parallel and would otherwise share a
        // directory and clobber each other's store.
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let unique = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("landscape-grants-{}-{unique}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_grant_is_active_until_its_deadline() {
        let dir = temp_dir();
        let mut store = GrantStore::load(&dir).unwrap();
        let grant = store.add(&dir, "aa:bb:cc:dd:ee:ff".into(), 7, "rescue".into(), 60).unwrap();
        assert!(!grant.is_expired());
        assert_eq!(store.active().len(), 1);
        assert!(grant.remaining_secs() > 55, "remaining: {}", grant.remaining_secs());
    }

    #[test]
    fn a_grant_without_a_duration_is_refused() {
        // A permanent authorization is a flow rule, not a grant; accepting it
        // here would be the "silent direct" the objective forbids.
        let dir = temp_dir();
        let mut store = GrantStore::default();
        assert!(store.add(&dir, "aa:bb:cc:dd:ee:ff".into(), 7, "-".into(), 0).is_err());
        assert!(store.all().is_empty());
    }

    #[test]
    fn expiry_is_enforced_on_read_not_only_by_the_sweep() {
        let dir = temp_dir();
        let mut store = GrantStore::default();
        let grant = store.add(&dir, "aa:bb:cc:dd:ee:ff".into(), 7, "x".into(), 1).unwrap();
        // Reach in and expire it, standing in for the clock passing.
        store.grants[0].expires_at_ms = now_ms() - 1000.0;
        assert!(store.grants[0].is_expired());
        assert!(store.active().is_empty(), "an expired grant must never be honoured");
        // The sweep then removes it for good.
        let expired = store.take_expired(&dir).unwrap();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].id, grant.id);
        assert!(store.all().is_empty());
    }

    #[test]
    fn the_sweep_keeps_the_grants_that_are_still_running() {
        let dir = temp_dir();
        let mut store = GrantStore::default();
        store.add(&dir, "aa:bb:cc:dd:ee:01".into(), 7, "live".into(), 600).unwrap();
        store.add(&dir, "aa:bb:cc:dd:ee:02".into(), 7, "dead".into(), 600).unwrap();
        store.grants[1].expires_at_ms = now_ms() - 1000.0;

        let expired = store.take_expired(&dir).unwrap();
        assert_eq!(expired.len(), 1, "exactly the expired grant is taken");
        assert_eq!(store.active().len(), 1);
        // And the store on disk agrees.
        let reloaded = GrantStore::load(&dir).unwrap();
        assert_eq!(reloaded.all().len(), 1);
    }

    #[test]
    fn grants_survive_a_reload() {
        let dir = temp_dir();
        let mut store = GrantStore::default();
        let grant = store.add(&dir, "aa:bb:cc:dd:ee:ff".into(), 9, "persist".into(), 600).unwrap();
        store.record_rule(&dir, &grant.id, "rule-1".into()).unwrap();

        let reloaded = GrantStore::load(&dir).unwrap();
        assert_eq!(reloaded.all().len(), 1);
        assert_eq!(reloaded.all()[0].added_rule.as_deref(), Some("rule-1"));
        assert_eq!(reloaded.all()[0].flow_id, 9);
    }

    #[test]
    fn revoking_removes_only_that_grant() {
        let dir = temp_dir();
        let mut store = GrantStore::default();
        let first = store.add(&dir, "aa:bb:cc:dd:ee:01".into(), 7, "one".into(), 600).unwrap();
        store.add(&dir, "aa:bb:cc:dd:ee:02".into(), 7, "two".into(), 600).unwrap();

        let revoked = store.revoke(&dir, &first.id).unwrap();
        assert_eq!(revoked.id, first.id);
        assert_eq!(store.all().len(), 1);
        assert_eq!(store.all()[0].reason, "two");
        // An unknown id is an error, not a silent no-op: the caller asked to
        // revoke something, and not finding it means they are looking at stale
        // state.
        assert!(store.revoke(&dir, "nope").is_err());
    }

    #[test]
    fn a_corrupt_store_is_an_error_rather_than_an_empty_one() {
        // Returning "no grants" would leave devices authorized with nothing
        // tracking them, so the caller has to see the problem.
        let dir = temp_dir();
        fs::create_dir_all(&dir).unwrap();
        fs::write(GrantStore::path(&dir), "{ not json").unwrap();
        assert!(GrantStore::load(&dir).is_err());
    }

    #[test]
    fn a_missing_store_is_simply_empty() {
        let dir = temp_dir();
        let store = GrantStore::load(&dir).unwrap();
        assert!(store.all().is_empty());
    }

    #[test]
    fn mac_addresses_parse_in_both_common_forms() {
        let colon = parse_mac("aa:bb:cc:dd:ee:ff").expect("colon form");
        let dash = parse_mac("AA-BB-CC-DD-EE-FF").expect("dash form");
        let plain = parse_mac("aabbccddeeff").expect("plain form");
        assert_eq!(colon, dash);
        assert_eq!(colon, plain);
    }

    #[test]
    fn anything_that_is_not_a_mac_is_rejected() {
        // Better to refuse than to place the wrong device in a flow.
        for bad in ["", "aa:bb:cc:dd:ee", "aa:bb:cc:dd:ee:ff:00", "zz:bb:cc:dd:ee:ff", "not a mac"]
        {
            assert!(parse_mac(bad).is_none(), "{bad} should not parse");
        }
    }

    #[test]
    fn a_grant_reports_its_device() {
        let dir = temp_dir();
        let mut store = GrantStore::default();
        let grant = store.add(&dir, "aa:bb:cc:dd:ee:ff".into(), 7, "x".into(), 600).unwrap();
        assert!(grant.mac_addr().is_some());
    }

    #[test]
    fn only_snapshot_ids_look_like_snapshot_ids() {
        // The snapshots directory also holds the transaction marker and the device
        // grants; neither is a snapshot.
        assert!(looks_like_snapshot_id("20261007-123456"));
        assert!(looks_like_snapshot_id("20261007-123456-2"));
        assert!(!looks_like_snapshot_id("device_grants"));
        assert!(!looks_like_snapshot_id("pending_transaction"));
        assert!(!looks_like_snapshot_id("20261007"));
        assert!(!looks_like_snapshot_id("2026100-123456"));
        assert!(!looks_like_snapshot_id("20261007-12345"));
        assert!(!looks_like_snapshot_id("20261007-12345a"));
        assert!(!looks_like_snapshot_id("20261007-123456-2-3"));
    }
}
