use super::*;

pub(crate) const CONFIG_KEY_PREFIX: &str = "astrolabe.calyx.";

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum MigrationDial {
    Off,
    Shadow,
}

impl MigrationDial {
    pub(crate) fn parse(value: &Value) -> Result<Self, String> {
        match value.as_str() {
            Some("off") => Ok(Self::Off),
            Some("shadow") => Ok(Self::Shadow),
            Some(other) => Err(format!(
                "invalid calyx dial {other:?}; expected \"off\" or \"shadow\""
            )),
            None => Err("invalid calyx dial; expected string \"off\" or \"shadow\"".to_string()),
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Shadow => "shadow",
        }
    }
}

pub(crate) fn read_config_u64(
    cache_dir: &Path,
    project: &str,
    key: &str,
) -> Result<Option<u64>, DynError> {
    Ok(read_config_value(cache_dir, &metadata_key(project, key))?
        .and_then(|value| value.parse::<u64>().ok()))
}

pub(crate) fn persist_dial(project: &str, dial: MigrationDial) -> Result<(), DynError> {
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    persist_dial_at(&cache_dir, project, dial)
}

pub(crate) fn read_dial(project: &str) -> Result<MigrationDial, DynError> {
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    read_dial_at(&cache_dir, project)
}

pub(crate) fn persist_dial_at(
    cache_dir: &Path,
    project: &str,
    dial: MigrationDial,
) -> Result<(), DynError> {
    write_config_value(cache_dir, &dial_key(project), dial.as_str())
}

pub(crate) fn read_dial_at(cache_dir: &Path, project: &str) -> Result<MigrationDial, DynError> {
    let Some(value) = read_config_value(cache_dir, &dial_key(project))? else {
        return Ok(MigrationDial::Off);
    };
    // A present-but-unrecognized persisted value is corrupt or from an
    // incompatible version — fail closed with a named, actionable error instead
    // of silently coercing to Off (which would disable all shadow wrapping and
    // surface confusing "requires calyx shadow indexing" refusals downstream).
    // Absence of the row is handled above as the legitimate unconfigured default.
    match value.as_str() {
        "shadow" => Ok(MigrationDial::Shadow),
        "off" => Ok(MigrationDial::Off),
        other => Err(format!(
            "ASTRO_MIGRATION_DIAL_CORRUPT: persisted calyx dial for project {project:?} is {other:?}, \
             expected \"off\" or \"shadow\"; the stored migration state is corrupt or from an \
             incompatible version. Remediation: re-issue a request with calyx=\"off\" or \
             calyx=\"shadow\" for this project to overwrite the invalid persisted dial."
        )
        .into()),
    }
}

pub(crate) fn read_config_value(cache_dir: &Path, key: &str) -> Result<Option<String>, DynError> {
    let conn = open_config(cache_dir)?;
    Ok(conn
        .query_row(
            "SELECT value FROM config WHERE key = ?",
            params![key],
            |row| row.get(0),
        )
        .optional()?)
}

/// Reads every `(key, value)` config row whose key starts with `prefix`, ordered
/// by key ascending for deterministic enumeration.
///
/// `_` and `%` in `prefix` are escaped so a literal metadata prefix (which
/// contains neither today, but might) is matched exactly rather than as a LIKE
/// wildcard. Used to enumerate the persisted per-axis assay cards behind the
/// `get_architecture` `signal_ranking` aspect (#43).
pub(crate) fn scan_config_prefix(
    cache_dir: &Path,
    prefix: &str,
) -> Result<Vec<(String, String)>, DynError> {
    let conn = open_config(cache_dir)?;
    let escaped = prefix
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    let pattern = format!("{escaped}%");
    let mut stmt =
        conn.prepare("SELECT key, value FROM config WHERE key LIKE ? ESCAPE '\\' ORDER BY key")?;
    let rows = stmt.query_map(params![pattern], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

pub(crate) fn write_config_value(cache_dir: &Path, key: &str, value: &str) -> Result<(), DynError> {
    let conn = open_config(cache_dir)?;
    conn.execute(
        "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
        params![key, value],
    )?;
    Ok(())
}

/// Removes a config key.
///
/// Idempotent: deleting an absent key succeeds and is a no-op, so a compensating rollback of
/// a failed write-then-readback verification (#122) is safe to retry.
pub(crate) fn delete_config_value(cache_dir: &Path, key: &str) -> Result<(), DynError> {
    let conn = open_config(cache_dir)?;
    conn.execute("DELETE FROM config WHERE key = ?", params![key])?;
    Ok(())
}

/// SQLITE_BUSY retry window for the shared config store — an operational
/// resilience timeout under cross-process access (multiple agent MCP processes
/// on one repo, #76), not a result-determining threshold.
pub(crate) const CONFIG_DB_BUSY_TIMEOUT_MS: u64 = 5_000;

pub(crate) fn open_config(cache_dir: &Path) -> Result<Connection, DynError> {
    fs::create_dir_all(cache_dir)?;
    let db_path = cache_dir.join("_config.db");
    // Concurrency + durability hardening for the per-project config store, which
    // multiple agent MCP processes may touch on one repo (#76): WAL lets a writer
    // proceed alongside concurrent readers; synchronous=NORMAL stays crash-safe
    // under WAL without an fsync per commit; busy_timeout retries transient
    // SQLITE_BUSY instead of failing the server.
    //
    // The subtle part is establishing WAL. journal_mode=WAL is a *persistent*
    // DB-header property, but the one-time DELETE->WAL conversion must promote a
    // SHARED lock to EXCLUSIVE. When two processes open a fresh (DELETE-mode)
    // store concurrently, one process's conversion tries to upgrade while the
    // other holds SHARED, and SQLite deliberately returns SQLITE_BUSY *without
    // invoking the busy handler* to avoid a lock-upgrade deadlock — so
    // busy_timeout provably cannot cover the conversion (SQLite busy_handler
    // docs; wal.html §9). The conversion can also silently return the *unchanged*
    // mode when it cannot get the lock. Both surfaced as intermittent
    // "database is locked" rc=1 on the two-process index_status path (#76).
    //
    // Fix: retry the whole open with bounded backoff. The conversion is a
    // momentary upgrade and opens are transient, so a quiet window admits it
    // quickly; and because WAL is persistent, the first process to win converts
    // the store *permanently* — every later open in both processes then reads
    // "wal" and takes the pure-read fast path with no upgrade at all. After the
    // bounded window we fail closed with a coded, retryable error rather than
    // silently degrading the store to rollback-mode serialization.
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_millis(CONFIG_DB_BUSY_TIMEOUT_MS);
    // PID-derived phase offset so two racing processes back off on distinct
    // schedules and cannot livelock retrying the conversion in lockstep.
    let jitter = (std::process::id() % 8) as u64;
    let mut attempt: u64 = 0;
    loop {
        match try_open_config(&db_path) {
            Ok(Some(conn)) => return Ok(conn),
            // Conversion did not engage this round (unchanged mode returned); retry.
            Ok(None) => {}
            // Lock-upgrade SQLITE_BUSY the busy handler skipped; retry.
            Err(err) if is_sqlite_busy(&err) => {}
            // Any other rusqlite error is a genuine fault — fail closed.
            Err(err) => return Err(err.into()),
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "ASTRO_CONFIG_DB_WAL_CONTENDED: could not establish WAL journal mode on \
                 {cache}/_config.db within {CONFIG_DB_BUSY_TIMEOUT_MS}ms of retries; another \
                 client is holding it in a conflicting journal mode or lock. Remediation: retry \
                 the request; if it persists, ensure no non-WAL SQLite client (e.g. a manual \
                 sqlite3 session) holds this store open.",
                cache = cache_dir.display(),
            )
            .into());
        }
        attempt += 1;
        let backoff = (attempt.min(16) * 2 + jitter).min(64);
        std::thread::sleep(std::time::Duration::from_millis(backoff));
    }
}

/// One attempt to open and configure the shared config store.
///
/// - `Ok(Some(conn))` — opened, WAL confirmed, `config` table ensured.
/// - `Ok(None)` — the DELETE->WAL conversion did not engage (the pragma returned the
///   unchanged mode because another connection held the DB open); the caller should retry.
/// - `Err(_)` — a rusqlite error; the caller retries on SQLITE_BUSY and fails closed otherwise.
///
/// A fresh `Connection` is opened per attempt so a failed attempt releases every lock it
/// held before the caller backs off, guaranteeing a lock-free window can open for the
/// conversion.
fn try_open_config(db_path: &Path) -> Result<Option<Connection>, rusqlite::Error> {
    // #412: extended-length (`\\?\`) normalization so the config store under a deep
    // CBM_CACHE_DIR (total path > MAX_PATH) opens instead of failing closed. A
    // normalization failure is surfaced as a rusqlite CANTOPEN so the caller's
    // fail-closed path handles it exactly like any other open error.
    let open_path = astrolabe_domain::winpath::sqlite_open_path(db_path).map_err(|error| {
        rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CANTOPEN),
            Some(format!("normalize config store path: {error}")),
        )
    })?;
    let conn = Connection::open(&open_path)?;
    conn.busy_timeout(std::time::Duration::from_millis(CONFIG_DB_BUSY_TIMEOUT_MS))?;
    // Per-connection (not persisted), so set on every open.
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    let journal_mode: String = conn.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        // query_row (not execute_batch) so the resulting mode is observed, not swallowed.
        let engaged: String = conn.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
        if !engaged.eq_ignore_ascii_case("wal") {
            return Ok(None);
        }
    }
    conn.execute(
        "CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)",
        [],
    )?;
    Ok(Some(conn))
}

/// True for the two retryable SQLite lock-contention codes — SQLITE_BUSY (the lock-upgrade
/// case the busy handler deliberately skips) and SQLITE_LOCKED — so `open_config` retries
/// them within its bounded window instead of surfacing a spurious "database is locked".
fn is_sqlite_busy(err: &rusqlite::Error) -> bool {
    matches!(
        err,
        rusqlite::Error::SqliteFailure(e, _)
            if e.code == rusqlite::ErrorCode::DatabaseBusy
                || e.code == rusqlite::ErrorCode::DatabaseLocked
    )
}

pub(crate) fn dial_key(project: &str) -> String {
    format!("{CONFIG_KEY_PREFIX}{project}")
}

pub(crate) fn metadata_key(project: &str, key: &str) -> String {
    format!("{CONFIG_KEY_PREFIX}{project}.{key}")
}
