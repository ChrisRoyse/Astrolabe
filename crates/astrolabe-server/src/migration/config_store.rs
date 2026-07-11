use super::*;

pub(crate) const CONFIG_KEY_PREFIX: &str = "astrolabe.calyx.";

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum MigrationDial {
    Off,
    Shadow,
}

impl MigrationDial {
    fn parse(value: &Value) -> Result<Self, String> {
        match value.as_str() {
            Some("off") => Ok(Self::Off),
            Some("shadow") => Ok(Self::Shadow),
            Some(other) => Err(format!(
                "invalid calyx dial {other:?}; expected \"off\" or \"shadow\""
            )),
            None => Err("invalid calyx dial; expected string \"off\" or \"shadow\"".to_string()),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Shadow => "shadow",
        }
    }
}

pub(crate) fn read_config_u64(cache_dir: &Path, project: &str, key: &str) -> Result<Option<u64>, DynError> {
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

pub(crate) fn persist_dial_at(cache_dir: &Path, project: &str, dial: MigrationDial) -> Result<(), DynError> {
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

pub(crate) fn write_config_value(cache_dir: &Path, key: &str, value: &str) -> Result<(), DynError> {
    let conn = open_config(cache_dir)?;
    conn.execute(
        "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
        params![key, value],
    )?;
    Ok(())
}

/// SQLITE_BUSY retry window for the shared config store — an operational
/// resilience timeout under cross-process access (multiple agent MCP processes
/// on one repo, #76), not a result-determining threshold.
pub(crate) const CONFIG_DB_BUSY_TIMEOUT_MS: u64 = 5_000;

pub(crate) fn open_config(cache_dir: &Path) -> Result<Connection, DynError> {
    fs::create_dir_all(cache_dir)?;
    let conn = Connection::open(cache_dir.join("_config.db"))?;
    // Concurrency + durability hardening for the per-project config store, which
    // multiple agent MCP processes may touch on one repo (#76): busy_timeout
    // retries instead of failing the server on SQLITE_BUSY; WAL lets readers
    // proceed during a writer's transaction; synchronous=NORMAL stays crash-safe
    // under WAL without an fsync per commit.
    conn.busy_timeout(std::time::Duration::from_millis(CONFIG_DB_BUSY_TIMEOUT_MS))?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)",
        [],
    )?;
    Ok(conn)
}

pub(crate) fn dial_key(project: &str) -> String {
    format!("{CONFIG_KEY_PREFIX}{project}")
}

pub(crate) fn metadata_key(project: &str, key: &str) -> String {
    format!("{CONFIG_KEY_PREFIX}{project}.{key}")
}
