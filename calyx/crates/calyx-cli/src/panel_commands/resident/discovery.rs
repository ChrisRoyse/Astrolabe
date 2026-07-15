use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::{CliError, CliResult};

/// Schema tag for the resident-service discovery file. Bump when the shape
/// changes so stale readers fail closed instead of misinterpreting fields.
pub(crate) const RESIDENT_DISCOVERY_SCHEMA: &str = "calyx-panel-resident-discovery-v1";

/// Well-known discovery record written by `calyx panel resident serve` under
/// `<CALYX_HOME>/resident/discovery.json`. Consumers (ingest route resolution)
/// treat every anomaly as "no discovered route" and record the reason; the
/// fail-closed enforcement happens at the GPU measurement gate, so a corrupt
/// or stale file never silently degrades a CPU-only ingest.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ResidentDiscovery {
    pub(crate) schema: String,
    pub(crate) bind: SocketAddr,
    pub(crate) process_id: u32,
    /// Canonicalized vault path when the service warmed from `--vault`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) vault: Option<PathBuf>,
    /// Template selector when the service warmed from `--template`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) template: Option<String>,
    pub(crate) written_at_unix_ms: u64,
}

pub(crate) fn resident_discovery_path(home: &Path) -> PathBuf {
    home.join("resident").join("discovery.json")
}

pub(crate) fn write_resident_discovery(
    home: &Path,
    discovery: &ResidentDiscovery,
) -> CliResult<PathBuf> {
    let path = resident_discovery_path(home);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            CliError::io(format!(
                "create resident discovery dir {}: {error}",
                parent.display()
            ))
        })?;
    }
    let bytes = serde_json::to_vec_pretty(discovery)
        .map_err(|error| CliError::runtime(format!("serialize resident discovery: {error}")))?;
    std::fs::write(&path, bytes).map_err(|error| {
        CliError::io(format!(
            "write resident discovery file {}: {error}",
            path.display()
        ))
    })?;
    Ok(path)
}

/// Read the discovery file. `Ok(None)` means "not discoverable" (missing file);
/// parse/schema anomalies also resolve to `Ok(None)` with the reason returned so
/// the caller can surface it at the GPU gate — see the struct-level contract.
pub(crate) fn read_resident_discovery(
    home: &Path,
) -> CliResult<Result<ResidentDiscovery, &'static str>> {
    let path = resident_discovery_path(home);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Err("no_discovery_file"));
        }
        Err(error) => {
            return Err(CliError::io(format!(
                "read resident discovery file {}: {error}",
                path.display()
            )));
        }
    };
    let Ok(discovery) = serde_json::from_slice::<ResidentDiscovery>(&bytes) else {
        return Ok(Err("discovery_file_unparseable"));
    };
    if discovery.schema != RESIDENT_DISCOVERY_SCHEMA {
        return Ok(Err("discovery_schema_mismatch"));
    }
    if !discovery.bind.ip().is_loopback() {
        return Ok(Err("discovery_addr_not_loopback"));
    }
    Ok(Ok(discovery))
}

pub(crate) fn remove_resident_discovery(home: &Path, process_id: u32) -> CliResult<()> {
    let path = resident_discovery_path(home);
    // Only remove a record this process wrote; a newer service instance may
    // have already replaced it.
    match read_resident_discovery(home)? {
        Ok(discovery) if discovery.process_id == process_id => {
            std::fs::remove_file(&path).map_err(|error| {
                CliError::io(format!(
                    "remove resident discovery file {}: {error}",
                    path.display()
                ))
            })
        }
        _ => Ok(()),
    }
}

pub(crate) fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

