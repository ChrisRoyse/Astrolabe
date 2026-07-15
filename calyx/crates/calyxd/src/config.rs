//! `CalyxConfig` — the single authoritative runtime configuration for `calyxd`
//! (PH65 · T01).
//!
//! Every daemon tunable (bind address, vault path, VRAM budget, log directory,
//! healthcheck output path, TEI endpoints) is declared here with a documented
//! key and populated from a TOML file (`calyx.toml`). Secrets
//! never appear in the config struct or file — they enter via environment
//! variables or an environment-rendered secret file. Validation is fail-closed:
//! a non-loopback bind address, an out-of-range VRAM budget, a missing key, or
//! a TOML syntax error each yields a stable `CALYX_*` error, never a silent
//! default.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use calyx_core::MtlsConfig;
use serde::Deserialize;

use crate::error::DaemonError;
use crate::learner_origin::LearnerOriginConfig;

/// Upper bound on the VRAM the daemon may budget for Forge, in MiB.
///
/// Conservative ceiling for high-memory CUDA devices; leaves headroom for
/// co-resident GPU services and CUDA context overhead.
const VRAM_BUDGET_MIB_CEILING: u32 = 30_000;

/// Environment variable interpolated into `vault_path` for portability.
const VAULT_PATH_HOME_VAR: &str = "CALYX_HOME";

fn default_bind_addr() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 7700))
}

fn default_health_log_path() -> PathBuf {
    PathBuf::from("/zfs/hot/logs/calyx-health/latest.json")
}

fn default_healthcheck_timeout_secs() -> u32 {
    30
}

/// Authoritative runtime configuration for the Calyx daemon.
///
/// Constructed only via [`CalyxConfig::from_file`] / [`CalyxConfig::from_toml_str`],
/// both of which run [`CalyxConfig::validate`] before returning. An instance
/// therefore always upholds the invariants: loopback bind address and
/// `0 < vram_budget_mib <= VRAM_BUDGET_MIB_CEILING`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalyxConfig {
    /// Loopback address the daemon listens on. Default `127.0.0.1:7700`.
    #[serde(default = "default_bind_addr")]
    pub bind_addr: SocketAddr,
    /// Optional loopback MCP socket bind address. Must be distinct from
    /// [`bind_addr`] when both ports are fixed; `:0` is allowed for tests.
    #[serde(default)]
    pub mcp_bind_addr: Option<SocketAddr>,
    /// Aster vault directory. May contain `$CALYX_HOME` — see
    /// [`CalyxConfig::vault_path_resolved`]. Required (no default).
    pub vault_path: PathBuf,
    /// VRAM budget for Forge, in MiB. Required; must be `1..=30000`.
    pub vram_budget_mib: u32,
    /// Directory for daemon logs. Required (no default).
    pub log_dir: PathBuf,
    /// Path the healthcheck JSON is written to.
    /// Default `/zfs/hot/logs/calyx-health/latest.json`.
    #[serde(default = "default_health_log_path")]
    pub health_log_path: PathBuf,
    /// Text-Embeddings-Inference endpoints (Calyx-owned plus legacy/manual).
    #[serde(default)]
    pub tei_endpoints: Vec<String>,
    /// Healthcheck timeout in seconds. Default `30`.
    #[serde(default = "default_healthcheck_timeout_secs")]
    pub healthcheck_timeout_secs: u32,
    /// Optional MCP mTLS block. MCP startup requires this; config parsing keeps
    /// it optional so non-MCP daemon tasks can still load minimal config.
    #[serde(default)]
    pub mcp_mtls: Option<MtlsConfig>,
    /// Optional Worker-only learner-origin API backed by a dedicated Aster vault.
    #[serde(default)]
    pub learner_origin: Option<LearnerOriginConfig>,
}

impl CalyxConfig {
    /// Parse and validate a config from a TOML string.
    ///
    /// A syntax error wraps the underlying parse failure (`CALYX_DAEMON_CONFIG_INVALID`);
    /// a missing required key yields a descriptive `CALYX_DAEMON_CONFIG_INVALID`;
    /// a non-loopback `bind_addr` yields `CALYX_DAEMON_BIND_FAILED`; an
    /// out-of-range `vram_budget_mib` yields `CALYX_FORGE_VRAM_BUDGET`.
    pub fn from_toml_str(text: &str) -> Result<Self, DaemonError> {
        let parsed: CalyxConfig = toml::from_str(text)
            .map_err(|error| DaemonError::config_invalid(format!("parse calyx config: {error}")))?;
        parsed.validate()
    }

    /// Read, parse, and validate a config from a TOML file on disk.
    pub fn from_file(path: &Path) -> Result<Self, DaemonError> {
        let bytes = std::fs::read(path).map_err(|error| {
            DaemonError::config_invalid(format!("read {}: {error}", path.display()))
        })?;
        let text = std::str::from_utf8(&bytes).map_err(|error| {
            DaemonError::config_invalid(format!("{} is not UTF-8: {error}", path.display()))
        })?;
        Self::from_toml_str(text)
    }

    /// Enforce the fail-closed invariants. Consumes and returns `self` so the
    /// only way to obtain a `CalyxConfig` is through a validated path.
    fn validate(self) -> Result<Self, DaemonError> {
        if !self.bind_addr.ip().is_loopback() {
            return Err(DaemonError::bind_failed(format!(
                "bind_addr {} is not loopback; calyxd must bind 127.0.0.1 or [::1]",
                self.bind_addr
            )));
        }
        if let Some(addr) = self.mcp_bind_addr {
            if !addr.ip().is_loopback() {
                return Err(DaemonError::bind_failed(format!(
                    "mcp_bind_addr {addr} is not loopback; calyxd MCP must bind 127.0.0.1 or [::1]",
                )));
            }
            if addr == self.bind_addr && addr.port() != 0 {
                return Err(DaemonError::bind_failed(format!(
                    "mcp_bind_addr {addr} conflicts with metrics bind_addr {}; configure a distinct loopback port",
                    self.bind_addr
                )));
            }
        }
        if self.vram_budget_mib == 0 || self.vram_budget_mib > VRAM_BUDGET_MIB_CEILING {
            return Err(DaemonError::vram_budget(format!(
                "vram_budget_mib {} out of range (must be 1..={VRAM_BUDGET_MIB_CEILING}); \
                 leave headroom for co-resident GPU services",
                self.vram_budget_mib
            )));
        }
        if let Some(mtls) = &self.mcp_mtls {
            validate_mcp_mtls(mtls)?;
            if self.mcp_bind_addr.is_none() {
                return Err(DaemonError::config_invalid(
                    "mcp_mtls is configured but mcp_bind_addr is missing; set a distinct loopback MCP port",
                ));
            }
        } else if self.mcp_bind_addr.is_some() {
            return Err(DaemonError::tls_config_invalid(
                "mcp_bind_addr is configured but mcp_mtls is missing",
            ));
        }
        if let Some(origin) = &self.learner_origin {
            origin.validate(&self.vault_path, &self.vault_path_resolved())?;
        }
        Ok(self)
    }

    /// `vault_path` with `$CALYX_HOME` / `${CALYX_HOME}` expanded from the
    /// environment. When the variable is unset the raw path is returned
    /// unchanged, so config files stay portable across dev and production.
    pub fn vault_path_resolved(&self) -> PathBuf {
        resolve_home(&self.vault_path, std::env::var(VAULT_PATH_HOME_VAR).ok())
    }
}

fn validate_mcp_mtls(mtls: &MtlsConfig) -> Result<(), DaemonError> {
    if !mtls.require_client_cert {
        return Err(DaemonError::tls_config_invalid(
            "mcp_mtls.require_client_cert must be true; anonymous MCP clients are refused",
        ));
    }
    if mtls.tls.ca_pem_path.is_none() {
        return Err(DaemonError::tls_config_invalid(
            "mcp_mtls.tls.ca_pem_path is required when client certificates are required",
        ));
    }
    mtls.tls.validate().map_err(|error| {
        DaemonError::tls_config_invalid(format!("{}: {}", error.code, error.message))
    })
}

/// Pure interpolation helper: substitute `home` for `$CALYX_HOME`/`${CALYX_HOME}`
/// when `Some`, otherwise return the path unchanged. Separated from
/// [`CalyxConfig::vault_path_resolved`] so it is testable without mutating the
/// process environment (which is `unsafe` under edition 2024 and racy).
fn resolve_home(path: &Path, home: Option<String>) -> PathBuf {
    match home {
        Some(home) => PathBuf::from(
            path.to_string_lossy()
                .replace("${CALYX_HOME}", &home)
                .replace("$CALYX_HOME", &home),
        ),
        None => path.to_path_buf(),
    }
}
