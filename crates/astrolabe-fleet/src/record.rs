//! Repository record model and its constellation codec (issue #449).
//!
//! One catalogued repository is one [`Constellation`] in the fleet vault's
//! Base column family. Discovery facts live as scalars/metadata; lifecycle
//! state and per-transition timestamps live beside them so the whole record is
//! a single durable row whose every mutation pairs with a ledger entry.
//!
//! # Identity
//!
//! The record's [`CxId`] is the content address of the repository identity —
//! [`repo_identity_bytes`] over `github_id` + `full_name` — so re-discovery of
//! the same repository is idempotent: it computes the same CxId and lands on
//! the same row.

use std::collections::BTreeMap;

use calyx_core::{
    CalyxError, Constellation, CxFlags, CxId, InputRef, LedgerRef, Modality, VaultId,
};
use serde::{Deserialize, Serialize};

use crate::state::RepoState;

/// Refusal code for a structurally invalid repository record.
pub const ASTRO_FLEET_RECORD_INVALID: &str = "ASTRO_FLEET_RECORD_INVALID";
/// Refusal code for a stored catalog row that does not decode as a repo record.
pub const ASTRO_FLEET_RECORD_CORRUPT: &str = "ASTRO_FLEET_RECORD_CORRUPT";

/// Catalog schema version, doubling as the constellation `panel_version`.
///
/// Catalog rows are measured by no lens panel; the field instead versions the
/// scalar/metadata layout of fleet records. Bump on any layout change.
pub const FLEET_PANEL_VERSION: u32 = 1;

/// Versioned identity namespace fed into the content address, so fleet CxIds
/// can never collide with another domain's addressing scheme.
pub const FLEET_IDENTITY_NAMESPACE: &str = "astrolabe-fleet-repo:v1";

/// Modality recorded on catalog constellations. Fleet records are textual
/// metadata about a repository, not measured source code, so `Text`.
pub const FLEET_MODALITY: Modality = Modality::Text;

// Scalar keys (numeric discovery facts).
/// GitHub's immutable numeric repository id.
pub const SCALAR_GITHUB_ID: &str = "github_id";
/// Stargazer count at last discovery refresh.
pub const SCALAR_STARS: &str = "stars";
/// Repository size in KiB as reported by the GitHub API.
pub const SCALAR_SIZE_KB: &str = "size_kb";

// Metadata keys (verbatim string facts). `head_commit` deliberately carries a
// `_hash` suffix: the ledger secret-scanner allowlists `*_hash` fields, and a
// bare 40-hex value under another name fails the commit closed.
/// `owner/name` as reported by GitHub.
pub const META_FULL_NAME: &str = "full_name";
/// HTTPS clone URL.
pub const META_CLONE_URL: &str = "clone_url";
/// Default branch name.
pub const META_DEFAULT_BRANCH: &str = "default_branch";
/// Primary language as reported by GitHub.
pub const META_LANGUAGE: &str = "language";
/// SPDX license id, when GitHub reports one.
pub const META_LICENSE_SPDX: &str = "license_spdx";
/// Last-push timestamp verbatim from the GitHub API (RFC 3339).
pub const META_PUSHED_AT: &str = "pushed_at";
/// HTTP ETag of the last discovery response, for conditional re-discovery.
pub const META_ETAG: &str = "etag";
/// Current lifecycle state (a [`RepoState::as_str`] value).
pub const META_STATE: &str = "state";
/// Absolute path of the local clone, once cloned.
pub const META_CLONE_PATH: &str = "clone_path";
/// 40-hex commit SHA the clone/index/kernel work was grounded on.
pub const META_HEAD_COMMIT_HASH: &str = "head_commit_hash";
/// Fingerprint of the indexed SQLite artifact, once indexed.
pub const META_INDEX_WATERMARK: &str = "index_watermark";
/// Kernel scope id, once kerneled.
pub const META_KERNEL_SCOPE_ID: &str = "kernel_scope_id";
/// Recorded reason, required when quarantining.
pub const META_QUARANTINE_REASON: &str = "quarantine_reason";
/// Recorded reason, required when marking a repo departed (#450).
pub const META_DEPARTED_REASON: &str = "departed_reason";
/// Prefix of per-transition timestamp keys: `ts_<state>` = unix seconds the
/// record entered `<state>`.
pub const META_TS_PREFIX: &str = "ts_";

/// Discovery-time facts about one repository, as fed by GitHub discovery
/// (#450) or synthetic registration. Lifecycle fields live on
/// [`FleetRepoRow`], not here: registration always starts at
/// [`RepoState::Discovered`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RepoRecord {
    /// GitHub's immutable numeric repository id.
    pub github_id: u64,
    /// `owner/name`.
    pub full_name: String,
    /// HTTPS clone URL.
    pub clone_url: String,
    /// Default branch name.
    pub default_branch: String,
    /// Stargazer count at discovery.
    pub stars: u64,
    /// Primary language as reported by GitHub.
    pub language: String,
    /// SPDX license id, when GitHub reports one.
    #[serde(default)]
    pub license_spdx: Option<String>,
    /// Repository size in KiB as reported by the GitHub API.
    pub size_kb: u64,
    /// Last-push timestamp verbatim from the GitHub API (RFC 3339).
    pub pushed_at: String,
    /// HTTP ETag of the discovery response, for conditional re-discovery.
    #[serde(default)]
    pub etag: Option<String>,
}

impl RepoRecord {
    /// Validates the discovery facts fail-closed before they touch the vault.
    pub fn validate(&self) -> Result<(), CalyxError> {
        let refuse = |what: &str| CalyxError {
            code: ASTRO_FLEET_RECORD_INVALID,
            message: format!("fleet repo record invalid: {what}"),
            remediation: "supply the field exactly as the GitHub repository API reports it",
        };
        if self.github_id == 0 {
            return Err(refuse("github_id must be a positive GitHub repository id"));
        }
        let mut parts = self.full_name.split('/');
        match (parts.next(), parts.next(), parts.next()) {
            (Some(owner), Some(name), None) if !owner.is_empty() && !name.is_empty() => {}
            _ => {
                return Err(refuse(&format!(
                    "full_name {:?} must be exactly owner/name",
                    self.full_name
                )));
            }
        }
        if self.clone_url.is_empty() {
            return Err(refuse("clone_url must not be empty"));
        }
        if self.default_branch.is_empty() {
            return Err(refuse("default_branch must not be empty"));
        }
        if self.language.is_empty() {
            return Err(refuse("language must not be empty"));
        }
        if self.pushed_at.is_empty() {
            return Err(refuse("pushed_at must not be empty"));
        }
        Ok(())
    }
}

/// Mutable context accompanying a lifecycle transition: the transition
/// timestamp plus the facts the transition establishes.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct TransitionContext {
    /// Unix seconds the transition happened (caller-supplied so replays and
    /// backfills stay deterministic; the CLI defaults to now).
    pub at_unix_secs: u64,
    /// Absolute path of the local clone (normally set at `cloned`).
    #[serde(default)]
    pub clone_path: Option<String>,
    /// 40-hex commit SHA the work was grounded on.
    #[serde(default)]
    pub head_commit_hash: Option<String>,
    /// Fingerprint of the indexed SQLite artifact (normally set at `indexed`).
    #[serde(default)]
    pub index_watermark: Option<String>,
    /// Kernel scope id (normally set at `kerneled`).
    #[serde(default)]
    pub kernel_scope_id: Option<String>,
    /// Reason for quarantining; required when the target state is
    /// [`RepoState::Quarantined`].
    #[serde(default)]
    pub quarantine_reason: Option<String>,
    /// Reason for departure; required when the target state is
    /// [`RepoState::Departed`] (#450).
    #[serde(default)]
    pub departed_reason: Option<String>,
}

/// One decoded catalog row: the discovery facts plus the lifecycle fields.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct FleetRepoRow {
    /// Content-addressed identity of this repository record.
    pub cx_id: CxId,
    /// Discovery facts.
    pub record: RepoRecord,
    /// Current lifecycle state.
    pub state: RepoState,
    /// Unix seconds the record entered each state it has visited.
    pub state_timestamps: BTreeMap<String, u64>,
    /// Absolute path of the local clone, once cloned.
    pub clone_path: Option<String>,
    /// 40-hex commit SHA the work was grounded on, once recorded.
    pub head_commit_hash: Option<String>,
    /// Fingerprint of the indexed SQLite artifact, once indexed.
    pub index_watermark: Option<String>,
    /// Kernel scope id, once kerneled.
    pub kernel_scope_id: Option<String>,
    /// Recorded quarantine reason, if quarantined.
    pub quarantine_reason: Option<String>,
    /// Recorded departure reason, if departed (#450).
    pub departed_reason: Option<String>,
}

/// Canonical identity bytes of a repository record:
/// `astrolabe-fleet-repo:v1\n<github_id>\n<full_name>`.
pub fn repo_identity_bytes(github_id: u64, full_name: &str) -> Vec<u8> {
    format!("{FLEET_IDENTITY_NAMESPACE}\n{github_id}\n{full_name}").into_bytes()
}

/// Content-addressed [`CxId`] of a repository record in a vault with `salt`.
pub fn repo_cx_id(github_id: u64, full_name: &str, salt: &[u8]) -> CxId {
    CxId::from_input(
        &repo_identity_bytes(github_id, full_name),
        FLEET_PANEL_VERSION,
        salt,
    )
}

/// Encodes a catalog row into the constellation persisted in the Base CF.
///
/// `provenance` is a zeroed stub: the vault's ledger-bind step stamps the real
/// ledger ref into the Base row inside the atomic commit, which is exactly the
/// invariant-5 pairing the readback verifies.
pub fn encode_repo_constellation(
    vault_id: VaultId,
    salt: &[u8],
    row: &FleetRepoRow,
) -> Result<Constellation, CalyxError> {
    row.record.validate()?;
    let identity = repo_identity_bytes(row.record.github_id, &row.record.full_name);

    let mut scalars = BTreeMap::new();
    scalars.insert(SCALAR_GITHUB_ID.to_string(), row.record.github_id as f64);
    scalars.insert(SCALAR_STARS.to_string(), row.record.stars as f64);
    scalars.insert(SCALAR_SIZE_KB.to_string(), row.record.size_kb as f64);

    let mut metadata = BTreeMap::new();
    metadata.insert(META_FULL_NAME.to_string(), row.record.full_name.clone());
    metadata.insert(META_CLONE_URL.to_string(), row.record.clone_url.clone());
    metadata.insert(
        META_DEFAULT_BRANCH.to_string(),
        row.record.default_branch.clone(),
    );
    metadata.insert(META_LANGUAGE.to_string(), row.record.language.clone());
    metadata.insert(META_PUSHED_AT.to_string(), row.record.pushed_at.clone());
    metadata.insert(META_STATE.to_string(), row.state.as_str().to_string());
    if let Some(license) = &row.record.license_spdx {
        metadata.insert(META_LICENSE_SPDX.to_string(), license.clone());
    }
    if let Some(etag) = &row.record.etag {
        metadata.insert(META_ETAG.to_string(), etag.clone());
    }
    if let Some(clone_path) = &row.clone_path {
        metadata.insert(META_CLONE_PATH.to_string(), clone_path.clone());
    }
    if let Some(head) = &row.head_commit_hash {
        metadata.insert(META_HEAD_COMMIT_HASH.to_string(), head.clone());
    }
    if let Some(watermark) = &row.index_watermark {
        metadata.insert(META_INDEX_WATERMARK.to_string(), watermark.clone());
    }
    if let Some(scope) = &row.kernel_scope_id {
        metadata.insert(META_KERNEL_SCOPE_ID.to_string(), scope.clone());
    }
    if let Some(reason) = &row.quarantine_reason {
        metadata.insert(META_QUARANTINE_REASON.to_string(), reason.clone());
    }
    if let Some(reason) = &row.departed_reason {
        metadata.insert(META_DEPARTED_REASON.to_string(), reason.clone());
    }
    for (key, at) in &row.state_timestamps {
        metadata.insert(format!("{META_TS_PREFIX}{key}"), at.to_string());
    }

    let discovered_at = row
        .state_timestamps
        .get(RepoState::Discovered.as_str())
        .copied()
        .unwrap_or(0);

    let constellation = Constellation {
        cx_id: repo_cx_id(row.record.github_id, &row.record.full_name, salt),
        vault_id,
        panel_version: FLEET_PANEL_VERSION,
        created_at: discovered_at,
        input_ref: InputRef {
            hash: *blake3::hash(&identity).as_bytes(),
            pointer: None,
            redacted: false,
        },
        modality: FLEET_MODALITY,
        slots: BTreeMap::new(),
        scalars,
        metadata,
        anchors: Vec::new(),
        provenance: LedgerRef {
            seq: 0,
            hash: [0; 32],
        },
        flags: CxFlags {
            ungrounded: true,
            degraded: false,
            novel_region: false,
            redacted_input: false,
        },
    };
    constellation.validate_schema()?;
    Ok(constellation)
}

/// Decodes a Base-CF constellation back into a catalog row, refusing
/// fail-closed on any missing or malformed field.
pub fn decode_repo_constellation(
    constellation: &Constellation,
) -> Result<FleetRepoRow, CalyxError> {
    let corrupt = |what: String| CalyxError {
        code: ASTRO_FLEET_RECORD_CORRUPT,
        message: format!(
            "fleet catalog row {} is corrupt: {what}",
            constellation.cx_id
        ),
        remediation: "the catalog vault holds a row this build cannot interpret; audit the vault's ledger for the writing session",
    };
    let scalar = |key: &str| -> Result<u64, CalyxError> {
        let value = *constellation
            .scalars
            .get(key)
            .ok_or_else(|| corrupt(format!("missing scalar {key:?}")))?;
        if !(value.is_finite() && value >= 0.0 && value.fract() == 0.0) {
            return Err(corrupt(format!("scalar {key:?} is not a whole number")));
        }
        Ok(value as u64)
    };
    let meta = |key: &str| -> Result<String, CalyxError> {
        constellation
            .metadata
            .get(key)
            .cloned()
            .ok_or_else(|| corrupt(format!("missing metadata {key:?}")))
    };
    let meta_opt = |key: &str| constellation.metadata.get(key).cloned();

    let state = RepoState::parse(&meta(META_STATE)?)?;
    let mut state_timestamps = BTreeMap::new();
    for (key, value) in &constellation.metadata {
        if let Some(state_name) = key.strip_prefix(META_TS_PREFIX) {
            // Only lifecycle timestamps use the ts_ prefix; anything else is a
            // layout drift this build must not silently skip.
            RepoState::parse(state_name)
                .map_err(|_| corrupt(format!("unexpected timestamp key {key:?}")))?;
            let at = value
                .parse::<u64>()
                .map_err(|_| corrupt(format!("timestamp {key:?}={value:?} is not unix seconds")))?;
            state_timestamps.insert(state_name.to_string(), at);
        }
    }

    Ok(FleetRepoRow {
        cx_id: constellation.cx_id,
        record: RepoRecord {
            github_id: scalar(SCALAR_GITHUB_ID)?,
            full_name: meta(META_FULL_NAME)?,
            clone_url: meta(META_CLONE_URL)?,
            default_branch: meta(META_DEFAULT_BRANCH)?,
            stars: scalar(SCALAR_STARS)?,
            language: meta(META_LANGUAGE)?,
            license_spdx: meta_opt(META_LICENSE_SPDX),
            size_kb: scalar(SCALAR_SIZE_KB)?,
            pushed_at: meta(META_PUSHED_AT)?,
            etag: meta_opt(META_ETAG),
        },
        state,
        state_timestamps,
        clone_path: meta_opt(META_CLONE_PATH),
        head_commit_hash: meta_opt(META_HEAD_COMMIT_HASH),
        index_watermark: meta_opt(META_INDEX_WATERMARK),
        kernel_scope_id: meta_opt(META_KERNEL_SCOPE_ID),
        quarantine_reason: meta_opt(META_QUARANTINE_REASON),
        departed_reason: meta_opt(META_DEPARTED_REASON),
    })
}
