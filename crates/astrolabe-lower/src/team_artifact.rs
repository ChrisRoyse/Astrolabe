use std::collections::BTreeSet;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use calyx_aster::cf::ColumnFamily;
use calyx_aster::ledger_view::parse_aster_ledger_seq;
use calyx_aster::vault::AsterVault;
use calyx_core::Clock;
use calyx_ledger::{
    LedgerRow, MemoryLedgerStore, MerkleExportBundle, VerifyResult, decode, merkle_root,
    verify_chain as calyx_verify_chain, verify_signature,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{LowerError, LowerResult};

pub const TEAM_ARTIFACT_SCHEMA: &str = "astrolabe.team_artifact.v1";
const TEAM_VAULT_EXPORT_SCHEMA: &str = "astrolabe.vault_export.v1";
pub const GRAPH_DB_ZST_NAME: &str = "graph.db.zst";
pub const VAULT_EXPORT_ZST_NAME: &str = "vault.export.zst";
const ARTIFACT_JSON_NAME: &str = "artifact.json";
const ZSTD_LEVEL: i32 = 3;

pub const ASTRO_TEAM_ARTIFACT_MISSING_GRAPH: &str = "ASTRO_TEAM_ARTIFACT_MISSING_GRAPH";
pub const ASTRO_TEAM_ARTIFACT_GRAPH_BYTES: &str = "ASTRO_TEAM_ARTIFACT_GRAPH_BYTES";
pub const ASTRO_TEAM_ARTIFACT_VAULT_BYTES: &str = "ASTRO_TEAM_ARTIFACT_VAULT_BYTES";
pub const ASTRO_TEAM_ARTIFACT_LEDGER_TAIL: &str = "ASTRO_TEAM_ARTIFACT_LEDGER_TAIL";
pub const ASTRO_TEAM_ARTIFACT_MERKLE_ROOT: &str = "ASTRO_TEAM_ARTIFACT_MERKLE_ROOT";
pub const ASTRO_TEAM_ARTIFACT_SIGNATURE: &str = "ASTRO_TEAM_ARTIFACT_SIGNATURE";
pub const ASTRO_TEAM_ARTIFACT_SIGNATURE_SIGNER: &str = "ASTRO_TEAM_ARTIFACT_SIGNATURE_SIGNER";

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TeamArtifactExportOptions {
    pub signing_key: Option<[u8; 32]>,
}

impl TeamArtifactExportOptions {
    pub const fn unsigned() -> Self {
        Self { signing_key: None }
    }

    pub const fn with_signing_key(signing_key: [u8; 32]) -> Self {
        Self {
            signing_key: Some(signing_key),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TeamArtifactImportOptions {
    pub expected_signer_pubkey: Option<[u8; 32]>,
}

impl TeamArtifactImportOptions {
    pub const fn new() -> Self {
        Self {
            expected_signer_pubkey: None,
        }
    }

    pub const fn with_expected_signer(expected_signer_pubkey: [u8; 32]) -> Self {
        Self {
            expected_signer_pubkey: Some(expected_signer_pubkey),
        }
    }
}

impl Default for TeamArtifactImportOptions {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TeamArtifactExportReport {
    pub manifest_path: PathBuf,
    pub graph_db_zst_path: PathBuf,
    pub vault_export_zst_path: PathBuf,
    pub manifest: TeamArtifactManifest,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TeamArtifactImportReport {
    pub mode: String,
    pub adopted_graph_path: PathBuf,
    pub graph_db_sha256: String,
    pub ledger_rows: usize,
    pub merkle_root: Option<String>,
    pub signature_status: String,
    pub fallback: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct TeamArtifactManifest {
    pub schema_version: String,
    pub graph_db_zst: String,
    pub graph_db_zst_sha256: String,
    pub graph_db_sha256: String,
    pub vault_export_zst: Option<String>,
    pub vault_export_zst_sha256: Option<String>,
    pub ledger_head: Option<TeamLedgerHead>,
    pub merkle_root: Option<String>,
    pub signature: Option<TeamArtifactSignature>,
    pub unsigned_artifact: bool,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct TeamLedgerHead {
    pub seq: u64,
    pub hash: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct TeamArtifactSignature {
    pub algorithm: String,
    pub domain: String,
    pub signature_hex: String,
    pub signer_pubkey_hex: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct TeamVaultExport {
    schema_version: String,
    ledger_rows: Vec<TeamLedgerRow>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct TeamLedgerRow {
    seq: u64,
    bytes_hex: String,
}

pub fn export_team_artifact<C>(
    vault: &AsterVault<C>,
    lowered_sqlite_path: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
    options: &TeamArtifactExportOptions,
) -> LowerResult<TeamArtifactExportReport>
where
    C: Clock,
{
    let lowered_sqlite_path = lowered_sqlite_path.as_ref();
    let output_dir = output_dir.as_ref();
    let graph_bytes = fs::read(lowered_sqlite_path)?;
    fs::create_dir_all(output_dir)?;

    let graph_zst = zstd::stream::encode_all(Cursor::new(&graph_bytes), ZSTD_LEVEL)?;
    let graph_db_zst_path = output_dir.join(GRAPH_DB_ZST_NAME);
    fs::write(&graph_db_zst_path, &graph_zst)?;

    let ledger_rows = collect_ledger_rows(vault)?;
    let store = memory_store(&ledger_rows);
    let range_end = ledger_range_end(&ledger_rows)?;
    ensure_intact_chain(&store, range_end)?;
    let root = merkle_root(&store, 0..range_end)?;
    let manifest_ledger_head = ledger_head(&ledger_rows)?;
    let root_hex = hex_lower(&root);

    let vault_export = TeamVaultExport {
        schema_version: TEAM_VAULT_EXPORT_SCHEMA.to_string(),
        ledger_rows: ledger_rows
            .iter()
            .map(|row| TeamLedgerRow {
                seq: row.seq,
                bytes_hex: hex_lower(&row.bytes),
            })
            .collect(),
    };
    let vault_export_json = serde_json::to_vec(&vault_export)?;
    let vault_export_zst = zstd::stream::encode_all(Cursor::new(&vault_export_json), ZSTD_LEVEL)?;
    let vault_export_zst_path = output_dir.join(VAULT_EXPORT_ZST_NAME);
    fs::write(&vault_export_zst_path, &vault_export_zst)?;

    let signature = options.signing_key.as_ref().map(|key| {
        let bundle = MerkleExportBundle::signed(0..range_end, root, key);
        TeamArtifactSignature {
            algorithm: "ed25519".to_string(),
            domain: "calyx-ledger-root-v1".to_string(),
            signature_hex: hex_lower(bundle.signature.as_ref().expect("signed bundle")),
            signer_pubkey_hex: hex_lower(bundle.signer_pubkey.as_ref().expect("signed bundle")),
        }
    });

    let manifest = TeamArtifactManifest {
        schema_version: TEAM_ARTIFACT_SCHEMA.to_string(),
        graph_db_zst: GRAPH_DB_ZST_NAME.to_string(),
        graph_db_zst_sha256: sha256_hex(&graph_zst),
        graph_db_sha256: sha256_hex(&graph_bytes),
        vault_export_zst: Some(VAULT_EXPORT_ZST_NAME.to_string()),
        vault_export_zst_sha256: Some(sha256_hex(&vault_export_zst)),
        ledger_head: manifest_ledger_head,
        merkle_root: Some(root_hex),
        unsigned_artifact: signature.is_none(),
        signature,
    };
    let manifest_path = output_dir.join(ARTIFACT_JSON_NAME);
    fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)?;

    Ok(TeamArtifactExportReport {
        manifest_path,
        graph_db_zst_path,
        vault_export_zst_path,
        manifest,
    })
}

pub fn import_team_artifact(
    artifact_dir: impl AsRef<Path>,
    adopted_graph_path: impl AsRef<Path>,
    options: &TeamArtifactImportOptions,
) -> LowerResult<TeamArtifactImportReport> {
    let artifact_dir = artifact_dir.as_ref();
    let adopted_graph_path = adopted_graph_path.as_ref().to_path_buf();
    let manifest_path = artifact_dir.join(ARTIFACT_JSON_NAME);
    if !manifest_path.exists() {
        return import_legacy_graph(artifact_dir, adopted_graph_path);
    }

    let manifest = read_manifest(&manifest_path)?;
    if manifest.schema_version != TEAM_ARTIFACT_SCHEMA {
        return Err(refuse(
            TeamArtifactRefusal::LedgerTail,
            format!(
                "artifact schema_version {:?} is not {TEAM_ARTIFACT_SCHEMA}",
                manifest.schema_version
            ),
        ));
    }

    let graph_zst_path = artifact_dir.join(&manifest.graph_db_zst);
    let graph_zst = fs::read(&graph_zst_path).map_err(|error| {
        refuse(
            TeamArtifactRefusal::MissingGraph,
            format!("read {}: {error}", graph_zst_path.display()),
        )
    })?;
    if sha256_hex(&graph_zst) != manifest.graph_db_zst_sha256 {
        return Err(refuse(
            TeamArtifactRefusal::GraphBytes,
            "graph.db.zst compressed bytes do not match artifact.json",
        ));
    }
    let graph_bytes = zstd::stream::decode_all(Cursor::new(&graph_zst)).map_err(|error| {
        refuse(
            TeamArtifactRefusal::GraphBytes,
            format!("decode graph.db.zst: {error}"),
        )
    })?;
    let graph_hash = sha256_hex(&graph_bytes);
    if graph_hash != manifest.graph_db_sha256 {
        return Err(refuse(
            TeamArtifactRefusal::GraphBytes,
            "decompressed graph.db bytes do not match artifact.json",
        ));
    }

    let vault_export_name = manifest.vault_export_zst.as_deref().ok_or_else(|| {
        refuse(
            TeamArtifactRefusal::VaultBytes,
            "artifact.json does not name vault.export.zst",
        )
    })?;
    let vault_zst_path = artifact_dir.join(vault_export_name);
    let vault_zst = fs::read(&vault_zst_path).map_err(|error| {
        refuse(
            TeamArtifactRefusal::VaultBytes,
            format!("read {}: {error}", vault_zst_path.display()),
        )
    })?;
    let expected_vault_hash = manifest.vault_export_zst_sha256.as_deref().ok_or_else(|| {
        refuse(
            TeamArtifactRefusal::VaultBytes,
            "artifact.json does not carry vault_export_zst_sha256",
        )
    })?;
    if sha256_hex(&vault_zst) != expected_vault_hash {
        return Err(refuse(
            TeamArtifactRefusal::VaultBytes,
            "vault.export.zst compressed bytes do not match artifact.json",
        ));
    }

    let vault_export = read_vault_export(&vault_zst)?;
    let ledger_rows = rows_from_export(&vault_export)?;
    let store = memory_store(&ledger_rows);
    let range_end = ledger_range_end(&ledger_rows)?;
    ensure_intact_chain(&store, range_end)?;
    ensure_manifest_head_matches(&manifest, &ledger_rows)?;

    let root = merkle_root(&store, 0..range_end)?;
    let root_hex = hex_lower(&root);
    if manifest.merkle_root.as_deref() != Some(root_hex.as_str()) {
        return Err(refuse(
            TeamArtifactRefusal::MerkleRoot,
            "artifact.json merkle_root does not match verified ledger rows",
        ));
    }

    let signature_status = verify_optional_signature(&manifest, root, range_end, options)?;
    write_adopted_graph(&adopted_graph_path, &graph_bytes)?;

    Ok(TeamArtifactImportReport {
        mode: "chain_verified_vault_export".to_string(),
        adopted_graph_path,
        graph_db_sha256: graph_hash,
        ledger_rows: ledger_rows.len(),
        merkle_root: Some(root_hex),
        signature_status,
        fallback: None,
    })
}

fn import_legacy_graph(
    artifact_dir: &Path,
    adopted_graph_path: PathBuf,
) -> LowerResult<TeamArtifactImportReport> {
    let graph_zst_path = artifact_dir.join(GRAPH_DB_ZST_NAME);
    if !graph_zst_path.exists() {
        return Err(refuse(
            TeamArtifactRefusal::MissingGraph,
            format!(
                "neither {} nor {} exists in {}",
                ARTIFACT_JSON_NAME,
                GRAPH_DB_ZST_NAME,
                artifact_dir.display()
            ),
        ));
    }
    let graph_zst = fs::read(&graph_zst_path)?;
    let graph_bytes = zstd::stream::decode_all(Cursor::new(&graph_zst)).map_err(|error| {
        refuse(
            TeamArtifactRefusal::GraphBytes,
            format!("decode legacy graph.db.zst: {error}"),
        )
    })?;
    let graph_hash = sha256_hex(&graph_bytes);
    write_adopted_graph(&adopted_graph_path, &graph_bytes)?;
    Ok(TeamArtifactImportReport {
        mode: "legacy_plain_graph_db_zst".to_string(),
        adopted_graph_path,
        graph_db_sha256: graph_hash,
        ledger_rows: 0,
        merkle_root: None,
        signature_status: "legacy_unverified".to_string(),
        fallback: Some("local_reindex_if_graph_rejected".to_string()),
    })
}

fn read_manifest(path: &Path) -> LowerResult<TeamArtifactManifest> {
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(|error| {
        refuse(
            TeamArtifactRefusal::LedgerTail,
            format!("decode {}: {error}", path.display()),
        )
    })
}

fn read_vault_export(vault_zst: &[u8]) -> LowerResult<TeamVaultExport> {
    let bytes = zstd::stream::decode_all(Cursor::new(vault_zst)).map_err(|error| {
        refuse(
            TeamArtifactRefusal::VaultBytes,
            format!("decode vault.export.zst: {error}"),
        )
    })?;
    let export: TeamVaultExport = serde_json::from_slice(&bytes).map_err(|error| {
        refuse(
            TeamArtifactRefusal::VaultBytes,
            format!("decode vault export JSON: {error}"),
        )
    })?;
    if export.schema_version != TEAM_VAULT_EXPORT_SCHEMA {
        return Err(refuse(
            TeamArtifactRefusal::VaultBytes,
            format!(
                "vault export schema_version {:?} is not {TEAM_VAULT_EXPORT_SCHEMA}",
                export.schema_version
            ),
        ));
    }
    Ok(export)
}

fn rows_from_export(export: &TeamVaultExport) -> LowerResult<Vec<LedgerRow>> {
    let mut seen = BTreeSet::new();
    let mut rows = Vec::with_capacity(export.ledger_rows.len());
    for row in &export.ledger_rows {
        if !seen.insert(row.seq) {
            return Err(refuse(
                TeamArtifactRefusal::LedgerTail,
                format!("duplicate ledger seq {}", row.seq),
            ));
        }
        let bytes = decode_hex(
            &row.bytes_hex,
            "ledger row bytes",
            TeamArtifactRefusal::LedgerTail,
        )?;
        let entry = decode(&bytes).map_err(|error| {
            refuse(
                TeamArtifactRefusal::LedgerTail,
                format!("decode ledger seq {}: {error}", row.seq),
            )
        })?;
        if entry.seq != row.seq {
            return Err(refuse(
                TeamArtifactRefusal::LedgerTail,
                format!(
                    "ledger export key seq {} encodes seq {}",
                    row.seq, entry.seq
                ),
            ));
        }
        if !entry.verify() {
            return Err(refuse(
                TeamArtifactRefusal::LedgerTail,
                format!("ledger seq {} entry hash is invalid", row.seq),
            ));
        }
        rows.push(LedgerRow {
            seq: row.seq,
            bytes,
        });
    }
    rows.sort_by_key(|row| row.seq);
    Ok(rows)
}

fn collect_ledger_rows<C>(vault: &AsterVault<C>) -> LowerResult<Vec<LedgerRow>>
where
    C: Clock,
{
    let mut rows = Vec::new();
    for (key, bytes) in vault.scan_cf_at(vault.latest_seq(), ColumnFamily::Ledger)? {
        rows.push(LedgerRow {
            seq: parse_aster_ledger_seq(&key)?,
            bytes,
        });
    }
    rows.sort_by_key(|row| row.seq);
    Ok(rows)
}

fn ledger_range_end(rows: &[LedgerRow]) -> LowerResult<u64> {
    for (expected, row) in rows.iter().enumerate() {
        let expected = u64::try_from(expected).map_err(|_| {
            refuse(
                TeamArtifactRefusal::LedgerTail,
                "ledger export is too large for this host",
            )
        })?;
        if row.seq != expected {
            return Err(refuse(
                TeamArtifactRefusal::LedgerTail,
                format!("ledger rows are not contiguous at seq {expected}"),
            ));
        }
    }
    Ok(rows.last().map_or(0, |row| row.seq.saturating_add(1)))
}

fn ensure_intact_chain(store: &MemoryLedgerStore, range_end: u64) -> LowerResult<()> {
    match calyx_verify_chain(store, 0..range_end)? {
        VerifyResult::Intact { .. } => Ok(()),
        VerifyResult::Broken { at_seq, .. } => Err(refuse(
            TeamArtifactRefusal::LedgerTail,
            format!("ledger chain broken at seq {at_seq}"),
        )),
        VerifyResult::Corrupt { at_seq, reason } => Err(refuse(
            TeamArtifactRefusal::LedgerTail,
            format!("ledger chain corrupt at seq {at_seq}: {reason}"),
        )),
    }
}

fn ensure_manifest_head_matches(
    manifest: &TeamArtifactManifest,
    rows: &[LedgerRow],
) -> LowerResult<()> {
    let computed = ledger_head(rows)?;
    if manifest.ledger_head != computed {
        return Err(refuse(
            TeamArtifactRefusal::LedgerTail,
            "artifact.json ledger_head does not match verified ledger tail",
        ));
    }
    Ok(())
}

fn ledger_head(rows: &[LedgerRow]) -> LowerResult<Option<TeamLedgerHead>> {
    rows.last()
        .map(|row| {
            let entry = decode(&row.bytes)?;
            Ok(TeamLedgerHead {
                seq: row.seq,
                hash: hex_lower(&entry.entry_hash),
            })
        })
        .transpose()
}

fn verify_optional_signature(
    manifest: &TeamArtifactManifest,
    root: [u8; 32],
    range_end: u64,
    options: &TeamArtifactImportOptions,
) -> LowerResult<String> {
    let Some(signature) = &manifest.signature else {
        return Ok("unsigned".to_string());
    };
    if signature.algorithm != "ed25519" || signature.domain != "calyx-ledger-root-v1" {
        return Err(refuse(
            TeamArtifactRefusal::Signature,
            "signature algorithm/domain is not the Calyx ledger root signing contract",
        ));
    }
    let signature_bytes = decode_hex_64(&signature.signature_hex, "signature")?;
    let signer_pubkey = decode_hex_32(&signature.signer_pubkey_hex, "signer_pubkey")?;
    if let Some(expected) = options.expected_signer_pubkey
        && signer_pubkey != expected
    {
        return Err(refuse(
            TeamArtifactRefusal::SignatureSigner,
            "artifact signer_pubkey does not match the expected signer",
        ));
    }
    let bundle = MerkleExportBundle {
        range_start: 0,
        range_end,
        root,
        signature: Some(signature_bytes),
        signer_pubkey: Some(signer_pubkey),
    };
    if !verify_signature(&bundle) {
        return Err(refuse(
            TeamArtifactRefusal::Signature,
            "artifact signature does not verify for the ledger Merkle root",
        ));
    }
    Ok("verified".to_string())
}

fn memory_store(rows: &[LedgerRow]) -> MemoryLedgerStore {
    let mut store = MemoryLedgerStore::default();
    for row in rows {
        store.insert_raw(row.seq, row.bytes.clone());
    }
    store
}

fn write_adopted_graph(path: &Path, bytes: &[u8]) -> LowerResult<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, bytes)?;
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut out, "{byte:02x}").expect("hex write to String");
    }
    out
}

fn decode_hex_32(input: &str, label: &str) -> LowerResult<[u8; 32]> {
    let bytes = decode_hex(input, label, TeamArtifactRefusal::Signature)?;
    let len = bytes.len();
    bytes.try_into().map_err(|_| {
        refuse(
            TeamArtifactRefusal::Signature,
            format!("{label} has {len} bytes, expected 32"),
        )
    })
}

fn decode_hex_64(input: &str, label: &str) -> LowerResult<[u8; 64]> {
    let bytes = decode_hex(input, label, TeamArtifactRefusal::Signature)?;
    let len = bytes.len();
    bytes.try_into().map_err(|_| {
        refuse(
            TeamArtifactRefusal::Signature,
            format!("{label} has {len} bytes, expected 64"),
        )
    })
}

fn decode_hex(input: &str, label: &str, component: TeamArtifactRefusal) -> LowerResult<Vec<u8>> {
    if !input.len().is_multiple_of(2) {
        return Err(refuse(component, format!("{label} hex has odd length")));
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    for chunk in input.as_bytes().chunks_exact(2) {
        let high = hex_nibble(chunk[0], label, component)?;
        let low = hex_nibble(chunk[1], label, component)?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

fn hex_nibble(byte: u8, label: &str, component: TeamArtifactRefusal) -> LowerResult<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(refuse(component, format!("{label} contains non-hex bytes"))),
    }
}

/// Typed refusal taxonomy for team-artifact fail-closed refusals.
///
/// Each variant owns exactly one stable `ASTRO_TEAM_ARTIFACT_*` code and its
/// operator remediation, so a refusal can never be built with a code that has
/// drifted from its message: [`refuse`] derives both the code and the
/// remediation from this enum, and callers name the failing component by type
/// rather than by re-typing a string code at each site.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum TeamArtifactRefusal {
    /// Neither `artifact.json` nor `graph.db.zst` was present to import.
    MissingGraph,
    /// The lowered graph bytes are missing, corrupt, or mismatch `artifact.json`.
    GraphBytes,
    /// The vault export container is missing, corrupt, or mismatches `artifact.json`.
    VaultBytes,
    /// The exported ledger tail is malformed, non-contiguous, or mismatches `artifact.json`.
    LedgerTail,
    /// The verified ledger Merkle root disagrees with `artifact.json`.
    MerkleRoot,
    /// The artifact signature is malformed or does not verify for the Merkle root.
    Signature,
    /// The artifact signer public key does not match the expected signer.
    SignatureSigner,
}

impl TeamArtifactRefusal {
    const fn code(self) -> &'static str {
        match self {
            Self::MissingGraph => ASTRO_TEAM_ARTIFACT_MISSING_GRAPH,
            Self::GraphBytes => ASTRO_TEAM_ARTIFACT_GRAPH_BYTES,
            Self::VaultBytes => ASTRO_TEAM_ARTIFACT_VAULT_BYTES,
            Self::LedgerTail => ASTRO_TEAM_ARTIFACT_LEDGER_TAIL,
            Self::MerkleRoot => ASTRO_TEAM_ARTIFACT_MERKLE_ROOT,
            Self::Signature => ASTRO_TEAM_ARTIFACT_SIGNATURE,
            Self::SignatureSigner => ASTRO_TEAM_ARTIFACT_SIGNATURE_SIGNER,
        }
    }

    const fn remediation(self) -> &'static str {
        match self {
            Self::MissingGraph => {
                "Re-export the team artifact so artifact.json and graph.db.zst are present, or point the import at the directory that contains them."
            }
            Self::GraphBytes => {
                "Re-download or re-export the team artifact; the graph.db bytes are corrupt or do not match artifact.json."
            }
            Self::VaultBytes => {
                "Re-export the team artifact; vault.export.zst is missing, corrupt, or does not match artifact.json."
            }
            Self::LedgerTail => {
                "Re-export the team artifact from an intact vault; the ledger export is malformed, non-contiguous, or does not match artifact.json."
            }
            Self::MerkleRoot => {
                "Re-export the team artifact; artifact.json merkle_root does not match the verified ledger rows."
            }
            Self::Signature => {
                "Re-export the team artifact with a valid signature over the ledger Merkle root, or import without an expected signer if the artifact is intentionally unsigned."
            }
            Self::SignatureSigner => {
                "Import with the expected signer public key that matches the artifact, or obtain an artifact signed by the trusted signer."
            }
        }
    }
}

fn refuse(component: TeamArtifactRefusal, message: impl Into<String>) -> LowerError {
    LowerError::refused(component.code(), message, component.remediation())
}
