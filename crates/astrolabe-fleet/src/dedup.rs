//! Cross-repo content dedup census (issue #455): equivalence classes over the
//! **content-only** frames of every stored atom input, joined across project
//! vaults, persisted as a fleet-level artifact.
//!
//! # Join key — a recorded design correction
//!
//! The issue text names `canonical_input_bytes` hashes as the join key, but the
//! identity spine deliberately frames `project` (and rel path/lines) into those
//! bytes — #454 proved that framing sound precisely because it makes identical
//! content hash differently across projects. Joining on it would return zero
//! duplicates by construction. The census therefore keys on
//! `blake3(frame(label) ‖ frame(language) ‖ frame(source_snippet_bytes))` —
//! the content-only frames parsed back out of each vault's #446 input store.
//!
//! # Policy (declared)
//!
//! Duplicates are **linked, never skipped**: per-repo constellations are not
//! touched; the artifact records the equivalence classes so fleet composition
//! (#456) can weight by distinct content and serving can cite "appears in N
//! repos" instead of double-counting.

use std::collections::BTreeMap;
use std::path::Path;

use calyx_aster::cf::ColumnFamily;
use calyx_aster::vault::input_store::{self, read_input_bytes};
use calyx_aster::vault::{AsterVault, VaultOptions};
use calyx_core::{CalyxError, VaultId};
use serde_json::{Value, json};
use std::str::FromStr;

use crate::orchestrator::{SHADOW_VAULT_ID, shadow_vault_salt};

/// Refusal code for a vault whose stored input bytes cannot be parsed back
/// into the canonical symbol frames — corrupt or foreign data, never skipped.
pub const ASTRO_FLEET_DEDUP_FRAME_INVALID: &str = "ASTRO_FLEET_DEDUP_FRAME_INVALID";

/// Content-only frames of one stored atom input.
#[derive(Clone, Debug)]
pub struct AtomFrames {
    /// Project the atom was measured in (from the canonical frames).
    pub project: String,
    /// Qualified symbol name.
    pub qualified_name: String,
    /// Symbol label (kind).
    pub label: String,
    /// Repo-relative file path.
    pub rel_file_path: String,
    /// Language tag.
    pub language: String,
    /// Content key: `blake3(frame(label) ‖ frame(language) ‖ frame(snippet))`.
    pub content_key: [u8; 32],
    /// True when the atom intentionally carries no source bytes (for example a
    /// structural-only node). Such atoms have no content to be equivalent on: they are counted explicitly
    /// and excluded from equivalence classes — otherwise every snippetless
    /// atom fleet-wide collapses into one degenerate "duplicate" class (found
    /// live on the pilot census: one 134-occurrence 10-repo `File` class).
    pub snippet_empty: bool,
}

fn take_frame<'a>(bytes: &'a [u8], cursor: &mut usize, what: &str) -> Result<&'a [u8], CalyxError> {
    let invalid = |detail: String| CalyxError {
        code: ASTRO_FLEET_DEDUP_FRAME_INVALID,
        message: format!("canonical input frames did not parse: {detail}"),
        remediation: "the stored input is not a canonical symbol record; audit the vault input store",
    };
    if bytes.len() < *cursor + 8 {
        return Err(invalid(format!("truncated length prefix for {what}")));
    }
    let encoded_len = u64::from_be_bytes(bytes[*cursor..*cursor + 8].try_into().unwrap());
    let len = usize::try_from(encoded_len)
        .map_err(|_| invalid(format!("frame {what} length {encoded_len} exceeds usize")))?;
    *cursor += 8;
    if bytes.len() < *cursor + len {
        return Err(invalid(format!(
            "frame {what} claims {len} bytes but only {} remain",
            bytes.len() - *cursor
        )));
    }
    let frame = &bytes[*cursor..*cursor + len];
    *cursor += len;
    Ok(frame)
}

fn frame_of(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + bytes.len());
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
    out
}

/// Parses the canonical symbol frames (the exact `canonical_input_bytes`
/// layout: tag, project, qualified_name, label, rel_file_path, language,
/// snippet, signature, start/end line) and derives the content-only key.
pub fn parse_atom_frames(bytes: &[u8]) -> Result<AtomFrames, CalyxError> {
    let mut cursor = 0_usize;
    let tag = take_frame(bytes, &mut cursor, "tag")?;
    let project = take_frame(bytes, &mut cursor, "project")?;
    let qualified_name = take_frame(bytes, &mut cursor, "qualified_name")?;
    let label = take_frame(bytes, &mut cursor, "label")?;
    let rel_file_path = take_frame(bytes, &mut cursor, "rel_file_path")?;
    let language = take_frame(bytes, &mut cursor, "language")?;
    let snippet = take_frame(bytes, &mut cursor, "source_snippet_bytes")?;
    let _signature = take_frame(bytes, &mut cursor, "signature")?;
    let start_line = take_frame(bytes, &mut cursor, "start_line")?;
    let end_line = take_frame(bytes, &mut cursor, "end_line")?;
    let invalid = |detail: String| CalyxError {
        code: ASTRO_FLEET_DEDUP_FRAME_INVALID,
        message: format!("canonical input frames did not parse: {detail}"),
        remediation: "the stored input is not a canonical symbol record; audit the vault input store",
    };
    if tag != astrolabe_domain::SYMBOL_CANONICAL_TAG.as_bytes() {
        return Err(invalid("canonical symbol tag is unsupported".to_string()));
    }
    if start_line.len() != 4 || end_line.len() != 4 {
        return Err(invalid(format!(
            "line frames must each contain four bytes, got {} and {}",
            start_line.len(),
            end_line.len()
        )));
    }
    if cursor != bytes.len() {
        return Err(invalid(format!(
            "{} trailing bytes remain after the canonical end_line frame",
            bytes.len() - cursor
        )));
    }
    let utf8 = |frame: &[u8], what: &str| {
        std::str::from_utf8(frame)
            .map(str::to_owned)
            .map_err(|error| invalid(format!("{what} is not UTF-8: {error}")))
    };
    let mut keyed = Vec::with_capacity(24 + label.len() + language.len() + snippet.len());
    keyed.extend_from_slice(&frame_of(label));
    keyed.extend_from_slice(&frame_of(language));
    keyed.extend_from_slice(&frame_of(snippet));
    Ok(AtomFrames {
        project: utf8(project, "project")?,
        qualified_name: utf8(qualified_name, "qualified_name")?,
        label: utf8(label, "label")?,
        rel_file_path: utf8(rel_file_path, "rel_file_path")?,
        language: utf8(language, "language")?,
        content_key: *blake3::hash(&keyed).as_bytes(),
        snippet_empty: snippet.is_empty(),
    })
}

/// Reads every stored atom input of `project`'s shadow vault and returns the
/// parsed frames. Fails closed on any unreadable or unparseable input; a vault
/// with zero stored inputs returns an empty vec (the caller labels it).
pub fn project_atoms(store_root: &Path, project: &str) -> Result<Vec<AtomFrames>, CalyxError> {
    let vault_dir = store_root
        .join(project)
        .join(format!("{project}.astrolabe-vault"));
    let vault_id = VaultId::from_str(SHADOW_VAULT_ID).map_err(|error| CalyxError {
        code: ASTRO_FLEET_DEDUP_FRAME_INVALID,
        message: format!("shadow vault id failed to parse: {error:?}"),
        remediation: "internal defect: SHADOW_VAULT_ID must be a valid ULID",
    })?;
    let vault = AsterVault::open(
        &vault_dir,
        vault_id,
        shadow_vault_salt(project).into_bytes(),
        VaultOptions {
            read_only: true,
            ..VaultOptions::default()
        },
    )?;
    // Manifest keyspace prefix, derived from the public key builder so the
    // private DISC/NAMESPACE constants stay owned by the input store.
    let probe = input_store::input_manifest_key(&[0_u8; 32]);
    let prefix = probe[..probe.len() - 32].to_vec();
    let snapshot = vault.latest_seq();
    let mut atoms = Vec::new();
    for (key, _value) in vault.scan_cf_at(snapshot, ColumnFamily::Blob)? {
        if !key.starts_with(&prefix) || key.len() != prefix.len() + 32 {
            continue;
        }
        let mut hash = [0_u8; 32];
        hash.copy_from_slice(&key[prefix.len()..]);
        let bytes = read_input_bytes(&vault, &hash)?;
        atoms.push(parse_atom_frames(&bytes)?);
    }
    Ok(atoms)
}

/// Runs the census over `(project, atoms)` sets and builds the fleet artifact.
/// Pure aggregation — callers gather atoms with [`project_atoms`] first.
pub fn census_artifact(per_project: &[(String, Vec<AtomFrames>)]) -> Value {
    #[derive(Default)]
    struct Class {
        occurrences: u64,
        repos: BTreeMap<String, u64>,
        sample: Option<(String, String, String, String)>,
    }
    let mut classes: BTreeMap<[u8; 32], Class> = BTreeMap::new();
    let mut snippetless_total = 0_u64;
    // Exact source bytes now flow from libcbm into every source-bearing canonical
    // atom, including File nodes. Structural nodes intentionally have no source;
    // they are counted explicitly and excluded instead of being collapsed into
    // one degenerate empty-content class.
    let content_free = |atom: &AtomFrames| atom.snippet_empty;
    for (project, atoms) in per_project {
        for atom in atoms {
            if content_free(atom) {
                snippetless_total += 1;
                continue;
            }
            let class = classes.entry(atom.content_key).or_default();
            class.occurrences += 1;
            *class.repos.entry(project.clone()).or_default() += 1;
            if class.sample.is_none() {
                class.sample = Some((
                    project.clone(),
                    atom.rel_file_path.clone(),
                    atom.qualified_name.clone(),
                    atom.label.clone(),
                ));
            }
        }
    }
    let atoms_total: u64 = classes.values().map(|class| class.occurrences).sum();
    let distinct = classes.len() as u64;
    let cross: Vec<(&[u8; 32], &Class)> = {
        let mut cross: Vec<_> = classes
            .iter()
            .filter(|(_, class)| class.repos.len() > 1)
            .collect();
        cross.sort_by_key(|(_, class)| std::cmp::Reverse((class.repos.len(), class.occurrences)));
        cross
    };
    let projects: Vec<Value> = per_project
        .iter()
        .map(|(project, atoms)| {
            let snippetless = atoms.iter().filter(|atom| content_free(atom)).count() as u64;
            let total = atoms.len() as u64 - snippetless;
            let shared = atoms
                .iter()
                .filter(|atom| !content_free(atom) && classes[&atom.content_key].repos.len() > 1)
                .count() as u64;
            json!({
                "project": project,
                "atoms": total,
                "content_free_atoms": snippetless,
                "atoms_in_cross_repo_classes": shared,
                "uniqueness_fraction": if total > 0 {
                    (total - shared) as f64 / total as f64
                } else {
                    0.0
                },
                "zero_atoms": total == 0,
            })
        })
        .collect();
    let hex = |key: &[u8; 32]| {
        key.iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    json!({
        "artifact": "fleet-dedup-census/v2",
        "policy": "linked-not-skipped: per-repo constellations untouched; classes weight fleet composition (#456)",
        "join_key": "blake3(frame(label)+frame(language)+frame(source_snippet_bytes)) — byte-exact content-only source identity (design correction on #455); only explicitly source-absent structural atoms are excluded",
        "atoms_total": atoms_total,
        "content_free_atoms_excluded": snippetless_total,
        "distinct_contents": distinct,
        "dedup_ratio": if distinct > 0 { atoms_total as f64 / distinct as f64 } else { 0.0 },
        "cross_repo_classes": cross.len(),
        "projects": projects,
        "top_cross_repo": cross.iter().take(500).map(|(key, class)| json!({
            "content_key_hash": hex(key),
            "repo_count": class.repos.len(),
            "occurrences": class.occurrences,
            "repos": class.repos,
            "sample": class.sample.as_ref().map(|(project, path, qualified_name, label)| json!({
                "project": project, "path": path, "qualified_name": qualified_name, "label": label,
            })),
        })).collect::<Vec<_>>(),
    })
}
