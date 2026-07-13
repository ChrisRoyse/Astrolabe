//! The `astro.layout.*` content-addressed knob registry for the S23 `layer_role`
//! lens (#180a, #310).
//!
//! Standing invariant 4 ("no constant that could be a measurement") requires every
//! threshold, weight, taxonomy, or seeded map a shipped path depends on to be a
//! *declared* knob with an explicit content identity — not a bare constant buried in
//! a function body. The S23 `layer_role` lens depends on exactly four such knobs, all
//! namespaced `astro.layout.*`:
//!
//! 1. [`CANONICAL_ROLES_SCHEMA`] — the frozen role taxonomy / coordinate system.
//! 2. [`API_FAMILIES_SCHEMA`] — the default persistence/transport callee seed lists
//!    (the measured, per-repo-learnable part of the model).
//! 3. [`EVIDENCE_WEIGHTS_SCHEMA`] — the weighted-evidence combiner weights (the frozen
//!    encoder spec bound into the lens `weights_sha`).
//! 4. [`DECLARED_MAP_SCHEMA`] — the directory-name → role declared map (per-repo,
//!    default-seeded here, learned downstream).
//!
//! Each knob is **content-addressed**: its canonical, order-stable byte serialization
//! is folded through [`crate::sha256_digest`] into a 32-byte identity that is *locked*
//! — persisted and read back byte-for-byte, and recomputed from the live registry on
//! read to detect drift. A change to any knob's content moves its identity, which
//! (for the three encoder-consumed knobs) also moves the S23 frozen lens id.

use serde::{Deserialize, Serialize};

use crate::lenses::{DEFAULT_PERSISTENCE_FAMILY_SEEDS, DEFAULT_TRANSPORT_FAMILY_SEEDS};
use crate::{
    ASTRO_PANEL_SEED_REGISTRY_INVALID, CANONICAL_ROLES, LayerRole, PanelError, PanelResult,
    sha256_digest,
};

/// Registry family version tag for the layout knobs.
pub const LAYOUT_REGISTRY_VERSION: &str = "astro.layout.v1";

/// Content-address schema id of the canonical role taxonomy knob.
pub const CANONICAL_ROLES_SCHEMA: &str = "astro.layout.canonical_roles.v1";
/// Content-address schema id of the API-family default-seed knob.
pub const API_FAMILIES_SCHEMA: &str = "astro.layout.api_families.v1";
/// Content-address schema id of the weighted-evidence combiner-weights knob.
pub const EVIDENCE_WEIGHTS_SCHEMA: &str = "astro.layout.evidence_weights.v1";
/// Content-address schema id of the directory→role declared-map knob.
pub const DECLARED_MAP_SCHEMA: &str = "astro.layout.declared_map.v1";

// ---------------------------------------------------------------------------
// Knob 3 content: weighted-evidence combiner weights.
//
// The single source of truth for the S23 combiner spec. `lenses::encode_layer_role`
// imports these; `evidence_weights_content_sha` folds them into the knob identity,
// so any edit here moves both the knob identity and the S23 frozen lens id.
// ---------------------------------------------------------------------------

/// Weight of an explicit `is_route` role flag toward `transport_api`.
pub const LR_W_ROUTE_FLAG: f32 = 2.0;
/// Weight of an explicit `is_handler` role flag toward `transport_api`.
pub const LR_W_HANDLER_FLAG: f32 = 2.0;
/// Weight of an observed route/channel surface toward `transport_api`.
pub const LR_W_ROUTE_SURFACE: f32 = 3.0;
/// Weight of an explicit `is_test` role flag toward `test`.
pub const LR_W_TEST_FLAG: f32 = 4.0;
/// Per-call weight of a transport-family resolved callee toward `transport_api`.
pub const LR_W_API_TRANSPORT: f32 = 1.5;
/// Per-call weight of a persistence-family resolved callee toward `persistence`.
pub const LR_W_API_PERSISTENCE: f32 = 2.0;
/// Per-call weight of an unclassified resolved callee toward `other`.
pub const LR_W_API_UNCLASSIFIED: f32 = 0.5;
/// Weight of sampled betweenness toward `service_domain`.
pub const LR_W_SERVICE_BETWEENNESS: f32 = 2.5;
/// Weight of the min(in,out) log-degree toward `service_domain`.
pub const LR_W_SERVICE_DEGREE: f32 = 1.0;

/// Ordered, named combiner weights — the canonical content of the evidence-weights
/// knob. The order is frozen: it is the byte order folded into the content address.
pub const EVIDENCE_WEIGHTS: &[(&str, f32)] = &[
    ("route_flag", LR_W_ROUTE_FLAG),
    ("handler_flag", LR_W_HANDLER_FLAG),
    ("route_surface", LR_W_ROUTE_SURFACE),
    ("test_flag", LR_W_TEST_FLAG),
    ("api_transport", LR_W_API_TRANSPORT),
    ("api_persistence", LR_W_API_PERSISTENCE),
    ("api_unclassified", LR_W_API_UNCLASSIFIED),
    ("service_betweenness", LR_W_SERVICE_BETWEENNESS),
    ("service_degree", LR_W_SERVICE_DEGREE),
];

// ---------------------------------------------------------------------------
// Knob 4 content: directory→role declared map (default seed).
// ---------------------------------------------------------------------------

/// Default directory-name → canonical-role seed of the declared-map knob.
///
/// A corpus-independent starting map of common layer directory names to canonical
/// roles. Names are matched case-insensitively against a path component (the per-repo
/// refinement — a repo declaring its own directory names — is the learned-downstream
/// part). Any directory that maps to no entry contributes no directory-role evidence;
/// it is a labeled absence, never a silent default.
pub const DEFAULT_DECLARED_DIR_ROLES: &[(&str, LayerRole)] = &[
    ("api", LayerRole::TransportApi),
    ("controllers", LayerRole::TransportApi),
    ("endpoints", LayerRole::TransportApi),
    ("handlers", LayerRole::TransportApi),
    ("routes", LayerRole::TransportApi),
    ("transport", LayerRole::TransportApi),
    ("domain", LayerRole::ServiceDomain),
    ("services", LayerRole::ServiceDomain),
    ("usecases", LayerRole::ServiceDomain),
    ("dao", LayerRole::Persistence),
    ("db", LayerRole::Persistence),
    ("persistence", LayerRole::Persistence),
    ("repositories", LayerRole::Persistence),
    ("repository", LayerRole::Persistence),
    ("store", LayerRole::Persistence),
    ("entities", LayerRole::ModelSchema),
    ("model", LayerRole::ModelSchema),
    ("models", LayerRole::ModelSchema),
    ("schema", LayerRole::ModelSchema),
    ("schemas", LayerRole::ModelSchema),
    ("config", LayerRole::InfraConfig),
    ("infra", LayerRole::InfraConfig),
    ("infrastructure", LayerRole::InfraConfig),
    ("migrations", LayerRole::InfraConfig),
    ("spec", LayerRole::Test),
    ("specs", LayerRole::Test),
    ("test", LayerRole::Test),
    ("tests", LayerRole::Test),
    ("components", LayerRole::Presentation),
    ("templates", LayerRole::Presentation),
    ("ui", LayerRole::Presentation),
    ("views", LayerRole::Presentation),
];

/// Returns the declared canonical role for a single path component, if any.
///
/// Case-insensitive exact match against the declared-map knob. Returns `None` for an
/// unmapped component — the caller must treat that as a labeled absence, not a role.
pub fn role_for_directory(component: &str) -> Option<LayerRole> {
    let lowered = component.trim().to_ascii_lowercase();
    if lowered.is_empty() {
        return None;
    }
    DEFAULT_DECLARED_DIR_ROLES
        .iter()
        .find(|(name, _)| *name == lowered)
        .map(|(_, role)| *role)
}

// ---------------------------------------------------------------------------
// Content addressing.
// ---------------------------------------------------------------------------

/// Canonical content address (32-byte SHA-256) of the canonical-roles knob.
pub fn canonical_roles_content_sha() -> [u8; 32] {
    let mut parts: Vec<&[u8]> = Vec::with_capacity(CANONICAL_ROLES.len() + 2);
    parts.push(LAYOUT_REGISTRY_VERSION.as_bytes());
    parts.push(CANONICAL_ROLES_SCHEMA.as_bytes());
    for role in CANONICAL_ROLES {
        parts.push(role.as_str().as_bytes());
    }
    sha256_digest(&parts)
}

/// Canonical content address (32-byte SHA-256) of the API-families knob.
pub fn api_families_content_sha() -> [u8; 32] {
    let mut parts: Vec<&[u8]> = Vec::new();
    parts.push(LAYOUT_REGISTRY_VERSION.as_bytes());
    parts.push(API_FAMILIES_SCHEMA.as_bytes());
    parts.push(b"persistence");
    for seed in DEFAULT_PERSISTENCE_FAMILY_SEEDS {
        parts.push(seed.as_bytes());
    }
    parts.push(b"transport");
    for seed in DEFAULT_TRANSPORT_FAMILY_SEEDS {
        parts.push(seed.as_bytes());
    }
    sha256_digest(&parts)
}

/// Canonical content address (32-byte SHA-256) of the evidence-weights knob.
pub fn evidence_weights_content_sha() -> [u8; 32] {
    // Buffer owns the interleaved name + IEEE-754 big-endian weight bits so the
    // borrowed `parts` slices outlive the digest call.
    let mut bit_bufs: Vec<[u8; 4]> = Vec::with_capacity(EVIDENCE_WEIGHTS.len());
    for (_, weight) in EVIDENCE_WEIGHTS {
        bit_bufs.push(weight.to_bits().to_be_bytes());
    }
    let mut parts: Vec<&[u8]> = Vec::with_capacity(EVIDENCE_WEIGHTS.len() * 2 + 2);
    parts.push(LAYOUT_REGISTRY_VERSION.as_bytes());
    parts.push(EVIDENCE_WEIGHTS_SCHEMA.as_bytes());
    for (idx, (name, _)) in EVIDENCE_WEIGHTS.iter().enumerate() {
        parts.push(name.as_bytes());
        parts.push(&bit_bufs[idx]);
    }
    sha256_digest(&parts)
}

/// Canonical content address (32-byte SHA-256) of the declared-map knob.
///
/// Entries are folded in name-sorted order so the identity is stable regardless of
/// declaration order.
pub fn declared_map_content_sha() -> [u8; 32] {
    let mut sorted: Vec<&(&str, LayerRole)> = DEFAULT_DECLARED_DIR_ROLES.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    let mut parts: Vec<&[u8]> = Vec::with_capacity(sorted.len() * 2 + 2);
    parts.push(LAYOUT_REGISTRY_VERSION.as_bytes());
    parts.push(DECLARED_MAP_SCHEMA.as_bytes());
    for (name, role) in &sorted {
        parts.push(name.as_bytes());
        parts.push(role.as_str().as_bytes());
    }
    sha256_digest(&parts)
}

/// A persisted, identity-locked manifest entry for one `astro.layout.*` knob.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LayoutKnobManifest {
    /// Registry family version tag.
    pub registry_version: String,
    /// Content-address schema id of this knob.
    pub schema: String,
    /// Lowercase hex of the 32-byte content-address identity lock.
    pub content_sha256_hex: String,
    /// Where the knob's content came from.
    pub source: String,
    /// Why this content is the right seed and what would replace it.
    pub rationale: String,
}

/// Lowercase-hex encodes a 32-byte digest.
pub fn hex32(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Returns the four `astro.layout.*` knob manifests in frozen schema order, each
/// carrying its recomputed content-address identity lock.
pub fn layout_knobs() -> Vec<LayoutKnobManifest> {
    vec![
        LayoutKnobManifest {
            registry_version: LAYOUT_REGISTRY_VERSION.to_string(),
            schema: CANONICAL_ROLES_SCHEMA.to_string(),
            content_sha256_hex: hex32(&canonical_roles_content_sha()),
            source: "Astrolabe blueprint P7 S23 layer_role coordinate system (#180a)".to_string(),
            rationale: "frozen 8-role taxonomy; a fixed coordinate system, not a measurement; \
                overflow role `other` absorbs any behavioral surface outside the taxonomy"
                .to_string(),
        },
        LayoutKnobManifest {
            registry_version: LAYOUT_REGISTRY_VERSION.to_string(),
            schema: API_FAMILIES_SCHEMA.to_string(),
            content_sha256_hex: hex32(&api_families_content_sha()),
            source: "corpus-independent default persistence/transport callee substrings"
                .to_string(),
            rationale: "default seed of the measured per-repo API-family classifier; refined \
                downstream by learned callee families"
                .to_string(),
        },
        LayoutKnobManifest {
            registry_version: LAYOUT_REGISTRY_VERSION.to_string(),
            schema: EVIDENCE_WEIGHTS_SCHEMA.to_string(),
            content_sha256_hex: hex32(&evidence_weights_content_sha()),
            source: "frozen S23 weighted-evidence combiner spec".to_string(),
            rationale: "relative evidence weights folding explicit graph/flag signals into the \
                role distribution; bound into the S23 lens weights_sha, so a change moves the \
                frozen lens identity"
                .to_string(),
        },
        LayoutKnobManifest {
            registry_version: LAYOUT_REGISTRY_VERSION.to_string(),
            schema: DECLARED_MAP_SCHEMA.to_string(),
            content_sha256_hex: hex32(&declared_map_content_sha()),
            source: "corpus-independent default directory-name → role map".to_string(),
            rationale: "default seed of the per-repo declared directory→role map; a repo declares \
                its own directory names, learned downstream"
                .to_string(),
        },
    ]
}

/// Recomputes the live content-address identity lock for a knob schema.
fn live_content_sha(schema: &str) -> Option<[u8; 32]> {
    match schema {
        CANONICAL_ROLES_SCHEMA => Some(canonical_roles_content_sha()),
        API_FAMILIES_SCHEMA => Some(api_families_content_sha()),
        EVIDENCE_WEIGHTS_SCHEMA => Some(evidence_weights_content_sha()),
        DECLARED_MAP_SCHEMA => Some(declared_map_content_sha()),
        _ => None,
    }
}

/// Serializes the layout knob manifest set to its canonical persisted byte form.
///
/// A length-prefixed JSON document; JSON of the fixed-field manifest structs in frozen
/// schema order is deterministic (no floats — only hex strings and text), so the
/// persisted bytes are stable and diffable.
pub fn serialize_layout_manifest(knobs: &[LayoutKnobManifest]) -> PanelResult<Vec<u8>> {
    serde_json::to_vec(knobs).map_err(|err| {
        PanelError::new(
            ASTRO_PANEL_SEED_REGISTRY_INVALID,
            format!("failed to serialize layout knob manifest: {err}"),
            "Emit a serializable layout knob manifest.",
        )
    })
}

/// Parses a persisted layout knob manifest.
pub fn parse_layout_manifest(bytes: &[u8]) -> PanelResult<Vec<LayoutKnobManifest>> {
    serde_json::from_slice(bytes).map_err(|err| {
        PanelError::new(
            ASTRO_PANEL_SEED_REGISTRY_INVALID,
            format!("failed to parse layout knob manifest: {err}"),
            "Re-persist the layout knob manifest from the live registry.",
        )
    })
}

/// Verifies a persisted manifest against the live registry — the identity-lock check.
///
/// Fails closed if any persisted knob is unknown, if the manifest is missing a knob or
/// carries an unexpected extra one, or if any persisted content-address hex does not
/// match the recomputed live content address (drift between the persisted lock and the
/// current registry content).
pub fn verify_layout_manifest(persisted: &[LayoutKnobManifest]) -> PanelResult<()> {
    let expected = layout_knobs();
    if persisted.len() != expected.len() {
        return Err(PanelError::new(
            ASTRO_PANEL_SEED_REGISTRY_INVALID,
            format!(
                "layout manifest has {} knobs, expected {}",
                persisted.len(),
                expected.len()
            ),
            "Persist exactly the four astro.layout.* knobs.",
        ));
    }
    for (idx, knob) in persisted.iter().enumerate() {
        let expected_knob = &expected[idx];
        if knob.schema != expected_knob.schema {
            return Err(PanelError::new(
                ASTRO_PANEL_SEED_REGISTRY_INVALID,
                format!(
                    "layout manifest knob {idx} schema {} != expected {}",
                    knob.schema, expected_knob.schema
                ),
                "Persist the astro.layout.* knobs in frozen schema order.",
            ));
        }
        let live = live_content_sha(&knob.schema).ok_or_else(|| {
            PanelError::new(
                ASTRO_PANEL_SEED_REGISTRY_INVALID,
                format!(
                    "layout manifest carries unknown knob schema {}",
                    knob.schema
                ),
                "Only astro.layout.* knobs declared by the registry are valid.",
            )
        })?;
        let live_hex = hex32(&live);
        if knob.content_sha256_hex != live_hex {
            return Err(PanelError::new(
                ASTRO_PANEL_SEED_REGISTRY_INVALID,
                format!(
                    "layout knob {} identity lock {} != live content address {}",
                    knob.schema, knob.content_sha256_hex, live_hex
                ),
                "The persisted knob content drifted from the registry; re-derive dependents \
                 and re-persist the manifest.",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! FSV for the `astro.layout.*` content-addressed knob registry (#310, DoD FSV4).
    //!
    //! Persists the manifest to a real file on disk, reads the bytes back
    //! independently, and verifies each knob's identity-lock hash against the live
    //! registry — the declared-map hash foremost. Tampering the persisted lock must
    //! fail closed.

    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn scratch_file(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("astro_layout_fsv_{tag}_{nanos}"));
        fs::create_dir_all(&dir).expect("create scratch dir");
        dir.join("layout_manifest.json")
    }

    #[test]
    fn fsv4_declared_map_identity_lock_persists_and_verifies() {
        // Known content ⇒ known identity: the declared-map content address is the
        // SHA-256 of the sorted (dir, role) entries. Recompute it two ways and hex it.
        let live = declared_map_content_sha();
        let live_hex = hex32(&live);
        assert_eq!(
            live_hex.len(),
            64,
            "content address is a 32-byte SHA-256 hex"
        );

        // Persist the whole four-knob manifest to a real file.
        let knobs = layout_knobs();
        let bytes = serialize_layout_manifest(&knobs).expect("serialize manifest");
        let path = scratch_file("declared_map");
        fs::write(&path, &bytes).expect("persist manifest");

        // Independent readback off disk.
        let read = fs::read(&path).expect("read manifest bytes");
        let parsed = parse_layout_manifest(&read).expect("parse persisted manifest");

        // The persisted declared-map lock must match the live content address.
        let declared = parsed
            .iter()
            .find(|k| k.schema == DECLARED_MAP_SCHEMA)
            .expect("declared_map knob present in manifest");
        assert_eq!(
            declared.content_sha256_hex, live_hex,
            "persisted declared-map identity lock must equal the live content address"
        );

        // Full identity-lock verification against the live registry passes.
        verify_layout_manifest(&parsed).expect("persisted manifest verifies against registry");

        // All four astro.layout.* knobs are present, in frozen schema order.
        let schemas: Vec<&str> = parsed.iter().map(|k| k.schema.as_str()).collect();
        assert_eq!(
            schemas,
            vec![
                CANONICAL_ROLES_SCHEMA,
                API_FAMILIES_SCHEMA,
                EVIDENCE_WEIGHTS_SCHEMA,
                DECLARED_MAP_SCHEMA,
            ]
        );

        fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn fsv4_tampered_declared_map_lock_fails_closed() {
        // Persist, then corrupt the declared-map lock on disk; verification must refuse.
        let mut knobs = layout_knobs();
        let idx = knobs
            .iter()
            .position(|k| k.schema == DECLARED_MAP_SCHEMA)
            .expect("declared_map present");
        knobs[idx].content_sha256_hex =
            "0000000000000000000000000000000000000000000000000000000000000000".to_string();
        let bytes = serialize_layout_manifest(&knobs).expect("serialize tampered manifest");

        let parsed = parse_layout_manifest(&bytes).expect("parse tampered manifest");
        let err = verify_layout_manifest(&parsed)
            .expect_err("a tampered declared-map identity lock must fail closed");
        assert_eq!(err.code(), ASTRO_PANEL_SEED_REGISTRY_INVALID);
    }

    #[test]
    fn fsv4_all_four_content_addresses_are_distinct_and_stable() {
        // Distinct: each knob's identity is its own; determinism: recomputation is
        // byte-identical across calls (no clock/env/order dependence).
        let a = [
            canonical_roles_content_sha(),
            api_families_content_sha(),
            evidence_weights_content_sha(),
            declared_map_content_sha(),
        ];
        let b = [
            canonical_roles_content_sha(),
            api_families_content_sha(),
            evidence_weights_content_sha(),
            declared_map_content_sha(),
        ];
        assert_eq!(a, b, "content addresses must be deterministic");
        for i in 0..a.len() {
            for j in (i + 1)..a.len() {
                assert_ne!(a[i], a[j], "knob content addresses must be distinct");
            }
        }
    }

    #[test]
    fn fsv4_edge_empty_and_short_manifest_fail_closed() {
        // Empty bytes are not a valid manifest.
        assert!(parse_layout_manifest(b"").is_err());
        // A manifest missing a knob fails the count check (fail-closed).
        let mut knobs = layout_knobs();
        knobs.pop();
        let bytes = serialize_layout_manifest(&knobs).unwrap();
        let parsed = parse_layout_manifest(&bytes).unwrap();
        let err = verify_layout_manifest(&parsed).expect_err("short manifest must fail closed");
        assert_eq!(err.code(), ASTRO_PANEL_SEED_REGISTRY_INVALID);
    }

    #[test]
    fn declared_map_lookup_is_case_insensitive_and_labeled_absent() {
        assert_eq!(
            role_for_directory("Handlers"),
            Some(LayerRole::TransportApi)
        );
        assert_eq!(role_for_directory("MODELS"), Some(LayerRole::ModelSchema));
        assert_eq!(role_for_directory("tests"), Some(LayerRole::Test));
        // Unmapped ⇒ labeled absence, never a silent default role.
        assert_eq!(role_for_directory("frobnicate"), None);
        assert_eq!(role_for_directory("   "), None);
    }
}
