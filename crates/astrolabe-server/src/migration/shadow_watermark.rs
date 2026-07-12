//! Self-describing, domain-tagged shadow content-freshness watermark (#223).
//!
//! The shadow freshness gate ([`evaluate_shadow_content_freshness`]) proves that a
//! persisted shadow import still matches the live CBM SQLite source by recomputing a
//! digest over that source and comparing it to a watermark persisted at import time.
//!
//! Before #223 that watermark was a **bare hex digest** with no record of which function
//! produced it, so the gate could not distinguish two completely different conditions —
//! both of which read as `Stale`:
//!
//! 1. the source genuinely changed (correct staleness), and
//! 2. the persisted watermark was produced by a *different* digest domain than the one
//!    the gate recomputes (a bug — #221 persisted `row_sink_fingerprint`, a digest over
//!    in-memory rows, where the gate recomputes `fingerprint_sqlite_hex`, a digest over
//!    the source *file* bytes; two values that can never be equal).
//!
//! Case (2) silently degraded to "permanently Stale", which drove the runner-less refresh
//! that clobbered the provenance surface (#222). A wrong-domain watermark is not stale
//! data — it is an *incommensurable* value, and comparing it is meaningless. It must fail
//! loud.
//!
//! The fix is the multiformats/multihash discipline applied to a config value: the stored
//! value **describes itself**, so a consumer never has to assume which function produced
//! it. Persisted form:
//!
//! ```text
//! sqlite-file-sha256:v1:<64 lowercase hex chars>
//! `-------algo------' `v' `-------digest--------'
//! ```
//!
//! [`parse_shadow_watermark`] classifies every stored value into exactly one of four
//! outcomes, and only the first is comparable:
//!
//! | stored value                        | classification            | gate behaviour                                |
//! |-------------------------------------|---------------------------|-----------------------------------------------|
//! | `sqlite-file-sha256:v1:<hex>`       | [`ShadowWatermark::Tagged`] (matching domain) | compare digests → `Fresh`/`Stale` |
//! | `row-sink-sha256:v1:<hex>` (or any other tag) | [`ShadowWatermark::Tagged`] (foreign domain)  | fail closed: `ASTRO_SHADOW_WATERMARK_DOMAIN_MISMATCH` |
//! | bare `<64 hex>` (pre-#223)          | [`ShadowWatermark::LegacyUntagged`] (v0)      | fail closed: `ASTRO_SHADOW_WATERMARK_LEGACY_UNTAGGED`, one reindex |
//! | anything else                       | [`ShadowWatermark::Malformed`]                | fail closed: `ASTRO_SHADOW_WATERMARK_MALFORMED` |
//!
//! A legacy untagged value is deliberately **not** compared even when it happens to equal
//! the recomputed digest: a v0 value may be either the source-file digest (post-#221) or
//! the row-sink digest (pre-#221), and nothing in the stored bytes distinguishes them. An
//! unprovable domain is refused, not guessed (standing invariant #2). One reindex
//! re-persists it in the tagged form and the project is permanently self-describing.

/// Registry-declared format identifier for the persisted shadow freshness watermark.
///
/// This is the declared contract for the `vault_fingerprint` config value, surfaced on
/// every `index_status` shadow-import summary so a consumer can see which watermark
/// format the server writes and parses. Bumping the format means bumping this constant
/// **and** [`SHADOW_WATERMARK_VERSION`]: an older watermark then classifies as a foreign
/// domain and fails closed with a reindex remediation instead of being compared across
/// incompatible domains.
pub(crate) const SHADOW_WATERMARK_FORMAT_REGISTRY_VERSION: &str = "astrolabe.shadow_watermark.v1";

/// The single digest domain the freshness gate computes: SHA-256 over the CBM SQLite
/// *source file* bytes, exactly as [`astrolabe_ingest::fingerprint_sqlite_hex`] produces.
///
/// Any other algorithm name in a persisted watermark — notably `row-sink-sha256`, the
/// digest over the in-memory pipeline rows — is incommensurable with this one and must
/// never be digest-compared against it (#221/#223).
pub(crate) const SHADOW_WATERMARK_ALGO: &str = "sqlite-file-sha256";

/// Version of the tagged watermark encoding the gate writes and accepts.
pub(crate) const SHADOW_WATERMARK_VERSION: &str = "v1";

/// The implicit version of a pre-#223 bare-hex watermark: untagged, domain unprovable.
pub(crate) const SHADOW_WATERMARK_LEGACY_VERSION: &str = "v0";

/// Algorithm label reported for a legacy untagged (v0) watermark, which records no algo.
pub(crate) const SHADOW_WATERMARK_LEGACY_ALGO: &str = "untagged";

/// Algorithm/version labels reported for a watermark that does not parse at all.
pub(crate) const SHADOW_WATERMARK_UNPARSEABLE_ALGO: &str = "unparseable";
pub(crate) const SHADOW_WATERMARK_UNPARSEABLE_VERSION: &str = "unknown";

/// Field separator of the tagged encoding.
const SHADOW_WATERMARK_SEPARATOR: char = ':';

/// Number of `algo:version:digest` fields in a tagged watermark.
const SHADOW_WATERMARK_FIELDS: usize = 3;

/// Length in characters of a lowercase-hex SHA-256 digest.
const SHA256_HEX_LEN: usize = 64;

/// The persisted watermark carries an algorithm/version tag the freshness gate does not
/// compute, so its digest is incommensurable with the recomputed one. Fail closed — this
/// is NOT ordinary staleness (#223).
pub(crate) const ASTRO_SHADOW_WATERMARK_DOMAIN_MISMATCH: &str =
    "ASTRO_SHADOW_WATERMARK_DOMAIN_MISMATCH";

/// The persisted watermark is a pre-#223 bare hex digest (v0): its domain is not recorded,
/// so it cannot be proven commensurable with the gate's digest. One reindex re-persists it
/// in the tagged form.
pub(crate) const ASTRO_SHADOW_WATERMARK_LEGACY_UNTAGGED: &str =
    "ASTRO_SHADOW_WATERMARK_LEGACY_UNTAGGED";

/// The persisted watermark is neither a tagged value nor a bare hex digest — the stored
/// metadata is corrupt or from an incompatible version.
pub(crate) const ASTRO_SHADOW_WATERMARK_MALFORMED: &str = "ASTRO_SHADOW_WATERMARK_MALFORMED";

pub(crate) const SHADOW_WATERMARK_DOMAIN_MISMATCH_REMEDIATION: &str = "the persisted shadow freshness watermark was produced by a different digest domain than the freshness gate computes, so no comparison against it is meaningful; rerun index_repository with calyx=\"shadow\" to re-import from current source and re-persist a watermark in this server's domain";

pub(crate) const SHADOW_WATERMARK_LEGACY_UNTAGGED_REMEDIATION: &str = "the persisted shadow freshness watermark predates the self-describing format, so the digest domain that produced it cannot be proven (it may be the source-file digest or the incommensurable row-sink digest); run index_repository with calyx=\"shadow\" once to re-persist it in the tagged format";

pub(crate) const SHADOW_WATERMARK_MALFORMED_REMEDIATION: &str = "the persisted shadow freshness watermark is not a tagged watermark or a hex digest; the stored shadow metadata is corrupt or from an incompatible version. Rerun index_repository with calyx=\"shadow\" to rebuild the shadow state from current source";

/// A persisted `vault_fingerprint` watermark, classified by whether its digest domain can
/// be proven to be the one the freshness gate recomputes.
///
/// Only [`ShadowWatermark::Tagged`] whose `algo`/`version` equal [`SHADOW_WATERMARK_ALGO`]
/// / [`SHADOW_WATERMARK_VERSION`] may have its digest compared; every other classification
/// is a fail-closed refusal, never a `Stale` verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ShadowWatermark {
    /// A self-describing `algo:version:digest` watermark. The algo/version may still be
    /// foreign — the caller compares them against the domain it computes.
    Tagged {
        algo: String,
        version: String,
        digest: String,
    },
    /// A pre-#223 bare hex digest with no domain record (implicitly `v0`).
    LegacyUntagged { digest: String },
    /// A stored value that is neither tagged nor a bare hex digest.
    Malformed { raw: String, reason: String },
}

/// Renders `digest` (a lowercase-hex SHA-256 of the CBM SQLite source file) in the tagged
/// v1 watermark form that [`parse_shadow_watermark`] accepts as this server's domain.
///
/// This is the only function that writes the persisted `vault_fingerprint` value.
pub(crate) fn format_shadow_watermark(digest: &str) -> String {
    format!(
        "{SHADOW_WATERMARK_ALGO}{SHADOW_WATERMARK_SEPARATOR}{SHADOW_WATERMARK_VERSION}{SHADOW_WATERMARK_SEPARATOR}{digest}"
    )
}

/// Classifies a persisted watermark value. Never panics and never guesses: an
/// unrecognized shape is [`ShadowWatermark::Malformed`], not a silently-accepted digest.
///
/// A tagged value must have exactly three non-empty `algo:version:digest` fields. When the
/// algo/version identify *this* server's domain the digest is additionally required to be
/// a 64-character lowercase-hex SHA-256 — a value claiming our domain with a malformed
/// digest is corrupt, not comparable. A foreign tag's digest shape is deliberately not
/// validated: we do not know that domain's digest encoding, and we will refuse it anyway.
pub(crate) fn parse_shadow_watermark(raw: &str) -> ShadowWatermark {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return ShadowWatermark::Malformed {
            raw: raw.to_string(),
            reason: "the persisted watermark is empty".to_string(),
        };
    }

    if !trimmed.contains(SHADOW_WATERMARK_SEPARATOR) {
        // Pre-#223 form: a bare digest. Accept it only as a legacy (v0) value whose domain
        // is unknown; anything that is not a SHA-256 hex digest is corrupt.
        return if is_sha256_hex_lower(trimmed) {
            ShadowWatermark::LegacyUntagged {
                digest: trimmed.to_string(),
            }
        } else {
            ShadowWatermark::Malformed {
                raw: raw.to_string(),
                reason: format!(
                    "the persisted watermark carries no {SHADOW_WATERMARK_SEPARATOR:?}-separated domain tag and is not a {SHA256_HEX_LEN}-character lowercase-hex SHA-256 digest either"
                ),
            }
        };
    }

    let fields = trimmed
        .split(SHADOW_WATERMARK_SEPARATOR)
        .collect::<Vec<_>>();
    if fields.len() != SHADOW_WATERMARK_FIELDS || fields.iter().any(|field| field.is_empty()) {
        return ShadowWatermark::Malformed {
            raw: raw.to_string(),
            reason: format!(
                "a tagged watermark must be exactly {SHADOW_WATERMARK_FIELDS} non-empty {SHADOW_WATERMARK_SEPARATOR:?}-separated fields (algo:version:digest); found {}",
                fields.len()
            ),
        };
    }
    let (algo, version, digest) = (fields[0], fields[1], fields[2]);

    if algo == SHADOW_WATERMARK_ALGO
        && version == SHADOW_WATERMARK_VERSION
        && !is_sha256_hex_lower(digest)
    {
        return ShadowWatermark::Malformed {
            raw: raw.to_string(),
            reason: format!(
                "the watermark claims this server's {SHADOW_WATERMARK_ALGO}:{SHADOW_WATERMARK_VERSION} domain but its digest is not a {SHA256_HEX_LEN}-character lowercase-hex SHA-256"
            ),
        };
    }

    ShadowWatermark::Tagged {
        algo: algo.to_string(),
        version: version.to_string(),
        digest: digest.to_string(),
    }
}

/// True only for exactly 64 lowercase-hex characters — the shape
/// [`astrolabe_ingest::fingerprint_sqlite_hex`] emits.
fn is_sha256_hex_lower(value: &str) -> bool {
    value.len() == SHA256_HEX_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
