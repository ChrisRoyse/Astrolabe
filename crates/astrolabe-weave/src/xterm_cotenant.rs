//! Co-tenant classifier for readers that scan the whole `ColumnFamily::XTerm`
//! (#369).
//!
//! `ColumnFamily::XTerm` is shared: loom-native [`XtermRow`] JSON rows live
//! there alongside co-tenant rows written by other Astrolabe lanes. The shadow
//! importer's layout lane co-tenants `astrolabe.placement_truth.v1`
//! cross-term rows into this CF, and those rows are **line-based text**
//! (`schema=<tag>\n…`), not JSON — so any reader that strict-decodes every row
//! as an [`XtermRow`] fails closed with `CALYX_ASTER_CORRUPT_SHARD` on a real
//! indexed corpus (CONFIRMED LIVE on `cbm/`: "decode live XTerm anomaly row:
//! expected value at line 1 column 1").
//!
//! This mirrors the #348 Assay-CF fix: a **positive** schema-tag allowlist. A
//! row that fails to decode as an `XtermRow` is inspected for a recognized
//! co-tenant schema marker; only an accepted marker yields a counted skip.
//! Anything else — invalid JSON with no schema tag, an unaccepted schema — is
//! genuine corruption and still fails the read closed (invariant 5 preserved,
//! invariant 3's skips are counted, never silent).

use std::collections::BTreeSet;

/// Schema tag of the layout `placement_truth` cross-term rows the shadow
/// importer's layout lane co-tenants into `ColumnFamily::XTerm`.
///
/// These rows are line-based text whose first line is
/// `schema=astrolabe.placement_truth.v1`. This const is the reader-side single
/// source of truth; a `#[test]` pins it byte-for-byte against
/// `astrolabe_kernel::PLACEMENT_TRUTH_SCHEMA` (the writer-side const) so the two
/// can never silently drift.
pub const XTERM_PLACEMENT_TRUTH_COTENANT_SCHEMA: &str = "astrolabe.placement_truth.v1";

/// The set of foreign schema tags a co-tenant-aware XTerm reader accepts as
/// counted skips rather than decoding as loom rows.
pub fn accepted_xterm_cotenant_schemas() -> BTreeSet<&'static str> {
    [XTERM_PLACEMENT_TRUTH_COTENANT_SCHEMA]
        .into_iter()
        .collect()
}

/// Positively extracts the top-level `schema` tag of a non-[`XtermRow`]
/// co-tenant row, or `None` when the bytes carry no recognizable schema marker.
///
/// Two on-disk co-tenant encodings are recognized:
/// - **JSON object** `{"schema":"<tag>", …}` (e.g. a future
///   `delta_invalidation`-style co-tenant), and
/// - **line-based text** whose first line is `schema=<tag>` (the layout
///   `placement_truth` / `scope_summary` artifact form).
///
/// This is a *positive* test: it never reports a tag for arbitrary bytes, so a
/// genuinely corrupt row (invalid JSON, no `schema=` first line) yields `None`
/// and the caller fails closed.
pub fn xterm_cotenant_schema_tag(value: &[u8]) -> Option<String> {
    // JSON object form first: {"schema":"<tag>", ...}.
    if let Ok(serde_json::Value::Object(map)) = serde_json::from_slice::<serde_json::Value>(value)
        && let Some(serde_json::Value::String(schema)) = map.get("schema")
    {
        return Some(schema.clone());
    }
    // Line-based text form: the first line is exactly `schema=<tag>`.
    let text = std::str::from_utf8(value).ok()?;
    let first_line = text.lines().next()?;
    first_line.strip_prefix("schema=").map(str::to_string)
}

/// True when `value` is an accepted co-tenant row (a counted skip) rather than a
/// genuine loom row or genuine corruption.
pub fn is_accepted_xterm_cotenant(value: &[u8], accepted: &BTreeSet<&str>) -> bool {
    xterm_cotenant_schema_tag(value).is_some_and(|schema| accepted.contains(schema.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use astrolabe_kernel::{
        PLACEMENT_TRUTH_PROVENANCE, PLACEMENT_TRUTH_SCHEMA, PlacementTruthRow,
        placement_truth_row_bytes,
    };
    use astrolabe_panel::LayerRole;

    fn sample_placement_truth_bytes() -> Vec<u8> {
        // The exact on-disk shape the layout lane co-tenants into XTerm CF.
        placement_truth_row_bytes(&PlacementTruthRow {
            schema: PLACEMENT_TRUTH_SCHEMA,
            symbol_id: "cx:42".to_string(),
            qualified_name: "crate::foo::bar".to_string(),
            directory_id: "cx:7".to_string(),
            agreement: 0.75,
            symbol_role: LayerRole::Persistence,
            directory_role: LayerRole::Persistence,
            agrees: true,
            provenance: PLACEMENT_TRUTH_PROVENANCE,
        })
    }

    #[test]
    fn reader_side_schema_const_matches_the_writer_side_const() {
        // The reader-side allowlist const must equal the writer-side schema const
        // in astrolabe-kernel (single source of truth pinned by test — a drift
        // would silently reintroduce the strict-decode hazard).
        assert_eq!(
            XTERM_PLACEMENT_TRUTH_COTENANT_SCHEMA,
            PLACEMENT_TRUTH_SCHEMA
        );
    }

    #[test]
    fn detects_line_based_placement_truth_cotenant() {
        let bytes = sample_placement_truth_bytes();
        // Faithful shape: the first line is the schema= header, not JSON.
        assert!(bytes.starts_with(b"schema=astrolabe.placement_truth.v1\n"));
        assert_eq!(
            xterm_cotenant_schema_tag(&bytes).as_deref(),
            Some(PLACEMENT_TRUTH_SCHEMA)
        );
        assert!(is_accepted_xterm_cotenant(
            &bytes,
            &accepted_xterm_cotenant_schemas()
        ));
    }

    #[test]
    fn detects_json_object_cotenant() {
        let bytes = serde_json::to_vec(&serde_json::json!({
            "schema": "astrolabe.delta_invalidation.v1",
            "kind": "kernel_dirty_scc"
        }))
        .unwrap();
        assert_eq!(
            xterm_cotenant_schema_tag(&bytes).as_deref(),
            Some("astrolabe.delta_invalidation.v1")
        );
        // Not in the XTerm accepted set (delta-invalidation never lands here), so
        // it is not an accepted skip — the caller would fail closed.
        assert!(!is_accepted_xterm_cotenant(
            &bytes,
            &accepted_xterm_cotenant_schemas()
        ));
    }

    #[test]
    fn genuinely_corrupt_bytes_have_no_schema_tag() {
        // Raw non-JSON, non-`schema=` bytes: no positive marker, so the caller
        // fails closed (invariant 5).
        assert_eq!(xterm_cotenant_schema_tag(&[0xde, 0xad, 0xbe, 0xef]), None);
        // A text row whose first line is not `schema=` is not a co-tenant.
        assert_eq!(xterm_cotenant_schema_tag(b"kind=frame\nschema=x\n"), None);
        // Empty bytes: no marker.
        assert_eq!(xterm_cotenant_schema_tag(b""), None);
    }
}
