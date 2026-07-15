//! `query_graph` `as_of` time-travel (#43 final leg).
//!
//! `query_graph` is a CBM-native Cypher tool: without `as_of` it is served
//! byte-for-byte by libcbm against the project's live store and is NEVER altered
//! here. The only divergence is an opt-in `as_of=<epoch_millis>` knob, which
//! serves the Cypher read against a **temporally-consistent historical view** of
//! the graph:
//!
//! 1. The shadow vault is opened read-only and the wall-clock `as_of` is resolved
//!    to an MVCC snapshot sequence through the vault's own `time_index` CF
//!    ([`AsterVault::as_of`]) — the greatest committed seqno at or before the
//!    timestamp, fail-closed (`CALYX_TIMETRAVEL_*`) when the vault has no write at
//!    or before `t` or `t` is below the retention horizon.
//! 2. The timestamp is quantized to a cache bucket `floor(t / width)` (`width` is
//!    the registry-declared [`AS_OF_BUCKET_WIDTH_MS_KNOB`]). Each bucket owns a
//!    private store directory whose `<project>.db` is the lowered SQLite of that
//!    bucket-floor snapshot ([`lower_cbm_sqlite_at`], a pure function of the
//!    seqno). Every `t` in a bucket reuses that one lowered artifact
//!    byte-for-byte; crossing into a new bucket re-lowers (a boundary miss).
//! 3. The CBM store is pointed at the bucket's store directory
//!    ([`astrolabe_bridge::set_cbm_cache_dir`]) only for the duration of the one
//!    Cypher call, then restored to the live store — success or error. The
//!    process-global store switch is serialized by a mutex; the CBM tool runner is
//!    itself driven single-threaded per request, so no concurrent tool call
//!    observes the switched store.
//!
//! The Cypher read subset is unchanged: the same query runs, only against the
//! historical `<project>.db`. Every `as_of` response carries a labeled `as_of`
//! block plus `trust`/`freshness`/`provenance` (invariant 1).
//!
//! SERVER-PENDING (lane/w15-43): the pure-Rust `as_of` lowering engine
//! (`astrolabe-lower::lower_cbm_sqlite_at` + the per-t-bucket cache) is FSV-verified
//! natively; this server routing (arg plumbing, CBM store-dir override, envelope
//! labeling) compiles and is exercised by the pure-JSON unit tests below, but the
//! end-to-end CBM Cypher-against-the-historical-store path must be verified on the
//! native pass with libcbm linked (the occupied C toolchain blocked it in-lane).

use super::*;

/// Surface schema tag for the `as_of` envelope block.
pub(crate) const QUERY_GRAPH_AS_OF_SCHEMA: &str = "astrolabe.query_graph.as_of.v1";

/// Stable refusal code: `as_of` was supplied but is not a non-negative integer
/// count of epoch milliseconds.
pub(crate) const ASTRO_QUERY_GRAPH_AS_OF_INVALID: &str = "ASTRO_QUERY_GRAPH_AS_OF_INVALID";
/// Stable refusal code: `as_of` needs the shadow vault, but the project carries
/// no `project` argument.
pub(crate) const ASTRO_QUERY_GRAPH_AS_OF_PROJECT: &str = "ASTRO_QUERY_GRAPH_AS_OF_PROJECT";
/// Stable refusal code: the project is not shadow-indexed, so there is no vault
/// history to time-travel.
pub(crate) const ASTRO_QUERY_GRAPH_AS_OF_SHADOW: &str = "ASTRO_QUERY_GRAPH_AS_OF_SHADOW";

/// Serializes the process-global CBM store switch so an `as_of` Cypher call
/// never overlaps another tool call's view of the store.
static AS_OF_STORE_SWITCH: Mutex<()> = Mutex::new(());

/// True when the request opted into an `as_of` historical read.
pub(crate) fn query_graph_as_of_requested(args: &Map<String, Value>) -> bool {
    args.contains_key("as_of")
}

/// Parses `as_of` as a non-negative epoch-millisecond integer.
fn parse_as_of_millis(value: &Value) -> Option<u64> {
    match value {
        Value::Number(n) => n.as_u64(),
        // A JSON string of digits is accepted for clients that cannot express a
        // 64-bit integer natively; anything else is refused.
        Value::String(s) => s.parse::<u64>().ok(),
        _ => None,
    }
}

/// The effective bucket width from its registry declaration (single source of the
/// default; invariant 4).
fn as_of_bucket_width_ms() -> u64 {
    as_of_bucket_knob(AS_OF_BUCKET_WIDTH_MS_KNOB)
        .map_or(AS_OF_BUCKET_DEFAULT_WIDTH_MS, |knob| knob.default)
}

/// MCP entry point for `query_graph`.
///
/// Without `as_of` this is a byte-identical passthrough to the CBM tool. With
/// `as_of` it serves the Cypher read against the historical `<project>.db`
/// lowered from the vault at the resolved snapshot, and labels the envelope.
pub(crate) fn handle_query_graph(
    runner: &CbmToolRunner,
    args_json: &str,
) -> Result<String, DynError> {
    let Ok(args) = serde_json::from_str::<Value>(args_json) else {
        return Ok(runner.handle_tool_raw("query_graph", args_json)?);
    };
    let Some(args_obj) = args.as_object() else {
        return Ok(runner.handle_tool_raw("query_graph", args_json)?);
    };
    let Some(as_of_value) = args_obj.get("as_of") else {
        // Pure legacy request — CBM serves it byte-for-byte against the live store.
        return Ok(runner.handle_tool_raw("query_graph", args_json)?);
    };

    let Some(as_of_millis) = parse_as_of_millis(as_of_value) else {
        return coded_error(
            ASTRO_QUERY_GRAPH_AS_OF_INVALID,
            "query_graph as_of must be a non-negative integer count of epoch milliseconds",
            "Pass as_of=<epoch_millis>, e.g. as_of=1720000000000.",
        );
    };
    let Some(project) = status_project_from_args(args_obj)? else {
        return coded_error(
            ASTRO_QUERY_GRAPH_AS_OF_PROJECT,
            "query_graph as_of requires a project to resolve the shadow vault history",
            "Pass project=\"<name>\" alongside as_of.",
        );
    };
    if read_dial(&project)? != MigrationDial::Shadow {
        return coded_error(
            ASTRO_QUERY_GRAPH_AS_OF_SHADOW,
            format!("project {project:?} is not shadow-indexed; as_of needs the vault timeline"),
            "Run index_repository with calyx=\"shadow\" for this project before an as_of query.",
        );
    }

    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    let width_ms = as_of_bucket_width_ms();
    let bucket = as_of_millis / width_ms;
    let canonical_millis = bucket.saturating_mul(width_ms);

    let (store_dir, resolved_seq, cache_hit) =
        prepare_as_of_store(&cache_dir, &project, bucket, canonical_millis)?;

    // Strip the Astrolabe-only `as_of` knob before the CBM tool sees it.
    let mut sanitized = args_obj.clone();
    sanitized.remove("as_of");
    let sanitized_json = serde_json::to_string(&Value::Object(sanitized))?;

    // Point CBM at the historical store for exactly this one Cypher call, then
    // restore the live store on any outcome. The switch is process-global, so it
    // is serialized; restoration is unconditional (before `?` propagation).
    let guard = AS_OF_STORE_SWITCH
        .lock()
        .map_err(|_| "as_of store-switch mutex poisoned")?;
    let original = astrolabe_bridge::cbm_cache_dir()?;
    astrolabe_bridge::set_cbm_cache_dir(&store_dir)?;
    let raw_result = runner.handle_tool_raw("query_graph", &sanitized_json);
    let restore = astrolabe_bridge::set_cbm_cache_dir(&original);
    drop(guard);
    let raw = raw_result?;
    restore?;

    let meta = AsOfMeta {
        requested_millis: as_of_millis,
        canonical_millis,
        bucket,
        bucket_width_ms: width_ms,
        resolved_seq,
        cache_hit,
        store: store_dir.display().to_string(),
    };
    label_as_of_result(&raw, &meta)
}

/// Ensures the bucket's historical store directory holds a `<project>.db` lowered
/// from the vault at the bucket-floor snapshot, lowering it on a boundary miss.
/// Returns the store dir, the resolved MVCC seqno, and whether the artifact was
/// already cached.
fn prepare_as_of_store(
    cache_dir: &Path,
    project: &str,
    bucket: u64,
    canonical_millis: u64,
) -> Result<(PathBuf, u64, bool), DynError> {
    let (vault_dir, vault_id, vault_salt) = shadow_vault_config_at(cache_dir, project)?;
    if !vault_dir.exists() {
        return Err(format!("shadow vault dir missing: {}", vault_dir.display()).into());
    }
    // Read-only over all CFs: the lowering reads Base/Graph/Ledger and the
    // time-travel resolution reads the TimeIndex CF.
    let vault = open_shadow_vault_read_only(&vault_dir, &vault_id, &vault_salt, Vec::new())?;
    let snapshot = vault.as_of(canonical_millis)?;
    let resolved_seq = snapshot.seqno();

    let store_dir = as_of_bucket_store_dir(cache_dir, project, bucket);
    // The CBM native store db for a project is `<store_dir>/<project>.db`
    // (`super::sqlite_path`); placing the historical lowered artifact there lets
    // libcbm resolve it as the project's graph store when pointed at store_dir.
    let db_path = sqlite_path(&store_dir, project);
    if db_path.exists() {
        return Ok((store_dir, resolved_seq, true));
    }
    fs::create_dir_all(&store_dir)?;
    let options = LowerSqliteOptions::new(project.to_string())
        .with_lowered_at(format!("as_of:{canonical_millis}"));
    lower_cbm_sqlite_at(&vault, &db_path, &options, resolved_seq)?;
    drop(snapshot);
    Ok((store_dir, resolved_seq, false))
}

/// Per-(cache_dir-relative) bucket store directory for a project's historical
/// views. Kept under the cache dir so it shares the store's lifecycle and is
/// cleaned with it.
fn as_of_bucket_store_dir(cache_dir: &Path, project: &str, bucket: u64) -> PathBuf {
    // Structural sanitization: the project must flatten to ONE traversal-free,
    // device-free Windows path component BY CONSTRUCTION, for any input class —
    // not merely for the inputs a test happens to plant. Three hazard classes:
    //   (a) `.`/`..` traversal components,
    //   (b) any ".." substring (never representable: a dot is only admitted when
    //       the previous emitted byte is not a dot, so consecutive dots collapse
    //       to `._` while building),
    //   (c) Windows reserved device names (CON/PRN/AUX/NUL/COM1-9/LPT1-9, with
    //       any extension — `nul.txt` IS the NUL device; the superscript
    //       COM¹/²/³ forms are non-ASCII and already fold to '_' in the char
    //       filter).
    // A name that still lands in a hazard class is disambiguated by suffixing a
    // short hash of the RAW project string: deterministic, collision-safe (the
    // hash input is the raw name, so two distinct raw names cannot converge),
    // and cache-appropriate (nothing needs to survive but uniqueness).
    let mut safe = String::with_capacity(project.len());
    for ch in project.chars() {
        let mapped = if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
            ch
        } else {
            '_'
        };
        if mapped == '.' && safe.ends_with('.') {
            safe.push('_');
        } else {
            safe.push(mapped);
        }
    }
    const RESERVED_DEVICE_STEMS: [&str; 22] = [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    let stem = safe.split('.').next().unwrap_or("").to_ascii_uppercase();
    if safe.is_empty() || safe == "." || RESERVED_DEVICE_STEMS.contains(&stem.as_str()) {
        // The hash must land in the STEM (prefix position): device reservation
        // is decided by the name before the first dot, so a suffix after an
        // extension ("nul.txt-p1234") would leave the stem "nul" reserved.
        let digest = Sha256::digest(project.as_bytes());
        safe = format!(
            "p{:02x}{:02x}{:02x}{:02x}-{safe}",
            digest[0], digest[1], digest[2], digest[3]
        );
    }
    debug_assert!(
        !safe.is_empty() && safe != "." && safe != ".." && !safe.contains(".."),
        "sanitized project component must be traversal-free by construction: {safe}"
    );
    cache_dir
        .join(".astrolabe-asof")
        .join(safe)
        .join(format!("bucket-{bucket}"))
}

/// The `as_of` provenance metadata stamped onto a served historical result.
pub(crate) struct AsOfMeta {
    requested_millis: u64,
    canonical_millis: u64,
    bucket: u64,
    bucket_width_ms: u64,
    resolved_seq: u64,
    cache_hit: bool,
    store: String,
}

impl AsOfMeta {
    fn as_of_block(&self) -> Value {
        json!({
            "schema": QUERY_GRAPH_AS_OF_SCHEMA,
            "requested_millis": self.requested_millis,
            "bucket": self.bucket,
            "bucket_width_ms": self.bucket_width_ms,
            "canonical_millis": self.canonical_millis,
            "resolved_seq": self.resolved_seq,
            "cache_hit": self.cache_hit,
            "store": self.store,
            "knob_registry_version": astrolabe_lower::AS_OF_BUCKET_KNOB_REGISTRY_VERSION,
        })
    }
}

/// Labels a CBM `query_graph` result served against a historical store with the
/// `as_of` provenance block and the trust/freshness/provenance envelope. Pure
/// JSON→JSON transform (the FSV workhorse): the `structuredContent` object and
/// the mirrored `content[0].text` payload are kept byte-consistent.
pub(crate) fn label_as_of_result(raw: &str, meta: &AsOfMeta) -> Result<String, DynError> {
    if tool_result_is_error(raw)? {
        // A Cypher error over the historical store is surfaced verbatim — never
        // relabeled as a grounded answer.
        return Ok(raw.to_string());
    }
    let mut envelope: Value = serde_json::from_str(raw)?;

    if let Some(structured) = envelope
        .get_mut("structuredContent")
        .and_then(Value::as_object_mut)
    {
        label_as_of_obj(structured, meta);
    }
    if let Some(text) = envelope
        .get_mut("content")
        .and_then(Value::as_array_mut)
        .and_then(|items| items.first_mut())
        .and_then(|item| item.get_mut("text"))
        && let Some(raw_text) = text.as_str()
        && let Ok(mut text_value) = serde_json::from_str::<Value>(raw_text)
        && let Some(text_obj) = text_value.as_object_mut()
    {
        label_as_of_obj(text_obj, meta);
        *text = Value::String(serde_json::to_string(&text_value)?);
    }

    Ok(serde_json::to_string(&envelope)?)
}

/// Stamps one CBM result object with the `as_of` block and envelope labels.
fn label_as_of_obj(obj: &mut Map<String, Value>, meta: &AsOfMeta) {
    obj.insert("as_of".to_string(), meta.as_of_block());
    // Envelope labels (invariant 1): the answer is grounded in a Cypher read of
    // the historical lowered store; freshness is `historical` because it is a
    // pinned time-travel view, not the live graph.
    obj.insert("trust".to_string(), json!("grounded"));
    obj.insert("freshness".to_string(), json!("historical"));
    obj.insert(
        "provenance".to_string(),
        json!(format!(
            "{QUERY_GRAPH_AS_OF_SCHEMA}: Cypher read of the vault lowered at MVCC seq {} \
             (as_of={}ms, bucket {}), served from {} store",
            meta.resolved_seq,
            meta.requested_millis,
            meta.bucket,
            if meta.cache_hit {
                "cached"
            } else {
                "freshly-lowered"
            }
        )),
    );
}

/// A coded fail-closed `query_graph` result in the CBM tool-result envelope shape.
fn coded_error(
    code: &str,
    message: impl Into<String>,
    remediation: &str,
) -> Result<String, DynError> {
    let message = message.into();
    let payload = json!({
        "code": code,
        "message": message,
        "remediation": remediation,
    });
    Ok(serde_json::to_string(&json!({
        "content": [{"type": "text", "text": serde_json::to_string(&payload)?}],
        "structuredContent": payload,
        "isError": true,
    }))?)
}

/// The Astrolabe `as_of` extension advertised on the CBM `query_graph` schema in
/// tools/list, so a client can discover the opt-in time-travel (#43).
pub(crate) fn query_graph_astrolabe_property_overlay() -> Vec<(String, Value)> {
    vec![(
        "as_of".to_string(),
        json!({
            "type": "integer",
            "minimum": 0,
            "description": "Astrolabe extension (#43): epoch-millisecond timestamp for a \
                time-travel Cypher read. When set, the query runs against a temporally-consistent \
                historical view of the graph — the vault is resolved to the greatest committed \
                MVCC snapshot at or before this time (via the time_index CF) and lowered to a \
                per-time-bucket store. Fails closed if the vault has no state at or before the \
                timestamp. Omitted keeps the byte-identical live query."
        }),
    )]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cbm_query_result(rows: Value) -> String {
        let text = serde_json::to_string(&rows).unwrap();
        serde_json::to_string(&json!({
            "content": [{"type": "text", "text": text}],
            "structuredContent": rows,
            "isError": false,
        }))
        .unwrap()
    }

    fn meta() -> AsOfMeta {
        AsOfMeta {
            requested_millis: 1_500,
            canonical_millis: 1_000,
            bucket: 1,
            bucket_width_ms: 1_000,
            resolved_seq: 7,
            cache_hit: false,
            store: "C:/store/.astrolabe-asof/demo/bucket-1".to_string(),
        }
    }

    #[test]
    fn as_of_request_detection() {
        let with =
            serde_json::json!({"project": "demo", "query": "MATCH (n) RETURN n", "as_of": 1500});
        assert!(query_graph_as_of_requested(with.as_object().unwrap()));
        let without = serde_json::json!({"project": "demo", "query": "MATCH (n) RETURN n"});
        assert!(!query_graph_as_of_requested(without.as_object().unwrap()));
    }

    #[test]
    fn parses_integer_and_digit_string_as_of() {
        assert_eq!(
            parse_as_of_millis(&json!(1_720_000_000_000_u64)),
            Some(1_720_000_000_000)
        );
        assert_eq!(parse_as_of_millis(&json!("42")), Some(42));
        assert_eq!(parse_as_of_millis(&json!(-5)), None);
        assert_eq!(parse_as_of_millis(&json!("not-a-number")), None);
        assert_eq!(parse_as_of_millis(&json!(1.5)), None);
    }

    #[test]
    fn labels_structured_and_text_consistently() {
        let raw = cbm_query_result(json!({"total": 2, "rows": [{"a": "x"}, {"a": "y"}]}));
        let out = label_as_of_result(&raw, &meta()).expect("label");
        let envelope: Value = serde_json::from_str(&out).unwrap();

        let structured = envelope.get("structuredContent").unwrap();
        assert_eq!(structured["trust"].as_str(), Some("grounded"));
        assert_eq!(structured["freshness"].as_str(), Some("historical"));
        assert!(structured["provenance"].as_str().unwrap().contains("seq 7"));
        assert_eq!(structured["as_of"]["bucket"].as_u64(), Some(1));
        assert_eq!(structured["as_of"]["resolved_seq"].as_u64(), Some(7));
        assert_eq!(
            structured["as_of"]["requested_millis"].as_u64(),
            Some(1_500)
        );
        assert_eq!(structured["as_of"]["cache_hit"].as_bool(), Some(false));
        // The original CBM payload survives untouched.
        assert_eq!(structured["total"].as_u64(), Some(2));

        // structuredContent and content[0].text carry the identical labeling.
        let text = envelope["content"][0]["text"].as_str().unwrap();
        let text_obj: Value = serde_json::from_str(text).unwrap();
        assert_eq!(&text_obj, structured);
    }

    #[test]
    fn cbm_error_result_is_surfaced_verbatim() {
        let err = serde_json::to_string(&json!({
            "content": [{"type": "text", "text": "syntax error near RETURN"}],
            "isError": true,
        }))
        .unwrap();
        let out = label_as_of_result(&err, &meta()).expect("passthrough");
        assert_eq!(
            out, err,
            "an error result must never be relabeled as grounded"
        );
    }

    #[test]
    fn bucket_store_dir_is_sandboxed_and_sanitized() {
        let dir = as_of_bucket_store_dir(Path::new("C:/store"), "weird/../name", 3);
        let s = dir.display().to_string();
        assert!(s.contains(".astrolabe-asof"));
        assert!(s.contains("bucket-3"));
        assert!(!s.contains(".."), "project segment must be sanitized: {s}");
        // Traversal-shaped raw names can never surface a ".." substring or a
        // bare-dot component — the property holds by construction, not by
        // enumerating inputs.
        for raw in ["..", ".", "a..b", "../..", "...."] {
            let dir = as_of_bucket_store_dir(Path::new("C:/store"), raw, 3);
            let component = dir
                .parent()
                .and_then(Path::file_name)
                .and_then(|c| c.to_str())
                .expect("project component present");
            assert!(
                !component.contains(".."),
                "no traversal substring: {raw} -> {component}"
            );
            assert!(
                component != "." && component != "..",
                "no dot component: {component}"
            );
        }
        // Windows reserved device names: a project literally named `nul` (or
        // `nul.txt` — an extension does not un-reserve a device) must not become
        // a raw device-path component. Fail-closed by deterministic
        // disambiguation, never by panicking.
        for raw in ["nul", "NUL", "nul.txt", "com1"] {
            let dir = as_of_bucket_store_dir(Path::new("C:/store"), raw, 3);
            let component = dir
                .parent()
                .and_then(Path::file_name)
                .and_then(|c| c.to_str())
                .expect("project component present");
            let stem = component.split('.').next().unwrap_or("");
            assert!(
                !["CON", "PRN", "AUX", "NUL", "COM1", "LPT1"]
                    .iter()
                    .any(|d| stem.eq_ignore_ascii_case(d)),
                "reserved device stem must be disambiguated: {raw} -> {component}"
            );
            assert!(
                !component.contains(".."),
                "no traversal substring: {component}"
            );
            // Deterministic: the same raw name maps to the same directory.
            assert_eq!(dir, as_of_bucket_store_dir(Path::new("C:/store"), raw, 3));
        }
        // Collision safety: the disambiguation hashes the RAW name, so a raw
        // name adjacent to a reserved one cannot collide with its rewrite.
        assert_ne!(
            as_of_bucket_store_dir(Path::new("C:/store"), "nul", 3),
            as_of_bucket_store_dir(Path::new("C:/store"), "nul_", 3),
        );
    }
}
