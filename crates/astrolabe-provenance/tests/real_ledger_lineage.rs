//! Real-ledger FSV for `get_provenance(mode="lineage")` and the edge-case triad.
//!
//! These tests do not hand-build lineage structs. They append entries through
//! the real Calyx ledger writer (`LedgerAppender`) into a disk-backed
//! `DirectoryLedgerStore`, drop the writer, reopen the store from disk, scan and
//! decode the *persisted ledger row bytes*, and only then build the lineage with
//! [`astrolabe_provenance::build_symbol_lineage`]. This is the same append/scan
//! path the server's live vault adapter uses; here it is exercised end-to-end
//! against bytes that were fsync'd to disk.

use std::path::PathBuf;

use calyx_core::FixedClock;
use calyx_ledger::{
    ActorId, DirectoryLedgerStore, EntryKind, LedgerAppender, LedgerCfStore, SubjectId,
    VerifyResult, decode, verify_chain,
};

use astrolabe_provenance::{
    ASTRO_PROVENANCE_LINEAGE_EMPTY, ASTRO_PROVENANCE_NOT_FOUND, ChainStatus, ChainVerification,
    Freshness, GET_PROVENANCE_SCHEMA, LedgerPointer, LedgerScanRow, PROVENANCE_WARN_CHAIN_BROKEN,
    PROVENANCE_WARN_CHAIN_CORRUPT, ProvenancePayload, ProvenanceQuery, ProvenanceStore,
    build_symbol_lineage, get_provenance, provenance_response_artifact_bytes,
};
use std::collections::BTreeMap;

const AUTH_LOGIN: &str = "symbol:auth.login";
const AUTH_TOKEN: &str = "symbol:auth.token";

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn scratch_dir(name: &str) -> PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push(format!(
        "astrolabe-provenance-real-ledger-{name}-{}",
        std::process::id()
    ));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// Appends the fixture ledger to a disk store and returns (root, entry count).
/// auth.login is ledgered at seqs 0,1,3 and auth.token at seq 2, so per-symbol
/// sequences are deliberately non-contiguous in the global ledger.
fn seed_real_ledger(root: &PathBuf) -> u64 {
    let store = DirectoryLedgerStore::open(root).expect("open disk ledger store");
    let mut appender = LedgerAppender::open(store, FixedClock::new(1)).expect("open appender");
    let actor = || ActorId::Service("astrolabe-provenance-test".to_string());
    let subject = |s: &str| SubjectId::Query(s.as_bytes().to_vec());

    appender
        .append(
            EntryKind::Ingest,
            subject(AUTH_LOGIN),
            b"initial import".to_vec(),
            actor(),
        )
        .expect("append login ingest");
    appender
        .append(
            EntryKind::Measure,
            subject(AUTH_LOGIN),
            b"panel measured".to_vec(),
            actor(),
        )
        .expect("append login measure");
    appender
        .append(
            EntryKind::Ingest,
            subject(AUTH_TOKEN),
            b"token import".to_vec(),
            actor(),
        )
        .expect("append token ingest");
    appender
        .append(
            EntryKind::Guard,
            subject(AUTH_LOGIN),
            b"guard verdict pass".to_vec(),
            actor(),
        )
        .expect("append login guard");

    // Drop the writer so nothing is buffered; the rows are now durable files.
    drop(appender);
    4
}

/// Reopens the store from disk and decodes every persisted ledger row into the
/// projected [`LedgerScanRow`] shape, exactly as the server's scan adapter would.
fn scan_rows_from_disk(root: &PathBuf) -> Vec<LedgerScanRow> {
    let store = DirectoryLedgerStore::open(root).expect("reopen disk ledger store");
    store
        .scan()
        .expect("scan persisted ledger rows")
        .into_iter()
        .map(|row| {
            let entry = decode(&row.bytes).expect("decode persisted ledger row");
            let subject = match &entry.subject {
                SubjectId::Query(bytes) => String::from_utf8(bytes.clone()).expect("subject utf8"),
                other => panic!("unexpected subject {other:?}"),
            };
            LedgerScanRow::new(
                entry.seq,
                hex_lower(&entry.entry_hash),
                entry.kind.as_str(),
                subject,
                String::from_utf8(entry.payload.clone()).unwrap_or_default(),
            )
        })
        .collect()
}

fn store_from_rows(rows: &[LedgerScanRow], head_seq: u64, head_hash: &str) -> ProvenanceStore {
    // Group scanned rows by subject and build each symbol's lineage from the
    // real persisted rows.
    let mut by_subject: BTreeMap<String, Vec<LedgerScanRow>> = BTreeMap::new();
    for row in rows {
        by_subject
            .entry(row.subject.clone())
            .or_default()
            .push(row.clone());
    }
    let mut symbols = BTreeMap::new();
    for (subject, subject_rows) in by_subject {
        let lineage = build_symbol_lineage(&subject, &subject_rows).expect("build lineage");
        symbols.insert(subject, lineage);
    }
    let head = LedgerPointer::new(head_seq, head_hash);
    ProvenanceStore {
        vault_fingerprint: "real-ledger-vault".to_string(),
        ledger_head: head.clone(),
        chain: ChainVerification {
            status: ChainStatus::Intact,
            checked_from: 0,
            checked_end: head_seq + 1,
            provenance: head,
        },
        symbols,
        answers: BTreeMap::new(),
        reproductions: BTreeMap::new(),
        manifests: BTreeMap::new(),
    }
}

#[test]
fn lineage_is_built_from_real_persisted_ledger_rows() {
    let root = scratch_dir("lineage");
    let count = seed_real_ledger(&root);

    // Independently verify the persisted chain and derive the real head pointer.
    let store_ref = DirectoryLedgerStore::open(&root).expect("reopen for verify");
    let verify = verify_chain(&store_ref, 0..count).expect("verify persisted chain");
    assert!(matches!(verify, VerifyResult::Intact { count: c } if c == count));

    let rows = scan_rows_from_disk(&root);
    assert_eq!(rows.len() as u64, count, "all persisted rows scanned");
    let head_row = rows.iter().max_by_key(|r| r.seq).expect("head row");
    let head_seq = head_row.seq;
    let head_hash = head_row.entry_hash.clone();

    // Lineage of auth.login is derived only from its real ledgered events (seqs
    // 0, 1, 3) — no invented edges, ordered by seq, each node hash-pointed.
    let login_rows: Vec<LedgerScanRow> = rows
        .iter()
        .filter(|r| r.subject == AUTH_LOGIN)
        .cloned()
        .collect();
    let lineage = build_symbol_lineage(AUTH_LOGIN, &login_rows).expect("login lineage");
    let seqs: Vec<u64> = lineage.versions.iter().map(|e| e.ledger.seq).collect();
    assert_eq!(
        seqs,
        vec![0, 1, 3],
        "auth.login ledgered at real global seqs"
    );
    let kinds: Vec<&str> = lineage.versions.iter().map(|e| e.kind.as_str()).collect();
    assert_eq!(kinds, vec!["ingest", "measure", "guard"]);
    for event in &lineage.versions {
        // Every node's hash equals the real persisted entry hash for that seq.
        let expected = login_rows
            .iter()
            .find(|r| r.seq == event.ledger.seq)
            .expect("row for node");
        assert_eq!(event.ledger.chain_hash, expected.entry_hash);
        assert_eq!(event.ledger.chain_hash.len(), 64, "blake3 entry hash hex");
    }

    // Drive the labeled envelope and FSV the served artifact from disk.
    let store = store_from_rows(&rows, head_seq, &head_hash);
    let response = get_provenance(&store, &ProvenanceQuery::new("lineage", Some(AUTH_LOGIN)))
        .expect("lineage response");
    assert_eq!(response.schema, GET_PROVENANCE_SCHEMA);
    assert_eq!(response.trust, "verified");
    assert_eq!(response.freshness, Freshness::fresh(head_seq));
    let ProvenancePayload::Lineage(payload) = &response.payload else {
        panic!("expected lineage payload");
    };
    assert_eq!(payload.versions.len(), 3);

    let bytes = provenance_response_artifact_bytes(&response);
    let artifact = root.join("lineage-response.txt");
    std::fs::write(&artifact, &bytes).expect("write response artifact");
    let text = String::from_utf8(std::fs::read(&artifact).expect("read artifact")).expect("utf8");
    assert!(
        text.contains("lineage\tsymbol:auth.login\t3"),
        "text: {text}"
    );
    assert!(text.contains("trust=verified"), "text: {text}");

    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn edge_case_triad_prints_before_and_after() {
    println!("=== get_provenance edge-case triad (real persisted ledger) ===");

    // --- (1) Empty ledger: no persisted row references the subject. ---
    let empty_root = scratch_dir("empty");
    let empty_store = DirectoryLedgerStore::open(&empty_root).expect("open empty store");
    let empty_verify = verify_chain(&empty_store, 0..0).expect("verify empty");
    println!("[empty] before: 0 persisted ledger rows; verify_chain(0..0) => {empty_verify:?}");
    let empty_err = build_symbol_lineage(AUTH_LOGIN, &[]).expect_err("empty lineage refused");
    println!(
        "[empty] after:  build_symbol_lineage({AUTH_LOGIN}) => REFUSED {} :: {}",
        empty_err.code(),
        empty_err.message()
    );
    assert_eq!(empty_err.code(), ASTRO_PROVENANCE_LINEAGE_EMPTY);
    assert!(matches!(empty_verify, VerifyResult::Intact { count: 0 }));
    std::fs::remove_dir_all(&empty_root).ok();

    // --- (2) Tampered chain row: flip one byte in a persisted ledger row. ---
    let tamper_root = scratch_dir("tamper");
    let count = seed_real_ledger(&tamper_root);
    let before_store = DirectoryLedgerStore::open(&tamper_root).expect("reopen before tamper");
    let before = verify_chain(&before_store, 0..count).expect("verify before tamper");
    println!("[tamper] before: verify_chain(0..{count}) => {before:?}");
    assert!(matches!(before, VerifyResult::Intact { .. }));

    // Byte-level tamper of the persisted row file for seq 1.
    let row_path = tamper_root.join(format!("{:016x}.ledger", 1u64));
    let mut row_bytes = std::fs::read(&row_path).expect("read persisted row for tamper");
    assert!(row_bytes.len() > 16, "row long enough to tamper");
    row_bytes[16] ^= 0xff;
    std::fs::write(&row_path, &row_bytes).expect("write tampered row");

    let after_store = DirectoryLedgerStore::open(&tamper_root).expect("reopen after tamper");
    let after = verify_chain(&after_store, 0..count).expect("verify after tamper");
    println!("[tamper] after:  verify_chain(0..{count}) => {after:?}");
    let (status, at_seq) = match &after {
        VerifyResult::Broken { at_seq, .. } => (ChainStatus::Broken { seq: *at_seq }, *at_seq),
        VerifyResult::Corrupt { at_seq, reason } => (
            ChainStatus::Corrupt {
                seq: *at_seq,
                reason: reason.clone(),
            },
            *at_seq,
        ),
        VerifyResult::Intact { .. } => panic!("tampered chain must not verify intact"),
    };
    assert_eq!(at_seq, 1, "tamper detected at the tampered seq");

    // The tampered chain must never ride a verified envelope. verify_chain mode
    // reads only the chain + head, so a chain-only store suffices here.
    let head = LedgerPointer::new(count - 1, "real-head");
    let tamper_prov = ProvenanceStore {
        vault_fingerprint: "real-ledger-vault".to_string(),
        ledger_head: head,
        chain: ChainVerification {
            status,
            checked_from: 0,
            checked_end: count,
            provenance: LedgerPointer::new(at_seq, "tampered"),
        },
        symbols: BTreeMap::new(),
        answers: BTreeMap::new(),
        reproductions: BTreeMap::new(),
        manifests: BTreeMap::new(),
    };
    let response =
        get_provenance(&tamper_prov, &ProvenanceQuery::new("verify_chain", None)).expect("verify");
    println!("[tamper] envelope trust => {}", response.trust);
    assert_ne!(response.trust, "verified", "tampered chain never verified");
    assert!(response.warnings.iter().any(|w| {
        w.code == PROVENANCE_WARN_CHAIN_BROKEN || w.code == PROVENANCE_WARN_CHAIN_CORRUPT
    }));
    std::fs::remove_dir_all(&tamper_root).ok();

    // --- (3) Nonexistent CxId: a symbol never ledgered. ---
    let missing_root = scratch_dir("missing");
    seed_real_ledger(&missing_root);
    let rows = scan_rows_from_disk(&missing_root);
    let store = store_from_rows(
        &rows,
        rows.iter().map(|r| r.seq).max().unwrap(),
        "real-head",
    );
    println!(
        "[missing] before: store holds subjects {:?}",
        store.symbols.keys().collect::<Vec<_>>()
    );
    let err = get_provenance(
        &store,
        &ProvenanceQuery::new("lineage", Some("symbol:does.not.exist")),
    )
    .expect_err("missing symbol refused");
    println!(
        "[missing] after:  get_provenance(lineage, symbol:does.not.exist) => REFUSED {} :: {}",
        err.code(),
        err.message()
    );
    assert_eq!(err.code(), ASTRO_PROVENANCE_NOT_FOUND);
    std::fs::remove_dir_all(&missing_root).ok();
}
