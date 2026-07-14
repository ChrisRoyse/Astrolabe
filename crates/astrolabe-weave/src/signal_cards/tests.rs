use super::*;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use astrolabe_ingest::{CbmGraphEdge, CbmGraphNode, CbmGraphSnapshot};
use calyx_aster::vault::encode::encode_slot_vector;
use calyx_aster::vault::{AsterVault, VaultOptions};
use calyx_core::{SystemClock, VaultId};

const SALT: &[u8] = b"astrolabe-weave-signal-cards-fsv";
const SEED: u64 = 11;
static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

fn vault_id() -> VaultId {
    "01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap()
}

fn cx(i: u64) -> CxId {
    CxId::from_input(&i.to_le_bytes(), 2, SALT)
}

fn durable_vault(name: &str) -> (PathBuf, AsterVault<SystemClock>) {
    let dir = std::env::temp_dir().join(format!(
        "astrolabe-weave-signalcards-{name}-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create signal-cards test vault dir");
    let vault = AsterVault::new_durable(&dir, vault_id(), SALT.to_vec(), VaultOptions::default())
        .expect("open durable vault");
    (dir, vault)
}

fn node(id: i64, cx_id: Option<CxId>, label: &str, structural: bool) -> CbmGraphNode {
    CbmGraphNode {
        source_node_id: id,
        project: "demo".to_string(),
        label: label.to_string(),
        name: format!("n{id}"),
        qualified_name: format!("demo::n{id}"),
        file_path: "src/lib.rs".to_string(),
        start_line: 1,
        end_line: 2,
        properties_json: "{}".to_string(),
        node_vector: None,
        cx_id,
        structural,
    }
}

fn edge(id: i64, src: Option<CxId>, dst: Option<CxId>) -> CbmGraphEdge {
    CbmGraphEdge {
        sqlite_edge_id: id,
        project: "demo".to_string(),
        source_node_id: 0,
        target_node_id: 0,
        src,
        dst,
        edge_type: "calls".to_string(),
        local_name_gen: String::new(),
        weight: 1.0,
        properties_json: "{}".to_string(),
    }
}

fn snapshot(nodes: Vec<CbmGraphNode>, edges: Vec<CbmGraphEdge>) -> CbmGraphSnapshot {
    CbmGraphSnapshot {
        project: "demo".to_string(),
        panel_version: Some(2),
        projects: Vec::new(),
        nodes,
        edges,
        file_hashes: Vec::new(),
        project_summaries: Vec::new(),
        token_vectors: Vec::new(),
    }
}

/// Writes one symbol's dense vector into the given slot CF.
fn write_slot(vault: &AsterVault<SystemClock>, slot: SlotId, cx_id: CxId, data: Vec<f32>) {
    let dim = data.len() as u32;
    let bytes = encode_slot_vector(&SlotVector::Dense { dim, data }).expect("encode slot vector");
    vault
        .write_cf(ColumnFamily::slot(slot), slot_key(cx_id), bytes)
        .expect("write slot vector");
}

#[test]
fn derive_symbol_axes_computes_kind_classes_and_degrees_from_the_snapshot() {
    let (a, b, c) = (cx(1), cx(2), cx(3));
    // A,B are "function" (class 0), C is "struct" (class 1) — sorted distinct
    // labels {function, struct} -> function=0, struct=1.
    let nodes = vec![
        node(1, Some(a), "function", false),
        node(2, Some(b), "function", false),
        node(3, Some(c), "struct", false),
        // Structural node and a cx-less node are not symbols.
        node(4, Some(cx(9)), "file", true),
        node(5, None, "function", false),
    ];
    // Edges: A-B, A-C, B-C -> degree A=2, B=2, C=2. Add A-A self-ish extra on A.
    let edges = vec![
        edge(1, Some(a), Some(b)),
        edge(2, Some(a), Some(c)),
        edge(3, Some(b), Some(c)),
        edge(4, Some(a), Some(cx(9))), // A gains +1 -> degree A=3
    ];
    let axes = derive_symbol_axes(&snapshot(nodes, edges));
    assert_eq!(axes.len(), 3, "three non-structural symbols with cx_ids");

    let by_cx: std::collections::BTreeMap<CxId, &SymbolAxes> =
        axes.iter().map(|s| (s.cx_id, s)).collect();
    assert_eq!(by_cx[&a].kind_class, 0, "function -> class 0");
    assert_eq!(by_cx[&b].kind_class, 0);
    assert_eq!(by_cx[&c].kind_class, 1, "struct -> class 1");
    // Degrees are hand-computable incident-edge counts.
    assert_eq!(by_cx[&a].degree, 3.0);
    assert_eq!(by_cx[&b].degree, 2.0);
    assert_eq!(by_cx[&c].degree, 2.0);
}

#[test]
fn signal_cards_rank_the_axis_predictive_slot_first() {
    // #379: real measured bits — the slot whose vectors ENCODE an axis carries
    // the most bits about it and ranks first; the aspect's cross-axis order is
    // hand-computable. S1 encodes symbol kind (parity), S3 encodes structural
    // degree, S2 is near-constant noise.
    let (dir, vault) = durable_vault("predictive-rank");
    let (s1, s2, s3) = (SlotId::new(1), SlotId::new(2), SlotId::new(3));

    let n = 80usize;
    let symbols: Vec<SymbolAxes> = (0..n)
        .map(|i| SymbolAxes {
            cx_id: cx(i as u64),
            kind_class: (i % 2) as i64, // parity: 2 classes
            degree: (i / 2) as f64,     // pairs share a degree -> hides parity
        })
        .collect();

    for (i, sym) in symbols.iter().enumerate() {
        // S1 clusters by parity (predicts kind, not degree).
        write_slot(
            &vault,
            s1,
            sym.cx_id,
            vec![(i % 2) as f32 * 100.0 + (i as f32) * 1e-6],
        );
        // S2 near-constant noise independent of both axes.
        write_slot(&vault, s2, sym.cx_id, vec![((i * 13) % 7) as f32 * 1e-3]);
        // S3 tracks degree (predicts degree, not parity).
        write_slot(
            &vault,
            s3,
            sym.cx_id,
            vec![(i / 2) as f32 + (i as f32) * 1e-6],
        );
    }

    let production = signal_cards_from_symbol_axes(&vault, &symbols, &[s1, s2, s3], SEED)
        .expect("measure signal cards");
    assert_eq!(production.symbols_measured, n);
    assert_eq!(
        production.cards.len(),
        2,
        "both axes are informative: {production:?}"
    );

    let kind = production
        .cards
        .iter()
        .find(|c| c.axis == SIGNAL_AXIS_SYMBOL_KIND)
        .expect("symbol_kind card");
    assert_eq!(
        kind.signals[0].slot, "S1",
        "S1 encodes kind -> ranks first: {:?}",
        kind.signals
    );
    let s1_kind_bits = kind.signals[0].bits;
    for signal in &kind.signals[1..] {
        assert!(
            s1_kind_bits > signal.bits,
            "the kind-predictive slot must carry strictly more bits than {}: {:?}",
            signal.slot,
            kind.signals
        );
    }

    let degree = production
        .cards
        .iter()
        .find(|c| c.axis == SIGNAL_AXIS_STRUCTURAL_DEGREE)
        .expect("structural_degree card");
    assert_eq!(
        degree.signals[0].slot, "S3",
        "S3 encodes degree -> ranks first: {:?}",
        degree.signals
    );
    let s3_degree_bits = degree.signals[0].bits;
    for signal in &degree.signals[1..] {
        assert!(
            s3_degree_bits > signal.bits,
            "the degree-predictive slot must carry strictly more bits than {}: {:?}",
            signal.slot,
            degree.signals
        );
    }

    // The card serializes into the exact shape the aspect reader consumes:
    // card.axis + card.signals[].{slot,bits,trust}.
    let card_json = serde_json::to_value(kind).expect("card json");
    let first = &card_json["signals"][0];
    assert_eq!(first["slot"].as_str(), Some("S1"));
    assert!(first["bits"].as_f64().is_some());
    assert!(
        first["trust"].as_str().is_some(),
        "trust serializes as a string"
    );

    drop(vault);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn no_dense_vectors_yields_no_cards_a_genuine_labeled_absence() {
    // Symbols exist but no slot vectors are persisted -> every slot is a labeled
    // no-dense skip, no card is produced, so the server persists nothing and the
    // aspect stays labeled-unavailable (genuinely absent, not faked).
    let (dir, vault) = durable_vault("absent");
    let symbols: Vec<SymbolAxes> = (0..4)
        .map(|i| SymbolAxes {
            cx_id: cx(i as u64),
            kind_class: (i % 2) as i64,
            degree: i as f64,
        })
        .collect();
    let production =
        signal_cards_from_symbol_axes(&vault, &symbols, &[SlotId::new(1), SlotId::new(4)], SEED)
            .expect("measure signal cards");
    assert!(
        production.cards.is_empty(),
        "no dense vectors -> no cards: {production:?}"
    );
    assert_eq!(production.slots_skipped_no_dense, 2, "{production:?}");

    drop(vault);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn constant_axes_are_labeled_degenerate_absences() {
    // Both axes constant across the sample -> neither carries information, so no
    // card is produced even though the slot has dense vectors.
    let (dir, vault) = durable_vault("degenerate");
    let s1 = SlotId::new(1);
    let symbols: Vec<SymbolAxes> = (0..10)
        .map(|i| SymbolAxes {
            cx_id: cx(i as u64),
            kind_class: 0, // constant kind
            degree: 5.0,   // constant degree
        })
        .collect();
    for (i, sym) in symbols.iter().enumerate() {
        write_slot(&vault, s1, sym.cx_id, vec![i as f32]);
    }
    let production =
        signal_cards_from_symbol_axes(&vault, &symbols, &[s1], SEED).expect("measure signal cards");
    assert!(
        production.cards.is_empty(),
        "constant axes -> no cards: {production:?}"
    );
    assert_eq!(production.axes_skipped_degenerate, 2, "{production:?}");
    assert_eq!(
        production.slots_skipped_no_dense, 0,
        "the slot had dense vectors"
    );

    drop(vault);
    let _ = std::fs::remove_dir_all(&dir);
}
