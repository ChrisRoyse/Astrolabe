//! Full State Verification for the S23 `layer_role` frozen lens (#310, DoD FSV1).
//!
//! Every assertion here reads persisted bytes back off a real filesystem store: the
//! encoder produces a posterior, it is serialized to the guard-raw byte envelope, the
//! bytes are written to a real `slot_23_*.raw` file, and an *independent* readback
//! decodes them and compares against hand-computed expectations. A return value alone
//! is never the evidence — the on-disk bytes are.

#![cfg(test)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use calyx_core::{SlotId, SlotVector};

use crate::lenses::{
    ApiCall, EncoderLensInput, GraphPositionInput, RoleFlagsInput, RouteObservation,
    RouteSurfaceInput,
};
use crate::{LayerRole, decode_slot_raw, encode_slot, slot_raw_bytes};

const S23: SlotId = SlotId::new(23);

/// A unique real scratch directory under the OS temp root for one FSV run.
fn scratch_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "astro_s23_fsv_{tag}_{nanos}_{:?}",
        std::thread::current().id()
    ));
    fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// A pure test symbol: only the `is_test` role flag ⇒ one-hot `test`.
fn test_symbol() -> EncoderLensInput {
    EncoderLensInput {
        role_flags: Some(RoleFlagsInput {
            is_test: true,
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// A route handler: route+handler flags plus a route surface ⇒ one-hot `transport_api`.
fn transport_symbol() -> EncoderLensInput {
    EncoderLensInput {
        role_flags: Some(RoleFlagsInput {
            is_route: true,
            is_handler: true,
            ..Default::default()
        }),
        route_surface: Some(RouteSurfaceInput {
            routes: vec![RouteObservation {
                method: "GET".to_string(),
                path: "/health".to_string(),
            }],
            channels: vec![],
        }),
        ..Default::default()
    }
}

/// A persistence symbol: one resolved store callee ⇒ one-hot `persistence`.
fn persistence_symbol() -> EncoderLensInput {
    EncoderLensInput {
        api_calls: Some(vec![ApiCall {
            callee: "db::execute_query".to_string(),
            call_count: 3.0,
            resolved: true,
        }]),
        ..Default::default()
    }
}

/// A service symbol: only inbound+outbound graph edges and betweenness ⇒ one-hot
/// `service_domain`.
fn service_symbol() -> EncoderLensInput {
    EncoderLensInput {
        graph_position: Some(GraphPositionInput {
            call_in: 5.0,
            call_out: 4.0,
            dataflow_in: 2.0,
            dataflow_out: 3.0,
            type_in: 0.0,
            type_out: 0.0,
            service_in: 1.0,
            service_out: 1.0,
            sampled_betweenness: 0.8,
            pagerank: 0.1,
            clustering_coeff: 0.2,
            neighbor_label_entropy: 0.5,
        }),
        ..Default::default()
    }
}

/// The frozen 4-symbol fixture, keyed by a stable per-symbol name.
fn fixture() -> Vec<(&'static str, EncoderLensInput)> {
    vec![
        ("test", test_symbol()),
        ("transport", transport_symbol()),
        ("persistence", persistence_symbol()),
        ("service", service_symbol()),
    ]
}

/// Encodes S23 for a symbol and writes its guard-raw posterior to `dir/slot_23_<name>.raw`.
fn persist_symbol(dir: &Path, name: &str, input: &EncoderLensInput) -> Vec<u8> {
    let vector = encode_slot(S23, input).expect("encode S23");
    let bytes = slot_raw_bytes(&vector).expect("serialize guard-raw posterior");
    fs::write(dir.join(format!("slot_23_{name}.raw")), &bytes).expect("persist raw sidecar");
    bytes
}

/// Persists the whole fixture into `dir`, returning name → persisted bytes.
fn persist_fixture(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    fixture()
        .into_iter()
        .map(|(name, input)| (name.to_string(), persist_symbol(dir, name, &input)))
        .collect()
}

/// Reads a persisted sidecar back off disk and decodes it independently.
fn readback(dir: &Path, name: &str) -> SlotVector {
    let bytes = fs::read(dir.join(format!("slot_23_{name}.raw"))).expect("read raw sidecar");
    decode_slot_raw(&bytes).expect("decode guard-raw posterior")
}

/// Extracts the dense posterior, asserting the frozen Dense(8) shape.
fn dense(vector: &SlotVector) -> Vec<f32> {
    match vector {
        SlotVector::Dense { dim, data } => {
            assert_eq!(*dim, 8, "S23 posterior must be Dense(8)");
            assert_eq!(data.len(), 8, "S23 posterior must carry 8 coordinates");
            data.clone()
        }
        other => panic!("S23 posterior must be dense, got {other:?}"),
    }
}

/// The one-hot posterior a single-role symbol must produce.
fn one_hot(role: LayerRole) -> [f32; 8] {
    let mut out = [0.0_f32; 8];
    out[role.index()] = 1.0;
    out
}

#[test]
fn fsv1_persisted_posteriors_match_hand_computed_roles() {
    let dir = scratch_dir("posterior");
    persist_fixture(&dir);

    // Independent readback: decode the bytes actually on disk and compare to the
    // hand-computed one-hot posteriors (each symbol carries single-role evidence, so
    // L1 normalization pins the whole mass onto that role's frozen coordinate).
    let expected = [
        ("test", LayerRole::Test),
        ("transport", LayerRole::TransportApi),
        ("persistence", LayerRole::Persistence),
        ("service", LayerRole::ServiceDomain),
    ];
    for (name, role) in expected {
        let vector = readback(&dir, name);
        let data = dense(&vector);
        assert_eq!(
            data,
            one_hot(role).to_vec(),
            "persisted {name} posterior must be one-hot {role:?}"
        );
        let mass: f32 = data.iter().sum();
        assert!(
            (mass - 1.0).abs() < 1e-6,
            "{name} posterior must be an L1 distribution"
        );
    }

    // Byte-exact readback of one symbol: `b"D" | dim=8 be | 8×f32be`, with 1.0 at the
    // frozen `test` index (5) and 0.0 elsewhere.
    let raw = fs::read(dir.join("slot_23_test.raw")).expect("read test sidecar");
    let mut expected_bytes = vec![b'D'];
    expected_bytes.extend_from_slice(&8_u32.to_be_bytes());
    for i in 0..8 {
        let value: f32 = if i == LayerRole::Test.index() {
            1.0
        } else {
            0.0
        };
        expected_bytes.extend_from_slice(&value.to_bits().to_be_bytes());
    }
    assert_eq!(raw, expected_bytes, "guard-raw byte envelope must be exact");

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn fsv1_two_ingests_are_byte_identical() {
    let dir_a = scratch_dir("ingest_a");
    let dir_b = scratch_dir("ingest_b");
    let a = persist_fixture(&dir_a);
    let b = persist_fixture(&dir_b);
    assert_eq!(
        a, b,
        "two independent ingests must persist byte-identical posteriors"
    );

    // Prove it against the real files, not just the in-memory return.
    for name in ["test", "transport", "persistence", "service"] {
        let ra = fs::read(dir_a.join(format!("slot_23_{name}.raw"))).unwrap();
        let rb = fs::read(dir_b.join(format!("slot_23_{name}.raw"))).unwrap();
        assert_eq!(ra, rb, "{name} sidecar bytes must match across ingests");
    }
    fs::remove_dir_all(&dir_a).ok();
    fs::remove_dir_all(&dir_b).ok();
}

#[test]
fn fsv1_worker_count_invariant() {
    // Sequential ingest.
    let sequential: BTreeMap<String, Vec<u8>> = fixture()
        .into_iter()
        .map(|(name, input)| {
            let vector = encode_slot(S23, &input).expect("encode");
            (
                name.to_string(),
                slot_raw_bytes(&vector).expect("serialize"),
            )
        })
        .collect();

    // Parallel ingest across one worker per symbol; a pure per-symbol encoder must be
    // invariant to worker count and scheduling order.
    let parallel: BTreeMap<String, Vec<u8>> = std::thread::scope(|scope| {
        let handles: Vec<_> = fixture()
            .into_iter()
            .map(|(name, input)| {
                scope.spawn(move || {
                    let vector = encode_slot(S23, &input).expect("encode");
                    (
                        name.to_string(),
                        slot_raw_bytes(&vector).expect("serialize"),
                    )
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("join"))
            .collect()
    });

    assert_eq!(
        sequential, parallel,
        "S23 posteriors must be worker-count invariant"
    );
}

#[test]
fn fsv1_edge_empty_input_is_labeled_absence() {
    // Empty: a symbol with no behavioral surface is a labeled absence, and the
    // guard-raw serializer fails closed rather than persisting a placeholder.
    let vector = encode_slot(S23, &EncoderLensInput::default()).expect("encode empty");
    assert!(
        matches!(vector, SlotVector::Absent { .. }),
        "empty input ⇒ Absent"
    );
    let err = slot_raw_bytes(&vector).expect_err("absent must not serialize to a raw sidecar");
    assert_eq!(err.code(), crate::ASTRO_PANEL_VECTOR_INVALID);
}

#[test]
fn fsv1_edge_boundary_zero_call_count() {
    // Boundary: a single resolved store callee at the lower call-count boundary (0)
    // still yields a valid one-hot `persistence` posterior (weight 1 + ln1p(0) = 1).
    let dir = scratch_dir("boundary");
    let input = EncoderLensInput {
        api_calls: Some(vec![ApiCall {
            callee: "repository::fetch_one".to_string(),
            call_count: 0.0,
            resolved: true,
        }]),
        ..Default::default()
    };
    persist_symbol(&dir, "boundary", &input);
    let data = dense(&readback(&dir, "boundary"));
    assert_eq!(data, one_hot(LayerRole::Persistence).to_vec());
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn fsv1_edge_invalid_non_finite_and_negative_fail_closed() {
    // Invalid #1: a non-finite graph signal fails closed.
    let mut gp = service_symbol();
    if let Some(g) = gp.graph_position.as_mut() {
        g.sampled_betweenness = f32::NAN;
    }
    let err = encode_slot(S23, &gp).expect_err("NaN graph signal must fail closed");
    assert_eq!(err.code(), astrolabe_domain::ASTRO_SYMBOL_NON_FINITE);

    // Invalid #2: a negative degree fails closed.
    let mut neg = service_symbol();
    if let Some(g) = neg.graph_position.as_mut() {
        g.call_in = -1.0;
    }
    let err = encode_slot(S23, &neg).expect_err("negative graph degree must fail closed");
    assert_eq!(err.code(), crate::ASTRO_PANEL_VECTOR_INVALID);
}

// ---------------------------------------------------------------------------
// DoD1: S23 slot registered with a FrozenLensContract + lens_id + the
// applicability-matrix rows.
// ---------------------------------------------------------------------------

#[test]
fn dod1_s23_slot_registered_in_v2_roster() {
    use crate::{
        S23_LAYER_ROLE_SLOT, SlotShape, default_panel_slots, default_panel_v2_slots, slot_spec,
    };

    // The v2 roster is the v1 roster plus exactly S23.
    let v1 = default_panel_slots();
    let v2 = default_panel_v2_slots();
    assert_eq!(v2.len(), v1.len() + 1, "v2 roster adds exactly one slot");
    assert!(
        v1.iter().all(|s| s.slot != 23),
        "S23 is not in the v1 roster"
    );
    assert!(v2.iter().any(|s| s.slot == 23), "S23 is in the v2 roster");

    // The slot resolves with its frozen spec: guard-raw Dense(8), L1 norm.
    let spec = slot_spec(SlotId::new(23)).expect("S23 resolves in the roster");
    assert_eq!(spec.key, "layer_role");
    assert!(
        spec.is_guard_raw(),
        "S23 is guard-designated (persisted raw)"
    );
    assert!(matches!(spec.shape, SlotShape::Dense(8)));
    assert_eq!(spec.slot, S23_LAYER_ROLE_SLOT.slot);
}

#[test]
fn dod1_s23_frozen_contract_and_lens_id_bind_the_real_encoder() {
    use crate::{FrozenLensContract, PANEL_V1_SLOTS, S23_LAYER_ROLE_SLOT};

    // The contract binds the real encoder output on the frozen probe fixture.
    let contract = FrozenLensContract::for_slot(&S23_LAYER_ROLE_SLOT).expect("S23 contract binds");
    assert_eq!(contract.name, "layer_role");

    // The content-addressed lens id is deterministic and distinct from every v1 slot's.
    let lens_id = contract.lens_id();
    assert_eq!(lens_id, contract.lens_id(), "lens id is deterministic");
    for slot in PANEL_V1_SLOTS {
        let other = FrozenLensContract::for_slot(slot).expect("v1 contract");
        assert_ne!(
            lens_id,
            other.lens_id(),
            "S23 lens id differs from {}",
            slot.key
        );
    }
}

#[test]
fn dod1_s23_applicability_matrix_rows() {
    use crate::applicable_slot_ids_versioned;
    use astrolabe_domain::SymbolLabel;

    // Applies to behavioral classes: Callable, TypeDeclaration, ModuleFile, RouteChannel.
    for label in [
        SymbolLabel::Function,
        SymbolLabel::Method,
        SymbolLabel::Macro,
        SymbolLabel::Class,
        SymbolLabel::Type,
        SymbolLabel::Module,
        SymbolLabel::File,
        SymbolLabel::Route,
        SymbolLabel::Channel,
    ] {
        assert!(
            applicable_slot_ids_versioned(label, crate::PANEL_V2_VERSION).contains(&S23),
            "S23 applies to {label:?}"
        );
    }

    // Not applicable to value / structural classes ⇒ Absent{NotApplicable}.
    for label in [
        SymbolLabel::Field,
        SymbolLabel::Constant,
        SymbolLabel::Property,
    ] {
        assert!(
            !applicable_slot_ids_versioned(label, crate::PANEL_V2_VERSION).contains(&S23),
            "S23 does not apply to {label:?}"
        );
    }

    // Under the v1 roster, S23 is never applicable (roster gating).
    assert!(
        !applicable_slot_ids_versioned(SymbolLabel::Function, crate::DEFAULT_PANEL_VERSION)
            .contains(&S23),
        "S23 is not applicable under the v1 roster"
    );
}

// ---------------------------------------------------------------------------
// DoD3: the panel-version bump astro.panel.v1 → .v2 is ledgerable with a
// re-derivation cost.
// ---------------------------------------------------------------------------

#[test]
fn dod3_version_bump_is_ledgerable_with_rederivation_cost() {
    use crate::{
        FrozenLensContract, PANEL_SCHEMA_ID, PANEL_SCHEMA_ID_V2, PANEL_V2_VERSION,
        S23_LAYER_ROLE_SLOT, plan_panel_version_bump_v1_to_v2,
    };

    let bump = plan_panel_version_bump_v1_to_v2().expect("plan v1→v2 bump");
    assert_eq!(bump.from_schema_id, PANEL_SCHEMA_ID);
    assert_eq!(bump.to_schema_id, PANEL_SCHEMA_ID_V2);
    assert_eq!(bump.from_version, crate::DEFAULT_PANEL_VERSION);
    assert_eq!(bump.to_version, PANEL_V2_VERSION);
    assert_eq!(bump.added_slot, S23);
    assert_eq!(bump.added_slot_key, "layer_role");

    // The recorded lens id is the real S23 frozen contract id.
    let contract = FrozenLensContract::for_slot(&S23_LAYER_ROLE_SLOT).unwrap();
    assert_eq!(bump.added_lens_id, contract.lens_id());

    // Re-derivation cost: S23 joins constellation identity, so dedup + assay must recompute.
    assert!(bump.rederivation.added_to_identity);
    assert!(bump.rederivation.dedup_reindex_required);
    assert!(bump.rederivation.assay_recompute_required);
    let classes = &bump.rederivation.affected_label_classes;
    for expected in [
        "callable",
        "type_declaration",
        "module_file",
        "route_channel",
    ] {
        assert!(
            classes.iter().any(|c| c == expected),
            "affected class {expected}"
        );
    }

    // Ledgerable: serialize the bump to a real file and read it back byte-stable.
    let dir = scratch_dir("version_bump");
    let bytes = serde_json::to_vec(&bump).expect("serialize bump");
    let path = dir.join("panel_v1_to_v2_bump.json");
    fs::write(&path, &bytes).expect("persist bump ledger record");
    let read = fs::read(&path).expect("read bump ledger record");
    let restored: crate::PanelVersionBump =
        serde_json::from_slice(&read).expect("parse persisted bump");
    assert_eq!(restored, bump, "persisted version-bump record round-trips");
    fs::remove_dir_all(&dir).ok();
}
