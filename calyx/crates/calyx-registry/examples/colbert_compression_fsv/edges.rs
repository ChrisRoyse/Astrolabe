use std::error::Error;
use std::path::Path;

use calyx_aster::cf::ColumnFamily;
use calyx_aster::vault::AsterVault;
use calyx_core::{CxId, LensId, QuantPolicy, Slot, SlotShape, SystemClock};
use calyx_registry::{
    MultiVectorCompressionConfig, MultiVectorCompressionQuery, MultiVectorCompressionRow,
    PackedMaxSimScratch, Registry, parse_packed_multivector_manifest, parse_packed_multivector_row,
    validate_quant_policy_for_shape,
};
use serde_json::json;
use sha2::{Digest, Sha256};

use super::state::{VaultState, read_state};

type AnyResult<T> = Result<T, Box<dyn Error>>;

const ROW_DOMAIN: &[u8] = b"calyx-colbert-residual-row-v1";

pub fn run_edges(
    registry: &Registry,
    vault: &AsterVault<SystemClock>,
    vault_dir: &Path,
    slot: &Slot,
    rows: &[MultiVectorCompressionRow],
    queries: &[MultiVectorCompressionQuery],
    config: MultiVectorCompressionConfig,
) -> AnyResult<()> {
    empty_document_edge(registry, vault, vault_dir, slot, rows, queries, config)?;
    empty_query_edge(registry, vault, vault_dir, slot)?;
    token_bound_edges(registry, vault, vault_dir, slot, queries, config)?;
    dimension_bound_edge(registry, vault, vault_dir, slot, rows, queries, config)?;
    malformed_row_edges(vault, vault_dir, slot)?;
    wrong_context_edge(registry, vault, vault_dir, slot)?;
    legacy_row_edge(vault, vault_dir, slot)?;
    catalog_pairing_edge(registry, vault, vault_dir, slot)?;
    Ok(())
}

fn empty_document_edge(
    registry: &Registry,
    vault: &AsterVault<SystemClock>,
    vault_dir: &Path,
    slot: &Slot,
    rows: &[MultiVectorCompressionRow],
    queries: &[MultiVectorCompressionQuery],
    config: MultiVectorCompressionConfig,
) -> AnyResult<()> {
    let mut invalid_rows = rows.to_vec();
    invalid_rows[0].tokens.clear();
    let before = edge_before("empty_document", vault, vault_dir, slot)?;
    let error = require_error(
        registry.write_packed_multivector_generation(
            vault,
            slot,
            &invalid_rows,
            queries,
            config,
            1,
        ),
        "empty document token matrix was accepted",
    )?;
    require(
        error.code == "CALYX_MULTIVECTOR_PACK_INVALID"
            && error.message.contains("document token matrix is empty"),
        format!("unexpected empty-document diagnostic: {error:?}"),
    )?;
    edge_after("empty_document", vault, vault_dir, slot, &before, &error)
}

fn empty_query_edge(
    registry: &Registry,
    vault: &AsterVault<SystemClock>,
    vault_dir: &Path,
    slot: &Slot,
) -> AnyResult<()> {
    let before = edge_before("empty_query", vault, vault_dir, slot)?;
    let index = registry.packed_multivector_index(vault, slot)?;
    let query = MultiVectorCompressionQuery {
        cx_id: CxId::from_bytes([0xE1; 16]),
        tokens: Vec::new(),
    };
    let mut scratch = PackedMaxSimScratch::default();
    let error = require_error(
        index.search(&query, 1, &mut scratch),
        "empty query token matrix was accepted",
    )?;
    require(
        error.code == "CALYX_MULTIVECTOR_PACK_INVALID"
            && error.message.contains("query token matrix is empty"),
        format!("unexpected empty-query diagnostic: {error:?}"),
    )?;
    drop(index);
    edge_after("empty_query", vault, vault_dir, slot, &before, &error)
}

fn token_bound_edges(
    registry: &Registry,
    vault: &AsterVault<SystemClock>,
    vault_dir: &Path,
    slot: &Slot,
    queries: &[MultiVectorCompressionQuery],
    config: MultiVectorCompressionConfig,
) -> AnyResult<()> {
    let max_query = queries
        .iter()
        .find(|query| query.tokens.len() == config.max_tokens as usize)
        .ok_or("real corpus did not exercise the declared maximum token count")?;
    let before_valid = edge_before("max_tokens_valid", vault, vault_dir, slot)?;
    let index = registry.packed_multivector_index(vault, slot)?;
    let mut scratch = PackedMaxSimScratch::default();
    let hits = index.search(max_query, 1, &mut scratch)?;
    require(hits.len() == 1, "maximum-token query returned no top hit")?;
    drop(index);
    let after_valid = read_state(vault, vault_dir, slot)?;
    require(
        before_valid == after_valid,
        "maximum-token read changed durable state",
    )?;
    println!(
        "{}",
        json!({
            "event": "edge_max_tokens_valid_after",
            "before": before_valid,
            "after": after_valid,
            "tokens": config.max_tokens,
            "top_hit": hits[0],
            "mutation": false,
        })
    );

    let before_over = edge_before("max_tokens_exceeded", vault, vault_dir, slot)?;
    let count = usize::try_from(config.max_tokens)?
        .checked_add(1)
        .ok_or("over-limit token count overflow")?;
    let over_query = MultiVectorCompressionQuery {
        cx_id: CxId::from_bytes([0xE2; 16]),
        tokens: vec![queries[0].tokens[0].clone(); count],
    };
    let index = registry.packed_multivector_index(vault, slot)?;
    let error = require_error(
        index.search(&over_query, 1, &mut scratch),
        "over-limit query token count was accepted",
    )?;
    require(
        error.code == "CALYX_MULTIVECTOR_PACK_INVALID"
            && error.message.contains("exceeds max_tokens"),
        format!("unexpected max-token diagnostic: {error:?}"),
    )?;
    drop(index);
    edge_after(
        "max_tokens_exceeded",
        vault,
        vault_dir,
        slot,
        &before_over,
        &error,
    )
}

fn dimension_bound_edge(
    registry: &Registry,
    vault: &AsterVault<SystemClock>,
    vault_dir: &Path,
    slot: &Slot,
    rows: &[MultiVectorCompressionRow],
    queries: &[MultiVectorCompressionQuery],
    mut config: MultiVectorCompressionConfig,
) -> AnyResult<()> {
    let before = edge_before("max_dimension_exceeded", vault, vault_dir, slot)?;
    config.max_token_dim = config
        .max_token_dim
        .checked_sub(4)
        .ok_or("real token dimension is too small for boundary audit")?;
    let error = require_error(
        registry.write_packed_multivector_generation(vault, slot, rows, queries, config, 1),
        "token dimension beyond declared maximum was accepted",
    )?;
    require(
        error.code == "CALYX_MULTIVECTOR_PACK_INVALID" && error.message.contains("max_token_dim"),
        format!("unexpected max-dimension diagnostic: {error:?}"),
    )?;
    edge_after(
        "max_dimension_exceeded",
        vault,
        vault_dir,
        slot,
        &before,
        &error,
    )
}

fn malformed_row_edges(
    vault: &AsterVault<SystemClock>,
    vault_dir: &Path,
    slot: &Slot,
) -> AnyResult<()> {
    let seq = vault.latest_seq();
    let manifest_bytes = vault
        .read_cf_at(
            seq,
            ColumnFamily::Compression,
            &calyx_aster::cf::compression_manifest_key(slot.slot_id),
        )?
        .ok_or("malformed-row edge found no manifest")?;
    let manifest = parse_packed_multivector_manifest(&manifest_bytes)?;
    let (key, stored) = vault
        .scan_cf_at(seq, ColumnFamily::slot(slot.slot_id))?
        .into_iter()
        .next()
        .ok_or("malformed-row edge found no primary row")?;
    let cx_id = CxId::from_bytes(key.as_slice().try_into()?);

    let before_offset = edge_before("malformed_offset", vault, vault_dir, slot)?;
    let mut bad_offset = stored.clone();
    let residual = u32::from_be_bytes(bad_offset[33..37].try_into()?) + 1;
    bad_offset[33..37].copy_from_slice(&residual.to_be_bytes());
    rewrite_digest(&mut bad_offset, ROW_DOMAIN)?;
    let offset_error = require_error(
        parse_packed_multivector_row(&bad_offset, &manifest, cx_id),
        "row with malformed residual offset was accepted",
    )?;
    require(
        offset_error
            .message
            .contains("offsets/counts are non-canonical"),
        format!("unexpected malformed-offset diagnostic: {offset_error:?}"),
    )?;
    edge_after(
        "malformed_offset",
        vault,
        vault_dir,
        slot,
        &before_offset,
        &offset_error,
    )?;

    let before_checksum = edge_before("malformed_checksum", vault, vault_dir, slot)?;
    let mut bad_checksum = stored;
    let last = bad_checksum.len() - 1;
    bad_checksum[last] ^= 0x01;
    let checksum_error = require_error(
        parse_packed_multivector_row(&bad_checksum, &manifest, cx_id),
        "row with malformed checksum was accepted",
    )?;
    require(
        checksum_error.message.contains("checksum mismatch"),
        format!("unexpected malformed-checksum diagnostic: {checksum_error:?}"),
    )?;
    edge_after(
        "malformed_checksum",
        vault,
        vault_dir,
        slot,
        &before_checksum,
        &checksum_error,
    )
}

fn wrong_context_edge(
    registry: &Registry,
    vault: &AsterVault<SystemClock>,
    vault_dir: &Path,
    slot: &Slot,
) -> AnyResult<()> {
    let before = edge_before("wrong_lens_context", vault, vault_dir, slot)?;
    let mut wrong = slot.clone();
    wrong.lens_id = LensId::from_bytes([0xEC; 16]);
    let error = require_error(
        registry.packed_multivector_index(vault, &wrong),
        "wrong lens context opened the generation",
    )?;
    require(
        error.code == "CALYX_LENS_UNREACHABLE" || error.code == "CALYX_LENS_FROZEN_VIOLATION",
        format!("unexpected wrong-context diagnostic: {error:?}"),
    )?;
    edge_after(
        "wrong_lens_context",
        vault,
        vault_dir,
        slot,
        &before,
        &error,
    )
}

fn legacy_row_edge(
    vault: &AsterVault<SystemClock>,
    vault_dir: &Path,
    slot: &Slot,
) -> AnyResult<()> {
    let before = edge_before("legacy_raw_row", vault, vault_dir, slot)?;
    let seq = vault.latest_seq();
    let manifest_bytes = vault
        .read_cf_at(
            seq,
            ColumnFamily::Compression,
            &calyx_aster::cf::compression_manifest_key(slot.slot_id),
        )?
        .ok_or("legacy edge found no manifest")?;
    let manifest = parse_packed_multivector_manifest(&manifest_bytes)?;
    let (key, raw) = vault
        .scan_cf_at(seq, ColumnFamily::slot_raw(slot.slot_id))?
        .into_iter()
        .next()
        .ok_or("legacy edge found no raw row")?;
    let cx_id = CxId::from_bytes(key.as_slice().try_into()?);
    let error = require_error(
        parse_packed_multivector_row(&raw, &manifest, cx_id),
        "legacy raw-F32 row was accepted as packed",
    )?;
    require(
        error
            .message
            .contains("legacy raw-F32/INT8 bytes are refused"),
        format!("unexpected legacy-row diagnostic: {error:?}"),
    )?;
    edge_after("legacy_raw_row", vault, vault_dir, slot, &before, &error)
}

fn catalog_pairing_edge(
    registry: &Registry,
    vault: &AsterVault<SystemClock>,
    vault_dir: &Path,
    slot: &Slot,
) -> AnyResult<()> {
    let before = edge_before("unsupported_catalog_pairing", vault, vault_dir, slot)?;
    let registry_before = registry.lens_snapshots();
    let error = require_error(
        validate_quant_policy_for_shape(
            "issue575-invalid-multi-dense-codec",
            slot.shape,
            QuantPolicy::TurboQuant {
                bits_per_channel_x2: 7,
            },
        ),
        "Multi shape accepted a dense TurboQuant policy",
    )?;
    require(
        error.code == "CALYX_LENS_QUANT_POLICY_SHAPE_MISMATCH"
            && registry.lens_snapshots() == registry_before,
        format!("catalog pairing refusal or registry state is wrong: {error:?}"),
    )?;
    let dense_error = require_error(
        validate_quant_policy_for_shape(
            "issue575-invalid-dense-colbert",
            SlotShape::Dense(96),
            QuantPolicy::ColbertResidual2Bit,
        ),
        "Dense shape accepted the ColBERT policy",
    )?;
    require(
        dense_error.code == "CALYX_LENS_QUANT_POLICY_SHAPE_MISMATCH",
        format!("unexpected dense/ColBERT diagnostic: {dense_error:?}"),
    )?;
    edge_after(
        "unsupported_catalog_pairing",
        vault,
        vault_dir,
        slot,
        &before,
        &error,
    )
}

fn edge_before(
    name: &str,
    vault: &AsterVault<SystemClock>,
    vault_dir: &Path,
    slot: &Slot,
) -> AnyResult<VaultState> {
    let state = read_state(vault, vault_dir, slot)?;
    println!(
        "{}",
        json!({ "event": format!("edge_{name}_before"), "state": state })
    );
    Ok(state)
}

fn edge_after(
    name: &str,
    vault: &AsterVault<SystemClock>,
    vault_dir: &Path,
    slot: &Slot,
    before: &VaultState,
    error: &calyx_core::CalyxError,
) -> AnyResult<()> {
    let after = read_state(vault, vault_dir, slot)?;
    require(
        &after == before,
        format!("edge {name} changed durable state"),
    )?;
    println!(
        "{}",
        json!({
            "event": format!("edge_{name}_after"),
            "before": before,
            "after": after,
            "error": {
                "code": error.code,
                "message": error.message,
                "remediation": error.remediation,
            },
            "mutation": false,
        })
    );
    Ok(())
}

fn rewrite_digest(bytes: &mut [u8], domain: &[u8]) -> AnyResult<()> {
    require(bytes.len() >= 32, "row is too short to rewrite checksum")?;
    let body = bytes.len() - 32;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(&bytes[..body]);
    bytes[body..].copy_from_slice(&hasher.finalize());
    Ok(())
}

fn require_error<T>(
    result: Result<T, calyx_core::CalyxError>,
    accepted_message: &str,
) -> AnyResult<calyx_core::CalyxError> {
    match result {
        Err(error) => Ok(error),
        Ok(_) => Err(accepted_message.to_string().into()),
    }
}

fn require(condition: bool, message: impl Into<String>) -> AnyResult<()> {
    if condition {
        Ok(())
    } else {
        Err(message.into().into())
    }
}
