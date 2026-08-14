use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use calyx_core::{CxId, SlotId, SlotVector};
use calyx_sextant::{HnswIndex, QuantConfig, SextantIndex};

const DIM: usize = 768;
const SLOT: u16 = 18;
const SEED: u64 = 0x4153_5452_4f4c_4142;
const POSITIVE_SCALAR8_LEVELS: f32 = 127.0;

fn fail(code: &str, message: impl AsRef<str>, remediation: &str) -> ! {
    eprintln!(
        "{}",
        serde_json::json!({
            "code": code,
            "message": message.as_ref(),
            "remediation": remediation,
        })
    );
    std::process::exit(1);
}

fn ordinal_id(ordinal: usize) -> CxId {
    let mut bytes = [0_u8; 16];
    bytes[8..].copy_from_slice(&(ordinal as u64).to_be_bytes());
    CxId::from_bytes(bytes)
}

fn main() {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.len() != 3 {
        fail(
            "ISSUE_441_ARGUMENT_CONTRACT",
            format!("expected 3 arguments, observed {}", args.len()),
            "pass <packed-i8-vector-file> <row-count> <fresh-artifact-path>",
        );
    }
    let input = PathBuf::from(&args[0]);
    let rows = args[1]
        .to_str()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or_else(|| {
            fail(
                "ISSUE_441_ROW_COUNT_INVALID",
                "row count is not a positive base-10 usize",
                "pass a positive row count no larger than the physical input cardinality",
            )
        });
    if rows == 0 {
        fail(
            "ISSUE_441_EMPTY_CORPUS",
            "row count must be positive",
            "supply at least one real 768-dimensional vector",
        );
    }
    let artifact = PathBuf::from(&args[2]);
    if artifact.exists() {
        fail(
            "ISSUE_441_ARTIFACT_ALREADY_EXISTS",
            format!("refusing to overwrite {}", artifact.display()),
            "pass a fresh artifact path and preserve the existing evidence bytes",
        );
    }

    let bytes = fs::read(&input).unwrap_or_else(|error| {
        fail(
            "ISSUE_441_INPUT_READ_FAILED",
            format!("cannot read {}: {error}", input.display()),
            "provide the independently exported physical node_vectors payload",
        )
    });
    if bytes.is_empty() || bytes.len() % DIM != 0 {
        fail(
            "ISSUE_441_VECTOR_SHAPE_INVALID",
            format!(
                "input has {} bytes; expected a nonzero multiple of {DIM}",
                bytes.len()
            ),
            "re-export whole 768-byte node_vectors rows without headers or separators",
        );
    }
    let available_rows = bytes.len() / DIM;
    if rows > available_rows {
        fail(
            "ISSUE_441_ROW_COUNT_EXCEEDS_INPUT",
            format!("requested {rows} rows but the input contains {available_rows}"),
            "lower the requested count or provide the complete physical vector payload",
        );
    }
    let selected = &bytes[..rows * DIM];
    let max_abs = selected
        .iter()
        .map(|byte| i16::from(*byte as i8).unsigned_abs() as f32)
        .fold(0.0_f32, f32::max);
    if max_abs == 0.0 {
        fail(
            "ISSUE_441_ZERO_VECTOR_CORPUS",
            "all selected packed coordinates are zero",
            "supply real non-collapsed semantic vectors",
        );
    }
    let scale = max_abs / POSITIVE_SCALAR8_LEVELS;
    let mut index = HnswIndex::new(SlotId::new(SLOT), DIM as u32, SEED)
        .with_quant(QuantConfig::scalar8(scale))
        .unwrap_or_else(|error| fail(error.code, error.message, error.remediation));
    let started = Instant::now();
    for (ordinal, packed) in selected.chunks_exact(DIM).enumerate() {
        let data = packed
            .iter()
            .map(|byte| f32::from(*byte as i8))
            .collect::<Vec<_>>();
        index
            .insert(
                ordinal_id(ordinal),
                SlotVector::Dense {
                    dim: DIM as u32,
                    data,
                },
                ordinal as u64,
            )
            .unwrap_or_else(|error| fail(error.code, error.message, error.remediation));
    }
    let build_elapsed_ms = started.elapsed().as_millis();
    let receipt = index
        .persist_artifact(&artifact)
        .unwrap_or_else(|error| fail(error.code, error.message, error.remediation));
    let neighbor_counts = index.neighbor_counts();
    let artifact_bytes = fs::read(&artifact).unwrap_or_else(|error| {
        fail(
            "ISSUE_441_ARTIFACT_READBACK_FAILED",
            format!("cannot re-read {}: {error}", artifact.display()),
            "preserve the artifact and inspect filesystem state before retrying",
        )
    });
    println!(
        "{}",
        serde_json::json!({
            "schema": "astrolabe.issue-441-hnsw-fsv.v1",
            "input": input,
            "input_selected_blake3": blake3::hash(selected).to_hex().to_string(),
            "rows": rows,
            "dimension": DIM,
            "scale_bits": scale.to_bits(),
            "build_elapsed_ms": build_elapsed_ms,
            "neighbor_count_min": neighbor_counts.iter().copied().min().unwrap_or(0),
            "neighbor_count_max": neighbor_counts.iter().copied().max().unwrap_or(0),
            "neighbor_count_sum": neighbor_counts.iter().sum::<usize>(),
            "artifact": artifact,
            "artifact_bytes": artifact_bytes.len(),
            "artifact_blake3": blake3::hash(&artifact_bytes).to_hex().to_string(),
            "receipt_digest": receipt.metadata.digest.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
            "physical_vector_bytes": index.physical_vector_bytes(),
        })
    );
}
