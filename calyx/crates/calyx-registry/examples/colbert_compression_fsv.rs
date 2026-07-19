//! Manual full-state operator for issue #575.
//!
//! This is not a test harness. It runs the real AnswerAI ColBERT ONNX model
//! over three real Astrolabe source files, persists a real Aster generation,
//! exercises every lifecycle transition and direct packed MaxSim, then reads
//! the database and wire bytes independently. A separate `--read-existing`
//! process proves the final source of truth without trusting writer returns.

#[path = "colbert_compression_fsv/edges.rs"]
mod edges;
#[path = "colbert_compression_fsv/model.rs"]
mod model;
#[path = "colbert_compression_fsv/state.rs"]
mod state;

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use calyx_registry::{
    MultiVectorCompressionConfig, MultiVectorCompressionQuery, MultiVectorCompressionReport,
    MultiVectorStorageCodec, PackedMaxSimScratch,
};
use serde_json::json;

use model::{
    AnyResult, MeasuredCorpus, Registered, ingest_real_corpus, measure_real_corpus, open_vault,
    register_real_colbert,
};
use state::{file_inventory, independent_format_readback, read_state};

enum Mode {
    Write {
        root: PathBuf,
        max_score_error: f32,
        centroids: u32,
        kmeans_iterations: u32,
        search_iterations: u32,
    },
    Read {
        root: PathBuf,
        search_iterations: u32,
    },
}

fn main() {
    if let Err(error) = run() {
        eprintln!(
            "{}",
            json!({
                "event": "fsv_failure",
                "error": error.to_string(),
                "remediation": "fix the exact reported model, format, vault, or argument failure; no fallback path exists",
            })
        );
        std::process::exit(1);
    }
}

fn run() -> AnyResult<()> {
    let workspace = std::env::current_dir()?;
    let mode = parse_mode(&workspace)?;
    match mode {
        Mode::Write {
            root,
            max_score_error,
            centroids,
            kmeans_iterations,
            search_iterations,
        } => write_fixture(
            &workspace,
            &root,
            max_score_error,
            centroids,
            kmeans_iterations,
            search_iterations,
        ),
        Mode::Read {
            root,
            search_iterations,
        } => read_fixture(&workspace, &root, search_iterations),
    }
}

fn write_fixture(
    workspace: &Path,
    root: &Path,
    max_score_error: f32,
    centroids: u32,
    kmeans_iterations: u32,
    search_iterations: u32,
) -> AnyResult<()> {
    require(
        !root.exists(),
        format!("write root already exists: {}", root.display()),
    )?;
    fs::create_dir(root)?;
    println!(
        "{}",
        json!({
            "event": "fsv_context",
            "mode": "write",
            "platform": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "artifact": std::env::current_exe()?,
            "fixture_root": root,
            "source_of_truth": root.join("vault"),
            "real_model": calyx_registry::DEFAULT_ANSWERAI_COLBERT_MODEL,
            "declared_knobs": {
                "max_score_error": max_score_error,
                "centroids": centroids,
                "kmeans_iterations": kmeans_iterations,
                "search_iterations": search_iterations,
            },
        })
    );
    let registered = register_real_colbert(root)?;
    let vault = open_vault(root, true)?;
    let vault_dir = root.join("vault");
    let empty = read_state(&vault, &vault_dir, &registered.slot)?;
    require(
        empty.seq == 0
            && empty.base.rows == 0
            && empty.primary.rows == 0
            && empty.raw.rows == 0
            && empty.compression.rows == 0
            && empty.ledger.rows == 0,
        "fresh source of truth is not empty",
    )?;
    println!(
        "{}",
        json!({ "event": "source_truth_before", "state": empty })
    );

    let measured = measure_real_corpus(workspace, &vault, &registered)?;
    let max_tokens = u32::try_from(
        *measured
            .token_counts
            .iter()
            .max()
            .ok_or("real corpus produced no token counts")?,
    )?;
    let config = MultiVectorCompressionConfig {
        max_tokens,
        max_token_dim: registered.token_dim,
        centroid_count: centroids,
        kmeans_iterations,
        max_score_error,
    };
    println!(
        "{}",
        json!({
            "event": "real_measurements",
            "document_paths": measured.document_paths,
            "token_counts": measured.token_counts,
            "token_dim": registered.token_dim,
            "lens_id": registered.slot.lens_id,
            "policy": registered.slot.quant,
        })
    );
    ingest_real_corpus(vault.clone(), measured.events.clone())?;
    let raw_state = read_state(&vault, &vault_dir, &registered.slot)?;
    require(
        raw_state.base.rows == measured.rows.len()
            && raw_state.primary.rows == measured.rows.len()
            && raw_state.raw.rows == 0
            && raw_state.compression.rows == 0,
        "streamed real corpus did not produce the exact raw pre-compression state",
    )?;
    println!(
        "{}",
        json!({ "event": "raw_ingest_readback", "state": raw_state })
    );

    let rss_before_create = process_rss_bytes()?;
    let create_started = Instant::now();
    let create = registered.registry.compress_streamed_multivector_column(
        &vault,
        &registered.slot,
        &measured.queries,
        config,
        1,
    )?;
    let create_elapsed = create_started.elapsed();
    let rss_after_create = process_rss_bytes()?;
    vault.flush()?;
    require_report(&create, measured.rows.len(), config)?;
    let created_state = read_state(&vault, &vault_dir, &registered.slot)?;
    require_live_state(&created_state, measured.rows.len())?;
    println!(
        "{}",
        json!({
            "event": "create_readback",
            "report": create,
            "elapsed_ns": create_elapsed.as_nanos(),
            "rss_before": rss_before_create,
            "rss_after": rss_after_create,
            "state": created_state,
        })
    );
    verify_expected_top_hits(&registered, &vault, &measured)?;

    let reseal = registered.registry.write_packed_multivector_generation(
        &vault,
        &registered.slot,
        &measured.rows,
        &measured.queries,
        config,
        1,
    )?;
    vault.flush()?;
    require_report(&reseal, measured.rows.len(), config)?;
    println!(
        "{}",
        json!({
            "event": "reseal_readback",
            "report": reseal,
            "state": read_state(&vault, &vault_dir, &registered.slot)?,
        })
    );

    let erased_row = measured
        .rows
        .last()
        .ok_or("real corpus has no last row")?
        .clone();
    let erase = registered.registry.erase_packed_multivector_rows(
        &vault,
        &registered.slot,
        &[erased_row.cx_id],
        &measured.queries,
        1,
    )?;
    vault.flush()?;
    require_report(&erase, measured.rows.len() - 1, config)?;
    let erased_state = read_state(&vault, &vault_dir, &registered.slot)?;
    require_live_state(&erased_state, measured.rows.len() - 1)?;
    println!(
        "{}",
        json!({ "event": "erase_reseal_readback", "report": erase, "state": erased_state })
    );

    let append = registered.registry.append_reseal_packed_multivector_rows(
        &vault,
        &registered.slot,
        std::slice::from_ref(&erased_row),
        &measured.queries,
        1,
    )?;
    vault.flush()?;
    require_report(&append, measured.rows.len(), config)?;
    let restored_state = read_state(&vault, &vault_dir, &registered.slot)?;
    require_live_state(&restored_state, measured.rows.len())?;
    println!(
        "{}",
        json!({ "event": "append_reseal_readback", "report": append, "state": restored_state })
    );

    edges::run_edges(
        &registered.registry,
        &vault,
        &vault_dir,
        &registered.slot,
        &measured.rows,
        &measured.queries,
        config,
    )?;
    let performance = measure_search(&registered, &vault, &measured.queries, search_iterations)?;
    let independent =
        independent_format_readback(&vault, &registered.slot, registered.slot.lens_id)?;
    require(
        independent.generation_rows as usize == measured.rows.len()
            && independent.max_token_dim == registered.token_dim,
        "independent format readback differs from the real generation",
    )?;
    let final_state = read_state(&vault, &vault_dir, &registered.slot)?;
    println!(
        "{}",
        json!({
            "event": "final_live_readback",
            "state": final_state,
            "independent_wire_parse": independent,
            "release_performance": performance,
        })
    );
    drop(vault);
    let physical = file_inventory(&vault_dir)?;
    println!(
        "{}",
        json!({
            "event": "physical_vault_readback",
            "inventory": physical,
        })
    );
    println!(
        "{}",
        json!({
            "event": "fsv_success",
            "issue": 575,
            "mode": "write",
            "fixture_root": root,
            "final_state_digest": final_state.digest_sha256,
            "physical_digest": physical.digest_sha256,
        })
    );
    Ok(())
}

fn read_fixture(workspace: &Path, root: &Path, search_iterations: u32) -> AnyResult<()> {
    require(
        root.is_dir(),
        format!("existing FSV root is absent: {}", root.display()),
    )?;
    let vault_dir = root.join("vault");
    let before_files = file_inventory(&vault_dir)?;
    let registered = register_real_colbert(root)?;
    let vault = open_vault(root, false)?;
    let measured = measure_real_corpus(workspace, &vault, &registered)?;
    let state = read_state(&vault, &vault_dir, &registered.slot)?;
    require_live_state(&state, measured.rows.len())?;
    let index = registered
        .registry
        .packed_multivector_index(&vault, &registered.slot)?;
    index.verify_at(vault.latest_seq())?;
    drop(index);
    verify_expected_top_hits(&registered, &vault, &measured)?;
    let independent =
        independent_format_readback(&vault, &registered.slot, registered.slot.lens_id)?;
    let performance = measure_search(&registered, &vault, &measured.queries, search_iterations)?;
    drop(vault);
    let after_files = file_inventory(&vault_dir)?;
    require(
        before_files == after_files,
        "separate reader changed physical vault bytes",
    )?;
    println!(
        "{}",
        json!({
            "event": "independent_process_readback",
            "mode": "read_existing",
            "fixture_root": root,
            "state": state,
            "wire": independent,
            "release_performance": performance,
            "physical_before": before_files,
            "physical_after": after_files,
            "mutation": false,
        })
    );
    println!(
        "{}",
        json!({
            "event": "fsv_success",
            "issue": 575,
            "mode": "read_existing",
            "state_digest": state.digest_sha256,
            "physical_digest": after_files.digest_sha256,
        })
    );
    Ok(())
}

fn verify_expected_top_hits(
    registered: &Registered,
    vault: &calyx_aster::vault::AsterVault<calyx_core::SystemClock>,
    measured: &MeasuredCorpus,
) -> AnyResult<()> {
    let index = registered
        .registry
        .packed_multivector_index(vault, &registered.slot)?;
    let mut scratch = PackedMaxSimScratch::default();
    for (row, query) in measured.rows.iter().zip(&measured.queries) {
        let hits = index.search(query, 1, &mut scratch)?;
        require(
            hits.len() == 1 && hits[0].cx_id == row.cx_id,
            format!(
                "real source-file self-query expected top {}, got {hits:?}",
                row.cx_id
            ),
        )?;
    }
    Ok(())
}

fn measure_search(
    registered: &Registered,
    vault: &calyx_aster::vault::AsterVault<calyx_core::SystemClock>,
    queries: &[MultiVectorCompressionQuery],
    iterations: u32,
) -> AnyResult<serde_json::Value> {
    require(
        iterations > 0,
        "search_iterations must be greater than zero",
    )?;
    let index = registered
        .registry
        .packed_multivector_index(vault, &registered.slot)?;
    let mut scratch = PackedMaxSimScratch::default();
    let rss_before = process_rss_bytes()?;
    let started = Instant::now();
    let mut score_accumulator = 0.0_f64;
    for _ in 0..iterations {
        for query in queries {
            let hits = index.search(query, 1, &mut scratch)?;
            score_accumulator += f64::from(hits[0].score);
        }
    }
    let elapsed = started.elapsed();
    let rss_after = process_rss_bytes()?;
    let operations = u64::from(iterations)
        .checked_mul(queries.len() as u64)
        .ok_or("search operation count overflow")?;
    let query_components = (index.manifest().config.max_tokens as usize)
        .checked_mul(index.manifest().token_dim as usize)
        .ok_or("scratch query-component bound overflow")?;
    let scratch_bound = query_components
        .checked_add(index.manifest().token_dim as usize)
        .and_then(|value| value.checked_add(index.manifest().config.max_tokens as usize))
        .and_then(|value| value.checked_mul(std::mem::size_of::<f32>()))
        .ok_or("scratch byte bound overflow")?;
    require(
        scratch.allocated_bytes() <= scratch_bound,
        format!(
            "direct packed scratch allocated {} bytes beyond declared bound {scratch_bound}",
            scratch.allocated_bytes()
        ),
    )?;
    Ok(json!({
        "iterations": iterations,
        "queries_per_iteration": queries.len(),
        "operations": operations,
        "elapsed_ns": elapsed.as_nanos(),
        "mean_latency_ns": elapsed.as_nanos() / u128::from(operations),
        "throughput_queries_per_second": operations as f64 / elapsed.as_secs_f64(),
        "rss_before": rss_before,
        "rss_after": rss_after,
        "rss_delta": i128::from(rss_after) - i128::from(rss_before),
        "packed_scratch_allocated_bytes": scratch.allocated_bytes(),
        "packed_scratch_declared_bound_bytes": scratch_bound,
        "scoring_backend": calyx_registry::packed_maxsim_backend(),
        "score_accumulator": score_accumulator,
    }))
}

fn require_report(
    report: &MultiVectorCompressionReport,
    expected_rows: usize,
    expected_config: MultiVectorCompressionConfig,
) -> AnyResult<()> {
    require(
        report.stored_codec == MultiVectorStorageCodec::ColbertResidual2BitV1
            && report.config == expected_config
            && report.generation_rows as usize == expected_rows
            && report.snapshot.is_some()
            && report.ledger.is_some()
            && report.recall_drop <= 0.02
            && report.max_abs_score_error <= expected_config.max_score_error
            && report.bytes.accounted_bytes > 0
            && report.bytes.centroid_code_bytes > 0
            && report.bytes.residual_bytes > 0
            && report.bytes.codebook_bytes > 0,
        format!("compression report violates the declared contract: {report:?}"),
    )
}

fn require_live_state(state: &state::VaultState, expected_rows: usize) -> AnyResult<()> {
    require(
        state.base.rows == 3
            && state.primary.rows == expected_rows
            && state.raw.rows == expected_rows
            && state.compression.rows >= 2
            && state.ledger.rows == state.physical_ledger_rows
            && state.ledger_chain == format!("intact:{}", state.ledger.rows),
        format!("persisted generation state is incomplete: {state:?}"),
    )
}

fn parse_mode(workspace: &Path) -> AnyResult<Mode> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match args.as_slice() {
        [
            write,
            root,
            max_error_flag,
            max_error,
            centroids_flag,
            centroids,
            iterations_flag,
            iterations,
            search_flag,
            search_iterations,
        ] if write == "--write"
            && max_error_flag == "--max-score-error"
            && centroids_flag == "--centroids"
            && iterations_flag == "--kmeans-iterations"
            && search_flag == "--search-iterations" =>
        {
            let max_score_error = max_error.parse::<f32>()?;
            require(
                max_score_error.is_finite() && max_score_error >= 0.0,
                "max-score-error must be finite and non-negative",
            )?;
            Ok(Mode::Write {
                root: bounded_root(workspace, Path::new(root))?,
                max_score_error,
                centroids: positive_u32(centroids, "centroids")?,
                kmeans_iterations: positive_u32(iterations, "kmeans-iterations")?,
                search_iterations: positive_u32(search_iterations, "search-iterations")?,
            })
        }
        [read, root, search_flag, search_iterations]
            if read == "--read-existing" && search_flag == "--search-iterations" =>
        {
            Ok(Mode::Read {
                root: bounded_root(workspace, Path::new(root))?,
                search_iterations: positive_u32(search_iterations, "search-iterations")?,
            })
        }
        _ => Err("usage: colbert_compression_fsv --write <absolute-root> --max-score-error <finite-f32> --centroids <positive-u32> --kmeans-iterations <positive-u32> --search-iterations <positive-u32> | --read-existing <absolute-root> --search-iterations <positive-u32>".into()),
    }
}

fn bounded_root(workspace: &Path, raw: &Path) -> AnyResult<PathBuf> {
    require(raw.is_absolute(), "FSV root must be absolute")?;
    let scratch = workspace.join(".tmp").canonicalize()?;
    let parent = raw
        .parent()
        .ok_or("FSV root has no parent")?
        .canonicalize()?;
    require(
        parent == scratch,
        "FSV root must be directly below workspace .tmp",
    )?;
    Ok(parent.join(raw.file_name().ok_or("FSV root has no final component")?))
}

fn positive_u32(raw: &str, label: &str) -> AnyResult<u32> {
    let value = raw.parse::<u32>()?;
    require(value > 0, format!("{label} must be greater than zero"))?;
    Ok(value)
}

#[cfg(windows)]
fn process_rss_bytes() -> AnyResult<u64> {
    use std::mem::{size_of, zeroed};
    use windows_sys::Win32::System::ProcessStatus::{
        GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    // SAFETY: the structure is correctly sized and remains writable for the
    // complete Windows API call.
    unsafe {
        let mut counters: PROCESS_MEMORY_COUNTERS = zeroed();
        counters.cb = size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
        if GetProcessMemoryInfo(
            GetCurrentProcess(),
            &mut counters,
            size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        ) == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(counters.WorkingSetSize as u64)
    }
}

#[cfg(not(windows))]
fn process_rss_bytes() -> AnyResult<u64> {
    Err("issue #575 RSS FSV is implemented only for the shipping Windows target".into())
}

fn require(condition: bool, message: impl Into<String>) -> Result<(), Box<dyn Error>> {
    if condition {
        Ok(())
    } else {
        Err(message.into().into())
    }
}
