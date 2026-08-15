//! Manual Full State Verification for Forge-backed Weave scalar8 exact kNN.
//!
//! This executable is a reality probe, not a test. It runs the production CPU
//! oracle, the attested CUDA producer, and the public Weave planner over one
//! known scalar8 corpus; persists their receipts; proves repeat/concurrent CUDA
//! determinism; and records before/action/after state for malformed and physical
//! admission refusals.

use std::collections::BTreeMap;
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use astrolabe_weave::{
    SimilarityCandidateStrategy, SimilarityFamily, SimilarityNode, SimilarityPlannerConfig,
    plan_similarity_family_edges,
};
use calyx_core::SlotVector;
use calyx_forge::{
    BackendKind, ForgeError, Scalar8ExactKnnExecution, scalar8_exact_knn_cpu,
    scalar8_exact_knn_cuda,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const ISSUE: u64 = 1_057;
const ROWS: usize = 6;
const DIM: usize = 4;
const K: usize = 3;
const CODES: [i8; ROWS * DIM] = [
    127, 0, 0, 0, // a: +x
    90, 90, 0, 0, // b: +x/+y
    0, 127, 0, 0, // c: +y
    -127, 0, 0, 0, // d: -x
    0, 0, 127, 0, // e: +z
    0, 0, 0, 127, // f: +w
];
const EXPECTED_NEIGHBORS: [[usize; K]; ROWS] = [
    [0, 1, 2],
    [1, 0, 2],
    [2, 1, 0],
    [3, 2, 4],
    [4, 0, 1],
    [5, 0, 1],
];

type AnyResult<T> = Result<T, Box<dyn Error + Send + Sync + 'static>>;

fn main() -> AnyResult<()> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if arguments
        .first()
        .is_some_and(|value| value == "--expected-error-child")
    {
        return expected_error_child(&arguments);
    }
    let output = arguments
        .first()
        .map(PathBuf::from)
        .ok_or("usage: issue_1057_forge_exact_knn_fsv <fresh-output-directory>")?;
    run(&output)
}

fn run(output: &Path) -> AnyResult<()> {
    prepare_fresh_output(output)?;
    let initial = inventory(output)?;
    write_json(output.join("00-initial.json"), &initial)?;

    let cpu = scalar8_exact_knn_cpu(&CODES, ROWS, DIM, K)?;
    require_execution(&cpu, BackendKind::Cpu, "cpu oracle")?;
    write_json(output.join("10-cpu-oracle.json"), &cpu)?;

    let gpu_first = scalar8_exact_knn_cuda(&CODES, ROWS, DIM, K)?;
    require_execution(&gpu_first, BackendKind::Cuda, "first CUDA execution")?;
    require(
        gpu_first.neighbors == cpu.neighbors,
        "first CUDA neighbors differ bit-for-bit from the CPU oracle",
    )?;
    require(
        gpu_first.receipt.output_sha256 == cpu.receipt.output_sha256,
        "first CUDA output hash differs from the CPU oracle",
    )?;
    require_cuda_release(&gpu_first, "first CUDA execution")?;
    write_json(output.join("20-gpu-first.json"), &gpu_first)?;

    let (gpu_concurrent_a, gpu_concurrent_b) = std::thread::scope(|scope| {
        let left = scope.spawn(|| scalar8_exact_knn_cuda(&CODES, ROWS, DIM, K));
        let right = scope.spawn(|| scalar8_exact_knn_cuda(&CODES, ROWS, DIM, K));
        let left = left
            .join()
            .map_err(|_| "concurrent CUDA caller A panicked")??;
        let right = right
            .join()
            .map_err(|_| "concurrent CUDA caller B panicked")??;
        Ok::<_, Box<dyn Error + Send + Sync + 'static>>((left, right))
    })?;
    for (label, execution) in [
        ("concurrent CUDA caller A", &gpu_concurrent_a),
        ("concurrent CUDA caller B", &gpu_concurrent_b),
    ] {
        require_execution(execution, BackendKind::Cuda, label)?;
        require_cuda_release(execution, label)?;
        require(
            execution.neighbors == cpu.neighbors,
            &format!("{label} neighbors differ from the CPU oracle"),
        )?;
        require(
            execution.receipt == gpu_first.receipt,
            &format!("{label} stable receipt differs from the first CUDA receipt"),
        )?;
    }
    write_json(
        output.join("21-gpu-concurrent.json"),
        &json!({
            "caller_a": gpu_concurrent_a,
            "caller_b": gpu_concurrent_b,
            "stable_receipt_equal": true,
            "neighbors_equal_cpu": true,
        }),
    )?;

    let weave = run_weave_plan()?;
    let weave_receipt = weave
        .skips
        .ann_reports
        .get(&SimilarityFamily::Semantic)
        .and_then(|report| report.forge_exact_knn_measurements.first())
        .ok_or("Weave plan did not expose one Forge exact-kNN receipt")?;
    require(
        weave_receipt.executor == BackendKind::Cuda,
        "Weave selected a non-CUDA exact-kNN executor",
    )?;
    require(
        weave_receipt.input_sha256 == cpu.receipt.input_sha256,
        "Weave's physical scalar8 input hash differs from the known corpus",
    )?;
    require(
        weave_receipt.output_sha256 == cpu.receipt.output_sha256,
        "Weave's Forge output hash differs from the CPU oracle",
    )?;
    let observed_pairs = weave
        .edges
        .iter()
        .map(|edge| format!("{}->{}", edge.source_qn, edge.target_qn))
        .collect::<Vec<_>>();
    let expected_pairs = vec![
        "fsv::0->fsv::1",
        "fsv::0->fsv::2",
        "fsv::1->fsv::2",
        "fsv::1->fsv::4",
        "fsv::2->fsv::3",
        "fsv::3->fsv::4",
    ];
    require(
        observed_pairs == expected_pairs,
        &format!(
            "Weave admitted edges differ from the hand-derived exact result: {observed_pairs:?}"
        ),
    )?;
    let pair_counts = weave
        .skips
        .pair_counts
        .get(&SimilarityFamily::Semantic)
        .ok_or("Weave plan omitted semantic pair counts")?;
    require(
        pair_counts.candidate_pairs == 9
            && pair_counts.incompatible_shape_pairs == 0
            && pair_counts.below_threshold_pairs == 0
            && pair_counts.cap_dropped_pairs == 3
            && pair_counts.admitted_pairs == expected_pairs.len(),
        &format!(
            "Weave pair accounting differs from the hand-derived 9/0/0/3/6 result: {pair_counts:?}"
        ),
    )?;
    let edge_dump = astrolabe_weave::similarity_edge_dump_bytes(&weave.edges);
    write_bytes(output.join("30-weave-edges.tsv"), &edge_dump)?;
    write_json(
        output.join("30-weave-plan.json"),
        &json!({
            "family": SimilarityFamily::Semantic.wire_name(),
            "edge_count": weave.edges.len(),
            "edge_dump_blake3": blake3::hash(&edge_dump).to_hex().to_string(),
            "expected_pairs": expected_pairs,
            "pair_counts": {
                "candidate_pairs": pair_counts.candidate_pairs,
                "incompatible_shape_pairs": pair_counts.incompatible_shape_pairs,
                "below_threshold_pairs": pair_counts.below_threshold_pairs,
                "cap_dropped_pairs": pair_counts.cap_dropped_pairs,
                "admitted_pairs": pair_counts.admitted_pairs,
            },
            "forge_receipt": weave_receipt,
        }),
    )?;

    let max_dim_codes = vec![127_i8; 2 * calyx_forge::SCALAR8_EXACT_KNN_MAX_DIM];
    let max_dim =
        scalar8_exact_knn_cpu(&max_dim_codes, 2, calyx_forge::SCALAR8_EXACT_KNN_MAX_DIM, 2)?;
    require(
        max_dim.receipt.dim == calyx_forge::SCALAR8_EXACT_KNN_MAX_DIM,
        "maximum exact scalar8 dimension was not accepted exactly",
    )?;
    write_json(output.join("40-max-dimension.json"), &max_dim)?;

    let empty = refusal_without_mutation(output, "50-empty", "CALYX_FORGE_SHAPE_MISMATCH", || {
        scalar8_exact_knn_cpu(&[], 0, DIM, 1)
    })?;
    let malformed = refusal_without_mutation(
        output,
        "51-malformed-length",
        "CALYX_FORGE_SHAPE_MISMATCH",
        || scalar8_exact_knn_cpu(&CODES[..CODES.len() - 1], ROWS, DIM, K),
    )?;
    let zero_norm = refusal_without_mutation(
        output,
        "52-zero-norm",
        "CALYX_FORGE_NUMERICAL_INVARIANT",
        || {
            let mut codes = CODES;
            codes[(ROWS - 1) * DIM..].fill(0);
            scalar8_exact_knn_cpu(&codes, ROWS, DIM, K)
        },
    )?;
    let over_dimension = refusal_without_mutation(
        output,
        "53-over-dimension",
        "CALYX_FORGE_SHAPE_MISMATCH",
        || {
            let codes = vec![1_i8; calyx_forge::SCALAR8_EXACT_KNN_MAX_DIM + 1];
            scalar8_exact_knn_cpu(&codes, 1, calyx_forge::SCALAR8_EXACT_KNN_MAX_DIM + 1, 1)
        },
    )?;

    let vram = child_refusal(
        output,
        "54-vram-budget",
        "CALYX_FORGE_VRAM_BUDGET",
        &[(calyx_forge::vram::VRAM_BUDGET_ENV, "1")],
    )?;
    let unavailable = child_refusal(
        output,
        "55-unavailable-device",
        "CALYX_CUDA_DEVICE_SELECTOR_INVALID",
        &[(calyx_forge::CUDA_DEVICE_ENV, "4294967295")],
    )?;

    let final_inventory_before_report = inventory(output)?;
    let report = json!({
        "schema": "astrolabe.issue-1057.forge-exact-knn-fsv.v1",
        "issue": ISSUE,
        "known_input": {
            "rows": ROWS,
            "dim": DIM,
            "k": K,
            "codes": CODES,
            "expected_neighbor_indices": EXPECTED_NEIGHBORS,
            "input_blake3": blake3::hash(bytemuck_i8(&CODES)).to_hex().to_string(),
        },
        "happy": {
            "cpu_output_sha256": cpu.receipt.output_sha256,
            "gpu_output_sha256": gpu_first.receipt.output_sha256,
            "weave_output_sha256": weave_receipt.output_sha256,
            "gpu_stable_receipt": gpu_first.receipt,
            "gpu_observation": gpu_first.observation,
            "concurrent_receipts_equal": gpu_concurrent_a.receipt == gpu_concurrent_b.receipt,
            "weave_forge_commissioned": true,
        },
        "boundaries": {
            "maximum_dimension": calyx_forge::SCALAR8_EXACT_KNN_MAX_DIM,
            "empty": empty,
            "malformed_length": malformed,
            "zero_norm": zero_norm,
            "over_dimension": over_dimension,
            "vram_budget": vram,
            "unavailable_device": unavailable,
        },
        "source_of_truth": {
            "kind": "durable JSON files in the native FSV payload directory",
            "pre_report_inventory": final_inventory_before_report,
        },
    });
    let report_path = output.join("report.json");
    write_json(&report_path, &report)?;
    let report_bytes = fs::read(&report_path)?;
    let report_hash = format!("{:x}", Sha256::digest(&report_bytes));
    write_bytes(
        output.join("report.sha256"),
        format!("{report_hash}  report.json\n").as_bytes(),
    )?;
    println!(
        "ASTRO_ISSUE_1057_FSV_OK report={} sha256={} cpu_gpu_weave_output_sha256={}",
        report_path.display(),
        report_hash,
        cpu.receipt.output_sha256
    );
    Ok(())
}

fn run_weave_plan() -> AnyResult<astrolabe_weave::SimilarityPlan> {
    let diagonal = std::f32::consts::FRAC_1_SQRT_2;
    let vectors = [
        [1.0, 0.0, 0.0, 0.0],
        [diagonal, diagonal, 0.0, 0.0],
        [0.0, 1.0, 0.0, 0.0],
        [-1.0, 0.0, 0.0, 0.0],
        [0.0, 0.0, 1.0, 0.0],
        [0.0, 0.0, 0.0, 1.0],
    ];
    let nodes = vectors
        .into_iter()
        .enumerate()
        .map(|(ordinal, data)| {
            SimilarityNode::new(format!("fsv-{ordinal}"), format!("fsv::{ordinal}")).with_slot(
                SimilarityFamily::Semantic.slot(),
                SlotVector::Dense {
                    dim: DIM as u32,
                    data: data.to_vec(),
                },
            )
        })
        .collect::<Vec<_>>();
    let mut config = SimilarityPlannerConfig::resolve_runtime()?;
    require(
        config.runtime.exact_knn_executor()
            == astrolabe_weave::knobs::WEAVE_EXACT_KNN_EXECUTOR_CUDA,
        "declared Weave production executor did not resolve to CUDA",
    )?;
    require(
        config.runtime.dense_ann_strategy()
            == astrolabe_weave::knobs::WEAVE_DENSE_ANN_STRATEGY_EXACT_KNN,
        "declared Weave dense strategy did not resolve to global exact kNN",
    )?;
    config.per_node_cap = 2;
    config.ann.candidate_multiplier = 1;
    // Zero-score pairs are admitted because the production predicate rejects
    // only `score < threshold`; use the registry's exact lower bound.
    config.thresholds.sim_semantic_min_score = 0.0;
    config = config
        .with_candidate_strategy(SimilarityFamily::Semantic, SimilarityCandidateStrategy::Ann);
    Ok(plan_similarity_family_edges(
        &nodes,
        SimilarityFamily::Semantic,
        &config,
    )?)
}

fn require_execution(
    execution: &Scalar8ExactKnnExecution,
    expected_executor: BackendKind,
    label: &str,
) -> AnyResult<()> {
    require(
        execution.receipt.executor == expected_executor,
        &format!("{label} executor differs from the requested backend"),
    )?;
    require(
        execution.receipt.rows == ROWS && execution.receipt.dim == DIM && execution.receipt.k == K,
        &format!("{label} receipt shape differs from the known input"),
    )?;
    let observed = execution
        .neighbors
        .iter()
        .map(|row| {
            row.iter()
                .map(|neighbor| neighbor.index)
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let expected = EXPECTED_NEIGHBORS
        .iter()
        .map(|row| row.to_vec())
        .collect::<Vec<_>>();
    require(
        observed == expected,
        &format!("{label} neighbor ordinals differ from the known exact answer: {observed:?}"),
    )?;
    Ok(())
}

fn require_cuda_release(execution: &Scalar8ExactKnnExecution, label: &str) -> AnyResult<()> {
    require(
        execution.observation.forge_allocated_after_release_bytes == 0,
        &format!("{label} retained a logical Forge VRAM reservation"),
    )?;
    require(
        execution.receipt.submission_contract == "process_serial_attested_context_default_stream",
        &format!("{label} did not report the process-serial submission contract"),
    )?;
    require(
        execution.receipt.kernels.len() == 2
            && execution
                .receipt
                .kernels
                .iter()
                .map(|kernel| kernel.module_name.as_str())
                .eq(["distance", "topk"]),
        &format!("{label} did not attest the exact distance/topk module set"),
    )?;
    Ok(())
}

fn refusal_without_mutation<F>(
    output: &Path,
    name: &str,
    expected_code: &str,
    action: F,
) -> AnyResult<Value>
where
    F: FnOnce() -> calyx_forge::Result<Scalar8ExactKnnExecution>,
{
    let before = inventory(output)?;
    let error = expect_error(action(), expected_code, None)?;
    let after = inventory(output)?;
    require(
        before == after,
        &format!("{name} refusal mutated the durable payload before its evidence record"),
    )?;
    let transition = json!({
        "name": name,
        "before": before,
        "action": error,
        "after": after,
        "state_unchanged": true,
    });
    write_json(output.join(format!("{name}.json")), &transition)?;
    Ok(transition)
}

fn child_refusal(
    output: &Path,
    name: &str,
    expected_detail_code: &str,
    environment: &[(&str, &str)],
) -> AnyResult<Value> {
    let error_path = output.join(format!("{name}.error.json"));
    let result_path = output.join(format!("{name}.result.json"));
    require(
        !error_path.exists() && !result_path.exists(),
        &format!("{name} output paths were not absent before the action"),
    )?;
    let mut command = Command::new(std::env::current_exe()?);
    command
        .arg("--expected-error-child")
        .arg(&error_path)
        .arg(&result_path)
        .arg(expected_detail_code)
        .env_remove("CALYX_ONNX_CUDA_DEVICE")
        .env_remove("CALYX_CANDLE_CUDA_DEVICE");
    for (key, value) in environment {
        command.env(key, value);
    }
    let status = command.status()?;
    require(
        status.success(),
        &format!("{name} child exited with {status}"),
    )?;
    require(
        error_path.is_file() && !result_path.exists(),
        &format!("{name} did not persist only its structured refusal record"),
    )?;
    let raw = fs::read(&error_path)?;
    let error: Value = serde_json::from_slice(&raw)?;
    require(
        error
            .get("detail")
            .and_then(Value::as_str)
            .is_some_and(|detail| detail.contains(expected_detail_code)),
        &format!("{name} error does not retain cause code {expected_detail_code}: {error}"),
    )?;
    Ok(json!({
        "name": name,
        "before": {
            "error_record_exists": false,
            "derived_result_exists": false,
        },
        "action": error,
        "after": {
            "error_record_exists": true,
            "error_record_bytes": raw.len(),
            "error_record_blake3": blake3::hash(&raw).to_hex().to_string(),
            "derived_result_exists": false,
        },
        "no_derived_result_published": true,
    }))
}

fn expected_error_child(arguments: &[std::ffi::OsString]) -> AnyResult<()> {
    if arguments.len() != 4 {
        return Err("expected-error child requires error path, result path, and cause code".into());
    }
    let error_path = PathBuf::from(&arguments[1]);
    let result_path = PathBuf::from(&arguments[2]);
    let expected_detail_code = arguments[3]
        .to_str()
        .ok_or("expected child cause code is not Unicode")?;
    require(
        !error_path.exists() && !result_path.exists(),
        "expected-error child output paths are not fresh",
    )?;
    let error = expect_error(
        scalar8_exact_knn_cuda(&CODES, ROWS, DIM, K),
        "CALYX_FORGE_SCALAR8_EXACT_KNN_FAILED",
        Some(expected_detail_code),
    )?;
    write_json(error_path, &error)
}

fn expect_error(
    result: calyx_forge::Result<Scalar8ExactKnnExecution>,
    expected_code: &str,
    expected_detail_code: Option<&str>,
) -> AnyResult<Value> {
    match result {
        Ok(execution) => Err(format!(
            "expected {expected_code}, received successful output {}",
            execution.receipt.output_sha256
        )
        .into()),
        Err(error) => {
            require(
                error.code() == expected_code,
                &format!(
                    "expected {expected_code}, observed {}: {error}",
                    error.code()
                ),
            )?;
            let detail = error.to_string();
            if let Some(expected) = expected_detail_code {
                require(
                    detail.contains(expected),
                    &format!("{expected_code} did not retain cause code {expected}: {detail}"),
                )?;
            }
            Ok(error_json(&error))
        }
    }
}

fn error_json(error: &ForgeError) -> Value {
    json!({
        "code": error.code(),
        "detail": error.to_string(),
        "remediation": error.remediation(),
    })
}

fn inventory(path: &Path) -> AnyResult<Value> {
    let mut files = BTreeMap::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            return Err(format!(
                "unexpected non-file in FSV payload: {}",
                entry.path().display()
            )
            .into());
        }
        let bytes = fs::read(entry.path())?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "FSV payload filename is not Unicode")?;
        files.insert(
            name,
            json!({
                "bytes": bytes.len(),
                "blake3": blake3::hash(&bytes).to_hex().to_string(),
            }),
        );
    }
    Ok(json!({
        "file_count": files.len(),
        "files": files,
    }))
}

fn prepare_fresh_output(path: &Path) -> AnyResult<()> {
    require(
        !path.exists(),
        &format!("FSV output already exists: {}", path.display()),
    )?;
    fs::create_dir_all(path)?;
    Ok(())
}

fn write_json(path: impl AsRef<Path>, value: &impl serde::Serialize) -> AnyResult<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    write_bytes(path, &bytes)
}

fn write_bytes(path: impl AsRef<Path>, bytes: &[u8]) -> AnyResult<()> {
    let path = path.as_ref();
    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn bytemuck_i8(values: &[i8]) -> &[u8] {
    // SAFETY: i8/u8 have identical size/alignment and all bit patterns are valid.
    unsafe { std::slice::from_raw_parts(values.as_ptr().cast::<u8>(), values.len()) }
}

fn require(condition: bool, message: &str) -> AnyResult<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string().into())
    }
}
