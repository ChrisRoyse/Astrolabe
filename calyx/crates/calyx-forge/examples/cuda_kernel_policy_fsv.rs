#[cfg(not(feature = "cuda"))]
fn main() {
    eprintln!(
        "CALYX_FORGE_CUDA_FSV_FEATURE_MISSING: run this real-artifact driver with --features cuda"
    );
    std::process::exit(2);
}

#[cfg(feature = "cuda")]
mod enabled {
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::Instant;

    use calyx_forge::cuda::kernels::{DISTANCE_CUBIN, MXFP_GEMM_CUBIN, TOPK_CUBIN};
    use calyx_forge::{
        Backend, CUDA_KERNEL_POLICY_JSON, CudaBackend, CudaContext, MxFp4GemmPlan, MxFp8GemmPlan,
        configured_cuda_runtime_ordinal, cuda_kernel_build_attestation, init_cuda_native_kernel,
        pack_mxfp4_a_row_major, pack_mxfp4_b_column_major, pack_mxfp8_a_row_major,
        pack_mxfp8_b_column_major,
    };
    use cudarc::driver::{LaunchConfig, PushKernelArg};
    #[cfg(feature = "cuda-policy-measurement")]
    use cudarc::nvrtc::Ptx;
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};

    const DISTANCE_DIM: usize = 1024;
    const DISTANCE_CANDIDATES: usize = 4;
    const MX_M: usize = 16;
    const MX_K: usize = 64;
    const MX_N: usize = 8;
    const WARM_RUNS: usize = 100;
    #[cfg(feature = "cuda-policy-measurement")]
    const MEASUREMENT_ROUNDS: usize = 5;

    type AnyResult<T> = Result<T, Box<dyn std::error::Error>>;

    pub fn run() -> AnyResult<()> {
        let args = std::env::args_os().collect::<Vec<_>>();
        if args.get(1).is_some_and(|arg| arg == "--selector-edge") {
            return selector_edge_child();
        }
        let output_dir = args
            .get(1)
            .map(PathBuf::from)
            .ok_or("usage: cuda_kernel_policy_fsv <output-directory>")?;
        fs::create_dir_all(&output_dir)?;

        let runtime_ordinal = configured_cuda_runtime_ordinal()?;
        let context_started = Instant::now();
        let ctx = init_cuda_native_kernel(runtime_ordinal, true)?;
        let context_init_ns = elapsed_ns(context_started)?;
        require(
            ctx.runtime_ordinal() == runtime_ordinal,
            "context did not preserve configured CUDA Runtime ordinal",
        )?;
        ctx.attest_physical_identity()?;
        let backend = CudaBackend::with_context(ctx.clone());

        let build = cuda_kernel_build_attestation();
        write_json(
            &output_dir.join("build-attestation.json"),
            &serde_json::to_value(build)?,
        )?;
        write_and_verify(
            &output_dir.join("cuda-kernel-policy-v1.json"),
            CUDA_KERNEL_POLICY_JSON.as_bytes(),
        )?;
        let module_dir = output_dir.join("production-modules");
        fs::create_dir_all(&module_dir)?;
        write_and_verify(&module_dir.join("distance.cubin"), DISTANCE_CUBIN)?;
        write_and_verify(&module_dir.join("topk.cubin"), TOPK_CUBIN)?;
        write_and_verify(&module_dir.join("mxfp_gemm.cubin"), MXFP_GEMM_CUBIN)?;

        let distance = exercise_distance(&backend, &output_dir)?;
        let topk = exercise_topk(&backend, &output_dir)?;
        let mxfp = exercise_mxfp(&ctx, &output_dir)?;
        let loaded_modules = ctx.loaded_kernel_modules()?;
        require(
            loaded_modules.len() == 3,
            "happy path did not physically load all three production kernel modules",
        )?;
        write_json(
            &output_dir.join("loaded-modules.json"),
            &serde_json::to_value(&loaded_modules)?,
        )?;
        let gpu_identity = capture_gpu_identity_state(&ctx, &output_dir)?;
        let (gpu_processes, gpu_process_binding) = capture_gpu_process_state(&ctx, &output_dir)?;
        let edges = exercise_edges(&backend, &output_dir)?;

        #[cfg(feature = "cuda-policy-measurement")]
        let measurement = exercise_measurement_matrix(&ctx, &output_dir)?;
        #[cfg(not(feature = "cuda-policy-measurement"))]
        let measurement = json!({"enabled": false});

        ctx.attest_physical_identity()?;
        let evidence_inventory = inventory(&output_dir)?;
        write_json(
            &output_dir.join("evidence-inventory.json"),
            &serde_json::to_value(&evidence_inventory)?,
        )?;
        let report = json!({
            "schema": "calyx.forge.cuda-kernel-fsv.v1",
            "issue": 492,
            "execution": {
                "pid": std::process::id(),
                "runtime_ordinal": ctx.runtime_ordinal(),
                "driver_ordinal": ctx.driver_ordinal(),
                "physical_device": ctx.physical_identity().canonical_execution_token(),
                "device_name": ctx.name(),
                "compute_capability": ctx.compute_capability(),
                "selection_authority": ctx.selection_authority(),
                "context_init_ns": context_init_ns,
                "post_run_physical_attestation": true,
            },
            "build": build,
            "source_of_truth": {
                "build_attestation": "build-attestation.json",
                "policy": "cuda-kernel-policy-v1.json",
                "loaded_modules": "loaded-modules.json",
                "production_modules": [
                    "production-modules/distance.cubin",
                    "production-modules/topk.cubin",
                    "production-modules/mxfp_gemm.cubin"
                ],
                "distance_output": "distance-output.f32le",
                "topk_output": "topk-output.json",
                "mxfp4_output": "mxfp4-output.f32le",
                "mxfp8_output": "mxfp8-output.f32le",
                "gpu_identity": "nvidia-smi-gpu.csv",
                "gpu_processes": "nvidia-smi-compute-apps.csv",
                "gpu_process_binding": "nvidia-smi-process-binding.json",
                "evidence_inventory": "evidence-inventory.json",
            },
            "distance": distance,
            "topk": topk,
            "mxfp": mxfp,
            "loaded_modules": loaded_modules,
            "gpu_identity": gpu_identity,
            "gpu_processes": gpu_processes,
            "gpu_process_binding": gpu_process_binding,
            "edges": edges,
            "measurement": measurement,
            "evidence_inventory": evidence_inventory,
        });
        write_json(&output_dir.join("report.json"), &report)?;
        let report_bytes = fs::read(output_dir.join("report.json"))?;
        let report_hash = sha256_hex(&report_bytes);
        write_and_verify(
            &output_dir.join("report.sha256"),
            format!("{report_hash}  report.json\r\n").as_bytes(),
        )?;
        let readback: Value = serde_json::from_slice(&report_bytes)?;
        require(
            readback == report,
            "persisted report JSON differs from memory",
        )?;
        println!(
            "{}",
            serde_json::to_string(&json!({
                "event": "cuda_kernel_fsv_readback",
                "report_sha256": report_hash,
                "report_bytes": report_bytes.len(),
                "files": inventory(&output_dir)?,
                "report": readback,
            }))?
        );
        Ok(())
    }

    fn exercise_distance(backend: &CudaBackend, output_dir: &Path) -> AnyResult<Value> {
        let query = (0..DISTANCE_DIM)
            .map(|index| if index.is_multiple_of(2) { 1.0 } else { -1.0 })
            .collect::<Vec<_>>();
        let mut candidates = Vec::with_capacity(DISTANCE_DIM * DISTANCE_CANDIDATES);
        candidates.extend_from_slice(&query);
        candidates.extend(query.iter().map(|value| -*value));
        candidates.extend((0..DISTANCE_DIM).map(|_| 1.0_f32));
        candidates.extend((0..DISTANCE_DIM).map(|index| {
            if index < DISTANCE_DIM / 2 {
                query[index]
            } else {
                -query[index]
            }
        }));
        let expected_dot = [DISTANCE_DIM as f32, -(DISTANCE_DIM as f32), 0.0, 0.0];
        let expected_cosine = [1.0, -1.0, 0.0, 0.0];
        let expected_l2 = [
            0.0,
            (4 * DISTANCE_DIM) as f32,
            (2 * DISTANCE_DIM) as f32,
            (2 * DISTANCE_DIM) as f32,
        ];
        let mut dot = [0.0_f32; DISTANCE_CANDIDATES];
        let mut cosine = [0.0_f32; DISTANCE_CANDIDATES];
        let mut l2 = [0.0_f32; DISTANCE_CANDIDATES];

        let first_started = Instant::now();
        backend.dot(&query, &candidates, DISTANCE_DIM, &mut dot)?;
        let first_dispatch_ns = elapsed_ns(first_started)?;
        backend.cosine(&query, &candidates, DISTANCE_DIM, &mut cosine)?;
        backend.l2(&query, &candidates, DISTANCE_DIM, &mut l2)?;
        require_f32_bits("distance dot", &dot, &expected_dot)?;
        require_f32_bits("distance cosine", &cosine, &expected_cosine)?;
        require_f32_bits("distance l2", &l2, &expected_l2)?;

        let warm_started = Instant::now();
        for _ in 0..WARM_RUNS {
            backend.dot(&query, &candidates, DISTANCE_DIM, &mut dot)?;
        }
        let warm_elapsed_ns = elapsed_ns(warm_started)?;
        require_f32_bits("warm distance dot", &dot, &expected_dot)?;
        let mut persisted = Vec::new();
        append_f32(&mut persisted, &dot);
        append_f32(&mut persisted, &cosine);
        append_f32(&mut persisted, &l2);
        write_and_verify(&output_dir.join("distance-output.f32le"), &persisted)?;
        Ok(json!({
            "shape": [DISTANCE_CANDIDATES, DISTANCE_DIM],
            "dot": dot,
            "cosine": cosine,
            "l2": l2,
            "first_dispatch_ns": first_dispatch_ns,
            "warm_runs": WARM_RUNS,
            "warm_total_ns": warm_elapsed_ns,
            "warm_ns_per_run": warm_elapsed_ns as f64 / WARM_RUNS as f64,
            "persisted_sha256": sha256_hex(&persisted),
        }))
    }

    fn exercise_topk(backend: &CudaBackend, output_dir: &Path) -> AnyResult<Value> {
        let scores = (0..2048)
            .map(|index| {
                let bucket = (index * 37) % 97;
                bucket as f32 - 48.0
            })
            .collect::<Vec<_>>();
        let mut expected = scores.iter().copied().enumerate().collect::<Vec<_>>();
        expected.sort_by(|left, right| {
            right
                .1
                .total_cmp(&left.1)
                .then_with(|| left.0.cmp(&right.0))
        });
        expected.truncate(32);
        let first_started = Instant::now();
        let mut observed = backend.topk(&scores, 32)?;
        let first_dispatch_ns = elapsed_ns(first_started)?;
        require(
            observed == expected,
            "top-k output differs from exact ordering",
        )?;
        let warm_started = Instant::now();
        for _ in 0..WARM_RUNS {
            observed = backend.topk(&scores, 32)?;
        }
        let warm_elapsed_ns = elapsed_ns(warm_started)?;
        require(observed == expected, "warm top-k output changed")?;
        let value = json!({
            "count": scores.len(),
            "k": 32,
            "pairs": observed,
            "first_dispatch_ns": first_dispatch_ns,
            "warm_runs": WARM_RUNS,
            "warm_total_ns": warm_elapsed_ns,
            "warm_ns_per_run": warm_elapsed_ns as f64 / WARM_RUNS as f64,
        });
        write_json(&output_dir.join("topk-output.json"), &value)?;
        Ok(value)
    }

    fn exercise_mxfp(ctx: &CudaContext, output_dir: &Path) -> AnyResult<Value> {
        let (a, b, expected) = mx_matrices(MX_M, MX_K, MX_N);
        let stream = ctx.inner().default_stream();
        let a4 = pack_mxfp4_a_row_major(&a, MX_M, MX_K)?;
        let b4 = pack_mxfp4_b_column_major(&b, MX_K, MX_N)?;
        let a8 = pack_mxfp8_a_row_major(&a, MX_M, MX_K)?;
        let b8 = pack_mxfp8_b_column_major(&b, MX_K, MX_N)?;
        let mut out4 = stream.alloc_zeros(MX_M * MX_N)?;
        let mut out8 = stream.alloc_zeros(MX_M * MX_N)?;
        let first_started = Instant::now();
        let mut plan4 = MxFp4GemmPlan::upload(ctx, &a4, &b4, MX_M, MX_K, MX_N)?;
        plan4.execute(ctx, &mut out4)?;
        let first_dispatch_ns = elapsed_ns(first_started)?;
        let mut plan8 = MxFp8GemmPlan::upload(ctx, &a8, &b8, MX_M, MX_K, MX_N)?;
        plan8.execute(ctx, &mut out8)?;
        let warm_started = Instant::now();
        for _ in 0..WARM_RUNS {
            plan4.execute(ctx, &mut out4)?;
            plan8.execute(ctx, &mut out8)?;
        }
        let warm_elapsed_ns = elapsed_ns(warm_started)?;
        let observed4 = stream.clone_dtoh(&out4)?;
        let observed8 = stream.clone_dtoh(&out8)?;
        require_f32_bits("MXFP4", &observed4, &expected)?;
        require_f32_bits("MXFP8", &observed8, &expected)?;
        let persisted4 = f32_bytes(&observed4);
        let persisted8 = f32_bytes(&observed8);
        write_and_verify(&output_dir.join("mxfp4-output.f32le"), &persisted4)?;
        write_and_verify(&output_dir.join("mxfp8-output.f32le"), &persisted8)?;
        Ok(json!({
            "shape": [MX_M, MX_K, MX_N],
            "first_dispatch_ns": first_dispatch_ns,
            "warm_runs_per_dtype": WARM_RUNS,
            "warm_total_ns": warm_elapsed_ns,
            "mxfp4_output_sha256": sha256_hex(&persisted4),
            "mxfp8_output_sha256": sha256_hex(&persisted8),
            "mxfp4_evidence": plan4.evidence(),
            "mxfp8_evidence": plan8.evidence(),
        }))
    }

    fn exercise_edges(backend: &CudaBackend, output_dir: &Path) -> AnyResult<Value> {
        let baseline = inventory(output_dir)?;

        let mut empty_out = Vec::new();
        backend.dot(&[], &[], 0, &mut empty_out)?;
        require(
            backend.topk(&[], 0)?.is_empty(),
            "empty top-k was not empty",
        )?;
        let empty_after = inventory(output_dir)?;
        require(
            baseline == empty_after,
            "empty edge mutated persisted state",
        )?;

        let mut malformed_out = [123.0_f32];
        let malformed_error = backend
            .dot(&[1.0, 2.0], &[1.0, 2.0, 3.0], 2, &mut malformed_out)
            .err()
            .ok_or("malformed distance shape was accepted")?;
        require(
            malformed_error.code() == "CALYX_FORGE_SHAPE_MISMATCH",
            "malformed shape returned the wrong structured code",
        )?;
        require(
            malformed_out[0].to_bits() == 123.0_f32.to_bits(),
            "malformed shape changed caller output",
        )?;
        let malformed_after = inventory(output_dir)?;
        require(
            baseline == malformed_after,
            "malformed shape mutated persisted state",
        )?;

        let mut nonfinite_out = [321.0_f32];
        let nonfinite_error = backend
            .dot(&[f32::NAN, 1.0], &[1.0, 1.0], 2, &mut nonfinite_out)
            .err()
            .ok_or("non-finite distance input was accepted")?;
        require(
            nonfinite_error.code() == "CALYX_FORGE_NUMERICAL_INVARIANT",
            "non-finite input returned the wrong structured code",
        )?;
        require(
            nonfinite_out[0].to_bits() == 321.0_f32.to_bits(),
            "non-finite input changed caller output",
        )?;
        let nonfinite_after = inventory(output_dir)?;
        require(
            baseline == nonfinite_after,
            "non-finite input mutated persisted state",
        )?;

        let child = Command::new(std::env::current_exe()?)
            .arg("--selector-edge")
            .env("CALYX_CUDA_DEVICE", "not-an-ordinal")
            .env_remove("CALYX_ONNX_CUDA_DEVICE")
            .env_remove("CALYX_CANDLE_CUDA_DEVICE")
            .output()?;
        require(
            child.status.success(),
            &format!(
                "invalid-selector child failed: stdout={} stderr={}",
                String::from_utf8_lossy(&child.stdout),
                String::from_utf8_lossy(&child.stderr)
            ),
        )?;
        let selector_after = inventory(output_dir)?;
        require(
            baseline == selector_after,
            "invalid selector mutated persisted state",
        )?;
        Ok(json!({
            "empty": {
                "before": baseline,
                "after": empty_after,
                "output": empty_out,
                "persisted_state_unchanged": true,
            },
            "malformed_shape": {
                "before": baseline,
                "after": malformed_after,
                "error_code": malformed_error.code(),
                "error": malformed_error.to_string(),
                "caller_output_bits": malformed_out[0].to_bits(),
                "persisted_state_unchanged": true,
            },
            "nonfinite_input": {
                "before": baseline,
                "after": nonfinite_after,
                "error_code": nonfinite_error.code(),
                "error": nonfinite_error.to_string(),
                "caller_output_bits": nonfinite_out[0].to_bits(),
                "persisted_state_unchanged": true,
            },
            "invalid_selector": {
                "before": baseline,
                "after": selector_after,
                "child_stdout": String::from_utf8(child.stdout)?,
                "child_stderr": String::from_utf8(child.stderr)?,
                "persisted_state_unchanged": true,
            },
        }))
    }

    fn selector_edge_child() -> AnyResult<()> {
        let error = configured_cuda_runtime_ordinal()
            .err()
            .ok_or("invalid CUDA selector was accepted")?;
        require(
            error.code() == "CALYX_CUDA_DEVICE_SELECTOR_INVALID",
            "invalid CUDA selector returned the wrong structured code",
        )?;
        println!(
            "{}",
            serde_json::to_string(&json!({
                "event": "invalid_selector_refused",
                "before": {"cuda_context_created": false},
                "after": {"cuda_context_created": false},
                "error_code": error.code(),
                "error": error.to_string(),
            }))?
        );
        Ok(())
    }

    fn capture_gpu_identity_state(ctx: &CudaContext, output_dir: &Path) -> AnyResult<String> {
        let output = Command::new("nvidia-smi.exe")
            .args([
                "--query-gpu=index,name,uuid,pci.bus_id,driver_version,memory.total,compute_cap",
                "--format=csv,noheader,nounits",
            ])
            .output()?;
        require(
            output.status.success(),
            &format!(
                "nvidia-smi GPU identity query failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ),
        )?;
        let stdout = String::from_utf8(output.stdout)?;
        let identity = ctx.physical_identity();
        let expected_uuid = identity.canonical_uuid();
        let canonical_pci = identity.canonical_pci_bus_id();
        let expanded_pci = format!("0000{canonical_pci}");
        let compute_capability = ctx.compute_capability();
        let expected_compute_capability =
            format!("{}.{}", compute_capability.0, compute_capability.1);
        let rows = parse_nvidia_csv_rows(&stdout, 7, "GPU identity")?;
        let mut matching_rows = 0usize;
        for (line_number, fields) in &rows {
            let ordinal = fields[0].parse::<u32>().map_err(|error| {
                format!(
                    "nvidia-smi GPU row {line_number} has invalid ordinal '{}': {error}",
                    fields[0]
                )
            })?;
            require(
                !fields[1].is_empty()
                    && valid_gpu_uuid(&fields[2])
                    && valid_pci_bus_id(&fields[3])
                    && valid_dotted_decimal(&fields[4])
                    && fields[5].parse::<u64>().is_ok_and(|value| value > 0)
                    && valid_compute_capability(&fields[6]),
                &format!("nvidia-smi GPU row {line_number} has an invalid physical schema"),
            )?;
            if ordinal == ctx.driver_ordinal()
                && fields[1] == ctx.name()
                && fields[2].eq_ignore_ascii_case(&expected_uuid)
                && (fields[3].eq_ignore_ascii_case(&canonical_pci)
                    || fields[3].eq_ignore_ascii_case(&expanded_pci))
                && fields[6] == expected_compute_capability
            {
                matching_rows += 1;
            }
        }
        require(
            matching_rows == 1,
            &format!(
                "nvidia-smi reported {matching_rows} exact selected physical-device rows; expected one uuid={expected_uuid} pci={canonical_pci} name={} driver_ordinal={} compute_capability={expected_compute_capability}",
                ctx.name(),
                ctx.driver_ordinal()
            ),
        )?;
        write_and_verify(&output_dir.join("nvidia-smi-gpu.csv"), stdout.as_bytes())?;
        Ok(stdout)
    }

    fn capture_gpu_process_state(
        ctx: &CudaContext,
        output_dir: &Path,
    ) -> AnyResult<(String, Value)> {
        let output = Command::new("nvidia-smi.exe")
            .args([
                "--query-compute-apps=pid,process_name,gpu_uuid,used_gpu_memory",
                "--format=csv,noheader",
            ])
            .output()?;
        require(
            output.status.success(),
            &format!(
                "nvidia-smi compute-app query failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ),
        )?;
        let stdout = String::from_utf8(output.stdout)?;
        write_and_verify(
            &output_dir.join("nvidia-smi-compute-apps.csv"),
            stdout.as_bytes(),
        )?;
        let expected_pid = std::process::id();
        let expected_executable_path = std::env::current_exe()?;
        let expected_executable = expected_executable_path.to_str().ok_or_else(|| {
            format!(
                "current FSV executable path is not Unicode: {}",
                expected_executable_path.display()
            )
        })?;
        let expected_canonical =
            canonical_existing_windows_file_path(expected_executable, "current FSV executable")?;
        let expected_uuid = ctx.physical_identity().canonical_uuid();
        let rows = parse_nvidia_csv_rows(&stdout, 4, "compute process")?;
        let mut matching_rows = 0usize;
        let mut selected_binding = None;
        for (line_number, fields) in &rows {
            let pid = fields[0].parse::<u32>().map_err(|error| {
                format!(
                    "nvidia-smi compute-process row {line_number} has invalid PID '{}': {error}",
                    fields[0]
                )
            })?;
            require(
                pid > 0
                    && !fields[1].is_empty()
                    && valid_gpu_uuid(&fields[2])
                    && valid_used_gpu_memory(&fields[3]),
                &format!(
                    "nvidia-smi compute-process row {line_number} has an invalid physical schema"
                ),
            )?;
            if pid == expected_pid && fields[2].eq_ignore_ascii_case(&expected_uuid) {
                let observed_canonical = canonical_existing_windows_file_path(
                    &fields[1],
                    &format!("nvidia-smi compute-process row {line_number} executable"),
                )?;
                if observed_canonical == expected_canonical {
                    matching_rows += 1;
                    selected_binding = Some(json!({
                        "schema": "calyx.forge.cuda-kernel-process-binding.v1",
                        "pid": expected_pid,
                        "gpu_uuid": expected_uuid,
                        "source_line": line_number,
                        "expected": {
                            "raw_path": expected_executable,
                            "canonical_path": expected_canonical,
                        },
                        "observed": {
                            "raw_path": fields[1],
                            "canonical_path": observed_canonical,
                        },
                        "canonical_paths_equal": true,
                    }));
                }
            }
        }
        require(
            matching_rows == 1,
            &format!(
                "nvidia-smi reported {matching_rows} exact live FSV process rows; expected one pid={expected_pid} raw_executable={expected_executable} canonical_executable={expected_canonical} gpu_uuid={expected_uuid}"
            ),
        )?;
        let mut binding = selected_binding.ok_or("matched process row has no path binding")?;
        let executable_bytes = fs::read(&expected_canonical)?;
        binding["artifact"] = json!({
            "bytes": executable_bytes.len(),
            "sha256": sha256_hex(&executable_bytes),
        });
        write_json(
            &output_dir.join("nvidia-smi-process-binding.json"),
            &binding,
        )?;
        Ok((stdout, binding))
    }

    fn canonical_existing_windows_file_path(raw: &str, description: &str) -> AnyResult<String> {
        require(
            valid_absolute_windows_file_path(raw),
            &format!(
                "{description} is not one strict absolute ordinary/extended DOS-or-UNC file path: {raw}"
            ),
        )?;
        let canonical = fs::canonicalize(raw).map_err(|error| {
            format!(
                "canonicalize {description} '{raw}' through the Windows file API failed: {error}"
            )
        })?;
        require(
            canonical.is_file(),
            &format!(
                "{description} canonical path is not an existing file: {}",
                canonical.display()
            ),
        )?;
        let canonical = canonical.to_str().ok_or_else(|| {
            format!(
                "{description} canonical path is not Unicode: {}",
                canonical.display()
            )
        })?;
        require(
            valid_canonical_windows_file_path(canonical),
            &format!(
                "{description} canonical path is not an extended-length DOS-or-UNC file path: {canonical}"
            ),
        )?;
        Ok(canonical.to_owned())
    }

    fn valid_absolute_windows_file_path(raw: &str) -> bool {
        if raw.is_empty()
            || raw.contains('/')
            || raw
                .chars()
                .any(|character| character == '\0' || character.is_control())
        {
            return false;
        }
        let display = if let Some(tail) = strip_prefix_ignore_ascii_case(raw, r"\\?\UNC\") {
            format!(r"\\{tail}")
        } else if let Some(tail) = strip_prefix_ignore_ascii_case(raw, r"\\?\") {
            if !valid_drive_absolute_path(tail) {
                return false;
            }
            tail.to_owned()
        } else {
            raw.to_owned()
        };
        if display.starts_with(r"\\.\") || display.starts_with(r"\\?\") || display.ends_with('\\') {
            return false;
        }
        valid_drive_absolute_path(&display) || valid_unc_absolute_path(&display)
    }

    fn valid_canonical_windows_file_path(path: &str) -> bool {
        if let Some(tail) = strip_prefix_ignore_ascii_case(path, r"\\?\UNC\") {
            return valid_unc_absolute_path(&format!(r"\\{tail}"));
        }
        strip_prefix_ignore_ascii_case(path, r"\\?\").is_some_and(valid_drive_absolute_path)
    }

    fn strip_prefix_ignore_ascii_case<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
        value
            .get(..prefix.len())
            .filter(|candidate| candidate.eq_ignore_ascii_case(prefix))
            .map(|_| &value[prefix.len()..])
    }

    fn valid_drive_absolute_path(path: &str) -> bool {
        let bytes = path.as_bytes();
        bytes.len() > 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && bytes[2] == b'\\'
            && valid_windows_components(&path[3..])
    }

    fn valid_unc_absolute_path(path: &str) -> bool {
        let Some(tail) = path.strip_prefix(r"\\") else {
            return false;
        };
        let components = tail.split('\\').collect::<Vec<_>>();
        components.len() >= 3
            && components[0] != "."
            && components[0] != "?"
            && components
                .iter()
                .all(|component| !component.is_empty() && *component != "." && *component != "..")
    }

    fn valid_windows_components(tail: &str) -> bool {
        !tail.is_empty()
            && tail
                .split('\\')
                .all(|component| !component.is_empty() && component != "." && component != "..")
    }

    fn parse_nvidia_csv_rows(
        source: &str,
        expected_fields: usize,
        description: &str,
    ) -> AnyResult<Vec<(usize, Vec<String>)>> {
        require(
            !source.as_bytes().contains(&0),
            &format!("nvidia-smi {description} CSV contains a NUL byte"),
        )?;
        let mut rows = Vec::new();
        for (line_index, line) in source.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let line_number = line_index + 1;
            let fields = parse_nvidia_csv_line(line, line_number, description)?;
            require(
                fields.len() == expected_fields,
                &format!(
                    "nvidia-smi {description} row {line_number} has {} fields, expected {expected_fields}",
                    fields.len()
                ),
            )?;
            require(
                fields.iter().all(|field| {
                    !field.is_empty()
                        && !field
                            .as_bytes()
                            .iter()
                            .any(|byte| matches!(byte, 0 | b'\r' | b'\n'))
                }),
                &format!(
                    "nvidia-smi {description} row {line_number} contains an empty field or forbidden control byte"
                ),
            )?;
            rows.push((line_number, fields));
        }
        require(
            !rows.is_empty(),
            &format!("nvidia-smi {description} CSV contains no physical rows"),
        )?;
        Ok(rows)
    }

    fn parse_nvidia_csv_line(
        line: &str,
        line_number: usize,
        description: &str,
    ) -> AnyResult<Vec<String>> {
        let mut fields = Vec::new();
        let mut field = String::new();
        let mut chars = line.chars().peekable();
        let mut in_quotes = false;
        let mut quote_closed = false;
        while let Some(character) = chars.next() {
            if in_quotes {
                if character == '"' {
                    if chars.peek() == Some(&'"') {
                        chars.next();
                        field.push('"');
                    } else {
                        in_quotes = false;
                        quote_closed = true;
                    }
                } else {
                    field.push(character);
                }
                continue;
            }
            if quote_closed {
                if character == ',' {
                    fields.push(field.trim().to_owned());
                    field.clear();
                    quote_closed = false;
                } else if !character.is_whitespace() {
                    return Err(format!(
                        "nvidia-smi {description} row {line_number} has non-whitespace after a closing quote"
                    )
                    .into());
                }
                continue;
            }
            match character {
                ',' => {
                    fields.push(field.trim().to_owned());
                    field.clear();
                }
                '"' if field.trim().is_empty() => {
                    field.clear();
                    in_quotes = true;
                }
                '"' => {
                    return Err(format!(
                        "nvidia-smi {description} row {line_number} has a quote inside an unquoted field"
                    )
                    .into());
                }
                _ => field.push(character),
            }
        }
        require(
            !in_quotes,
            &format!("nvidia-smi {description} row {line_number} has an unterminated quote"),
        )?;
        fields.push(field.trim().to_owned());
        Ok(fields)
    }

    fn valid_gpu_uuid(value: &str) -> bool {
        let Some(rest) = value.strip_prefix("GPU-") else {
            return false;
        };
        let groups = rest.split('-').collect::<Vec<_>>();
        let expected_lengths = [8usize, 4, 4, 4, 12];
        groups.len() == expected_lengths.len()
            && groups.iter().zip(expected_lengths).all(|(group, length)| {
                group.len() == length && group.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
    }

    fn valid_pci_bus_id(value: &str) -> bool {
        let components = value.split(':').collect::<Vec<_>>();
        if components.len() != 3 {
            return false;
        }
        let domain = components[0];
        let bus = components[1];
        let Some((device, function)) = components[2].split_once('.') else {
            return false;
        };
        matches!(domain.len(), 4 | 8)
            && bus.len() == 2
            && device.len() == 2
            && function.len() == 1
            && domain.bytes().all(|byte| byte.is_ascii_hexdigit())
            && bus.bytes().all(|byte| byte.is_ascii_hexdigit())
            && device.bytes().all(|byte| byte.is_ascii_hexdigit())
            && function.bytes().all(|byte| matches!(byte, b'0'..=b'7'))
    }

    fn valid_dotted_decimal(value: &str) -> bool {
        let components = value.split('.').collect::<Vec<_>>();
        (2..=3).contains(&components.len())
            && components
                .iter()
                .all(|component| !component.is_empty() && component.parse::<u32>().is_ok())
    }

    fn valid_compute_capability(value: &str) -> bool {
        let components = value.split('.').collect::<Vec<_>>();
        components.len() == 2
            && components
                .iter()
                .all(|component| !component.is_empty() && component.parse::<u32>().is_ok())
    }

    fn valid_used_gpu_memory(value: &str) -> bool {
        value == "[N/A]"
            || value
                .strip_suffix(" MiB")
                .is_some_and(|number| number.parse::<u64>().is_ok())
    }

    #[cfg(feature = "cuda-policy-measurement")]
    fn exercise_measurement_matrix(ctx: &CudaContext, output_dir: &Path) -> AnyResult<Value> {
        use calyx_forge::CUDA_KERNEL_MEASUREMENT_ARTIFACTS;

        let artifact_dir = output_dir.join("measurement-artifacts");
        fs::create_dir_all(&artifact_dir)?;
        let mut samples = (0..CUDA_KERNEL_MEASUREMENT_ARTIFACTS.len())
            .map(|_| Vec::with_capacity(MEASUREMENT_ROUNDS))
            .collect::<Vec<Vec<Value>>>();
        for artifact in CUDA_KERNEL_MEASUREMENT_ARTIFACTS {
            let label = format!(
                "{}.fmad-{}.{}",
                artifact.module_name,
                if artifact.fmad { "on" } else { "off" },
                artifact.module_kind
            );
            write_and_verify(&artifact_dir.join(&label), artifact.bytes)?;
        }
        for round in 0..MEASUREMENT_ROUNDS {
            let mut order = (0..CUDA_KERNEL_MEASUREMENT_ARTIFACTS.len()).collect::<Vec<_>>();
            let order_len = order.len();
            order.rotate_left((round * 5) % order_len);
            if !round.is_multiple_of(2) {
                order.reverse();
            }
            for (order_index, artifact_index) in order.into_iter().enumerate() {
                let artifact = &CUDA_KERNEL_MEASUREMENT_ARTIFACTS[artifact_index];
                let mut measurement = match artifact.module_name {
                    "distance" => measure_distance_artifact(ctx, artifact)?,
                    "topk" => measure_topk_artifact(ctx, artifact)?,
                    "mxfp_gemm" => measure_mxfp_artifact(ctx, artifact)?,
                    other => return Err(format!("unknown measurement kernel set {other}").into()),
                };
                let object = measurement
                    .as_object_mut()
                    .ok_or("measurement sample is not a JSON object")?;
                object.insert("round".to_string(), json!(round));
                object.insert("order_index".to_string(), json!(order_index));
                samples[artifact_index].push(measurement);
            }
        }
        let measurements = CUDA_KERNEL_MEASUREMENT_ARTIFACTS
            .iter()
            .zip(&samples)
            .map(|(artifact, samples)| aggregate_measurement(artifact, samples))
            .collect::<AnyResult<Vec<_>>>()?;
        let value = json!({
            "enabled": true,
            "rounds": MEASUREMENT_ROUNDS,
            "warm_runs": WARM_RUNS,
            "ordering": "round-robin-rotated-and-reversed-v1",
            "artifacts": measurements,
        });
        write_json(&output_dir.join("measurement.json"), &value)?;
        Ok(value)
    }

    #[cfg(feature = "cuda-policy-measurement")]
    fn aggregate_measurement(
        artifact: &calyx_forge::CudaKernelMeasurementArtifact,
        samples: &[Value],
    ) -> AnyResult<Value> {
        require(
            samples.len() == MEASUREMENT_ROUNDS,
            "measurement aggregate has the wrong sample count",
        )?;
        let first = samples
            .first()
            .ok_or("measurement aggregate has no samples")?;
        let output_bytes = value_u64(first, "output_bytes")?;
        let output_sha256 = value_str(first, "output_sha256")?;
        let output_hex = value_str(first, "output_hex")?;
        let max_abs_error_f64 = value_f64(first, "max_abs_error_f64")?;
        let max_abs_error_bound_f64 = value_f64(first, "max_abs_error_bound_f64")?;
        for sample in samples {
            require(
                value_str(sample, "artifact_sha256")? == sha256_hex(artifact.bytes)
                    && value_u64(sample, "artifact_bytes")? == u64::try_from(artifact.bytes.len())?
                    && value_u64(sample, "output_bytes")? == output_bytes
                    && value_str(sample, "output_sha256")? == output_sha256
                    && value_str(sample, "output_hex")? == output_hex
                    && value_bool(sample, "correctness_verified")?
                    && value_f64(sample, "max_abs_error_f64")? == max_abs_error_f64
                    && value_f64(sample, "max_abs_error_bound_f64")? == max_abs_error_bound_f64,
                "repeated measurement changed artifact, output, or numerical evidence",
            )?;
        }
        let sample_order = samples
            .iter()
            .map(|sample| {
                Ok(json!({
                    "round": value_u64(sample, "round")?,
                    "order_index": value_u64(sample, "order_index")?,
                }))
            })
            .collect::<AnyResult<Vec<_>>>()?;
        Ok(json!({
            "module_name": artifact.module_name,
            "module_kind": artifact.module_kind,
            "fmad": artifact.fmad,
            "artifact_bytes": artifact.bytes.len(),
            "artifact_sha256": sha256_hex(artifact.bytes),
            "output_bytes": output_bytes,
            "output_sha256": output_sha256,
            "output_hex": output_hex,
            "correctness_verified": true,
            "max_abs_error_f64": max_abs_error_f64,
            "max_abs_error_bound_f64": max_abs_error_bound_f64,
            "module_load_ns": samples.iter()
                .map(|sample| value_u64(sample, "module_load_ns"))
                .collect::<AnyResult<Vec<_>>>()?,
            "function_load_ns": samples.iter()
                .map(|sample| value_u64(sample, "function_load_ns"))
                .collect::<AnyResult<Vec<_>>>()?,
            "first_dispatch_ns": samples.iter()
                .map(|sample| value_u64(sample, "first_dispatch_ns"))
                .collect::<AnyResult<Vec<_>>>()?,
            "warm_runs": WARM_RUNS,
            "warm_total_ns": samples.iter()
                .map(|sample| value_u64(sample, "warm_total_ns"))
                .collect::<AnyResult<Vec<_>>>()?,
            "sample_order": sample_order,
        }))
    }

    #[cfg(feature = "cuda-policy-measurement")]
    fn load_measurement_module(
        ctx: &CudaContext,
        artifact: &calyx_forge::CudaKernelMeasurementArtifact,
    ) -> AnyResult<(std::sync::Arc<cudarc::driver::CudaModule>, u64)> {
        let ptx = match artifact.module_kind {
            "ptx" => Ptx::from_src(std::str::from_utf8(artifact.bytes)?),
            "cubin" => Ptx::from_binary(artifact.bytes.to_vec()),
            other => return Err(format!("unsupported measurement module kind {other}").into()),
        };
        let started = Instant::now();
        let module = ctx.inner().load_module(ptx)?;
        Ok((module, elapsed_ns(started)?))
    }

    #[cfg(feature = "cuda-policy-measurement")]
    fn measure_distance_artifact(
        ctx: &CudaContext,
        artifact: &calyx_forge::CudaKernelMeasurementArtifact,
    ) -> AnyResult<Value> {
        const DIM: usize = 4096;
        const CANDIDATES: usize = 128;
        let query = (0..DIM)
            .map(|index| {
                let byte = include_bytes!("../src/cuda/kernels/distance.cu")
                    [index % include_bytes!("../src/cuda/kernels/distance.cu").len()];
                (f32::from(byte) - 127.5) / 127.5
            })
            .collect::<Vec<_>>();
        let candidates = (0..CANDIDATES * DIM)
            .map(|index| {
                let byte = include_bytes!("../src/cuda/kernels/topk.cu")[(index * 17
                    + index / DIM)
                    % include_bytes!("../src/cuda/kernels/topk.cu").len()];
                (f32::from(byte) - 127.5) / 127.5
            })
            .collect::<Vec<_>>();
        let stream = ctx.inner().default_stream();
        let query_dev = stream.clone_htod(&query)?;
        let candidates_dev = stream.clone_htod(&candidates)?;
        let mut out = stream.alloc_zeros(CANDIDATES)?;
        let (module, module_load_ns) = load_measurement_module(ctx, artifact)?;
        let function_started = Instant::now();
        let function = module.load_function("dot_batch_f32")?;
        let function_load_ns = elapsed_ns(function_started)?;
        let dim = DIM as i32;
        let candidates_count = CANDIDATES as i32;
        let config = LaunchConfig {
            grid_dim: (CANDIDATES as u32, 1, 1),
            block_dim: (256, 1, 1),
            shared_mem_bytes: 0,
        };
        let first_started = Instant::now();
        launch_distance(
            &stream,
            &function,
            &query_dev,
            &candidates_dev,
            &dim,
            &candidates_count,
            &mut out,
            config,
        )?;
        stream.synchronize()?;
        let first_dispatch_ns = elapsed_ns(first_started)?;
        let warm_started = Instant::now();
        for _ in 0..WARM_RUNS {
            launch_distance(
                &stream,
                &function,
                &query_dev,
                &candidates_dev,
                &dim,
                &candidates_count,
                &mut out,
                config,
            )?;
            stream.synchronize()?;
        }
        let warm_total_ns = elapsed_ns(warm_started)?;
        let observed = stream.clone_dtoh(&out)?;
        require(
            observed.iter().all(|value| value.is_finite()),
            "measurement distance output is non-finite",
        )?;
        let unit_roundoff = f64::from(f32::EPSILON) / 2.0;
        let operation_count = (2 * DIM) as f64;
        let gamma = (operation_count * unit_roundoff) / (1.0 - operation_count * unit_roundoff);
        let mut max_abs_error_f64 = 0.0_f64;
        let mut max_abs_error_bound_f64 = 0.0_f64;
        for (candidate_index, observed) in observed.iter().enumerate() {
            let row = &candidates[candidate_index * DIM..(candidate_index + 1) * DIM];
            let reference = query
                .iter()
                .zip(row)
                .map(|(left, right)| f64::from(*left) * f64::from(*right))
                .sum::<f64>();
            let absolute_product_sum = query
                .iter()
                .zip(row)
                .map(|(left, right)| (f64::from(*left) * f64::from(*right)).abs())
                .sum::<f64>();
            let error = (f64::from(*observed) - reference).abs();
            let bound = gamma * absolute_product_sum;
            require(
                error <= bound,
                &format!(
                    "measurement distance output exceeds the derived IEEE-754 forward-error bound at candidate {candidate_index}: error={error} bound={bound}"
                ),
            )?;
            max_abs_error_f64 = max_abs_error_f64.max(error);
            max_abs_error_bound_f64 = max_abs_error_bound_f64.max(bound);
        }
        Ok(measurement_json(
            artifact,
            module_load_ns,
            function_load_ns,
            first_dispatch_ns,
            warm_total_ns,
            &f32_bytes(&observed),
            max_abs_error_f64,
            max_abs_error_bound_f64,
        ))
    }

    #[cfg(feature = "cuda-policy-measurement")]
    fn launch_distance(
        stream: &std::sync::Arc<cudarc::driver::CudaStream>,
        function: &cudarc::driver::CudaFunction,
        query: &cudarc::driver::CudaSlice<f32>,
        candidates: &cudarc::driver::CudaSlice<f32>,
        dim: &i32,
        count: &i32,
        out: &mut cudarc::driver::CudaSlice<f32>,
        config: LaunchConfig,
    ) -> AnyResult<()> {
        let mut launch = stream.launch_builder(function);
        unsafe {
            launch
                .arg(query)
                .arg(candidates)
                .arg(dim)
                .arg(count)
                .arg(out)
                .launch(config)?;
        }
        Ok(())
    }

    #[cfg(feature = "cuda-policy-measurement")]
    fn measure_topk_artifact(
        ctx: &CudaContext,
        artifact: &calyx_forge::CudaKernelMeasurementArtifact,
    ) -> AnyResult<Value> {
        const COUNT: usize = 1024;
        const K: usize = 32;
        let scores = (0..COUNT)
            .map(|index| ((index * 37) % 97) as f32 - 48.0)
            .collect::<Vec<_>>();
        let stream = ctx.inner().default_stream();
        let scores_dev = stream.clone_htod(&scores)?;
        let mut indices = stream.alloc_zeros(K)?;
        let mut values = stream.alloc_zeros(K)?;
        let (module, module_load_ns) = load_measurement_module(ctx, artifact)?;
        let function_started = Instant::now();
        let function = module.load_function("bitonic_topk_f32")?;
        let function_load_ns = elapsed_ns(function_started)?;
        let count = COUNT as i32;
        let k = K as i32;
        let config = LaunchConfig {
            grid_dim: (1, 1, 1),
            block_dim: (1024, 1, 1),
            shared_mem_bytes: 0,
        };
        let first_started = Instant::now();
        launch_topk(
            &stream,
            &function,
            &scores_dev,
            &count,
            &k,
            &mut indices,
            &mut values,
            config,
        )?;
        stream.synchronize()?;
        let first_dispatch_ns = elapsed_ns(first_started)?;
        let warm_started = Instant::now();
        for _ in 0..WARM_RUNS {
            launch_topk(
                &stream,
                &function,
                &scores_dev,
                &count,
                &k,
                &mut indices,
                &mut values,
                config,
            )?;
            stream.synchronize()?;
        }
        let warm_total_ns = elapsed_ns(warm_started)?;
        let observed_indices = stream.clone_dtoh(&indices)?;
        let observed_values = stream.clone_dtoh(&values)?;
        let mut expected = scores.iter().copied().enumerate().collect::<Vec<_>>();
        expected.sort_by(|left, right| {
            right
                .1
                .total_cmp(&left.1)
                .then_with(|| left.0.cmp(&right.0))
        });
        expected.truncate(K);
        require(
            observed_indices.len() == K && observed_values.len() == K,
            "measurement top-k returned the wrong output cardinality",
        )?;
        for (rank, ((observed_index, observed_value), (expected_index, expected_value))) in
            observed_indices
                .iter()
                .zip(&observed_values)
                .zip(&expected)
                .enumerate()
        {
            require(
                *observed_index >= 0
                    && usize::try_from(*observed_index)? == *expected_index
                    && observed_value.to_bits() == expected_value.to_bits(),
                &format!(
                    "measurement top-k mismatch at rank {rank}: observed=({observed_index},{observed_value}) expected=({expected_index},{expected_value})"
                ),
            )?;
        }
        let mut output = Vec::new();
        for (index, value) in observed_indices.iter().zip(&observed_values) {
            output.extend_from_slice(&index.to_le_bytes());
            output.extend_from_slice(&value.to_bits().to_le_bytes());
        }
        Ok(measurement_json(
            artifact,
            module_load_ns,
            function_load_ns,
            first_dispatch_ns,
            warm_total_ns,
            &output,
            0.0,
            0.0,
        ))
    }

    #[cfg(feature = "cuda-policy-measurement")]
    #[allow(clippy::too_many_arguments)]
    fn launch_topk(
        stream: &std::sync::Arc<cudarc::driver::CudaStream>,
        function: &cudarc::driver::CudaFunction,
        scores: &cudarc::driver::CudaSlice<f32>,
        count: &i32,
        k: &i32,
        indices: &mut cudarc::driver::CudaSlice<i32>,
        values: &mut cudarc::driver::CudaSlice<f32>,
        config: LaunchConfig,
    ) -> AnyResult<()> {
        let mut launch = stream.launch_builder(function);
        unsafe {
            launch
                .arg(scores)
                .arg(count)
                .arg(k)
                .arg(indices)
                .arg(values)
                .launch(config)?;
        }
        Ok(())
    }

    #[cfg(feature = "cuda-policy-measurement")]
    fn measure_mxfp_artifact(
        ctx: &CudaContext,
        artifact: &calyx_forge::CudaKernelMeasurementArtifact,
    ) -> AnyResult<Value> {
        let (a, b, expected) = mx_matrices(MX_M, MX_K, MX_N);
        let a_blocks = pack_mxfp4_a_row_major(&a, MX_M, MX_K)?;
        let b_blocks = pack_mxfp4_b_column_major(&b, MX_K, MX_N)?;
        let a_codes = a_blocks
            .iter()
            .flat_map(|block| block.codes)
            .collect::<Vec<_>>();
        let a_scales = a_blocks
            .iter()
            .map(|block| block.scale_e8m0)
            .collect::<Vec<_>>();
        let b_codes = b_blocks
            .iter()
            .flat_map(|block| block.codes)
            .collect::<Vec<_>>();
        let b_scales = b_blocks
            .iter()
            .map(|block| block.scale_e8m0)
            .collect::<Vec<_>>();
        let stream = ctx.inner().default_stream();
        let a_codes = stream.clone_htod(&a_codes)?;
        let a_scales = stream.clone_htod(&a_scales)?;
        let b_codes = stream.clone_htod(&b_codes)?;
        let b_scales = stream.clone_htod(&b_scales)?;
        let mut output = stream.alloc_zeros(MX_M * MX_N)?;
        let mut status = stream.alloc_zeros(1)?;
        let (module, module_load_ns) = load_measurement_module(ctx, artifact)?;
        let function_started = Instant::now();
        let function = module.load_function("gemm_mxfp4_e2m1_fp32_accum_kernel")?;
        let function_load_ns = elapsed_ns(function_started)?;
        let dims = [
            MX_M as u32,
            MX_K as u32,
            MX_N as u32,
            MX_K.div_ceil(32) as u32,
        ];
        let config = LaunchConfig {
            grid_dim: (MX_N.div_ceil(8) as u32, MX_M.div_ceil(16) as u32, 1),
            block_dim: (32, 1, 1),
            shared_mem_bytes: 0,
        };
        let first_started = Instant::now();
        launch_mxfp(
            &stream,
            &function,
            &a_codes,
            &a_scales,
            &b_codes,
            &b_scales,
            &dims,
            &mut output,
            &mut status,
            config,
        )?;
        stream.synchronize()?;
        let first_dispatch_ns = elapsed_ns(first_started)?;
        let warm_started = Instant::now();
        for _ in 0..WARM_RUNS {
            launch_mxfp(
                &stream,
                &function,
                &a_codes,
                &a_scales,
                &b_codes,
                &b_scales,
                &dims,
                &mut output,
                &mut status,
                config,
            )?;
            stream.synchronize()?;
        }
        let warm_total_ns = elapsed_ns(warm_started)?;
        let observed_status = stream.clone_dtoh(&status)?;
        require(
            observed_status == [0],
            "measurement MXFP status is non-zero",
        )?;
        let observed = stream.clone_dtoh(&output)?;
        require_f32_bits("measurement MXFP4", &observed, &expected)?;
        Ok(measurement_json(
            artifact,
            module_load_ns,
            function_load_ns,
            first_dispatch_ns,
            warm_total_ns,
            &f32_bytes(&observed),
            0.0,
            0.0,
        ))
    }

    #[cfg(feature = "cuda-policy-measurement")]
    #[allow(clippy::too_many_arguments)]
    fn launch_mxfp(
        stream: &std::sync::Arc<cudarc::driver::CudaStream>,
        function: &cudarc::driver::CudaFunction,
        a_codes: &cudarc::driver::CudaSlice<u8>,
        a_scales: &cudarc::driver::CudaSlice<u8>,
        b_codes: &cudarc::driver::CudaSlice<u8>,
        b_scales: &cudarc::driver::CudaSlice<u8>,
        dims: &[u32; 4],
        output: &mut cudarc::driver::CudaSlice<f32>,
        status: &mut cudarc::driver::CudaSlice<u32>,
        config: LaunchConfig,
    ) -> AnyResult<()> {
        let mut launch = stream.launch_builder(function);
        unsafe {
            launch
                .arg(a_codes)
                .arg(a_scales)
                .arg(b_codes)
                .arg(b_scales)
                .arg(&dims[0])
                .arg(&dims[1])
                .arg(&dims[2])
                .arg(&dims[3])
                .arg(output)
                .arg(status)
                .launch(config)?;
        }
        Ok(())
    }

    #[cfg(feature = "cuda-policy-measurement")]
    fn measurement_json(
        artifact: &calyx_forge::CudaKernelMeasurementArtifact,
        module_load_ns: u64,
        function_load_ns: u64,
        first_dispatch_ns: u64,
        warm_total_ns: u64,
        output: &[u8],
        max_abs_error_f64: f64,
        max_abs_error_bound_f64: f64,
    ) -> Value {
        json!({
            "module_name": artifact.module_name,
            "module_kind": artifact.module_kind,
            "fmad": artifact.fmad,
            "artifact_bytes": artifact.bytes.len(),
            "artifact_sha256": sha256_hex(artifact.bytes),
            "module_load_ns": module_load_ns,
            "function_load_ns": function_load_ns,
            "first_dispatch_ns": first_dispatch_ns,
            "warm_runs": WARM_RUNS,
            "warm_total_ns": warm_total_ns,
            "warm_ns_per_run": warm_total_ns as f64 / WARM_RUNS as f64,
            "output_bytes": output.len(),
            "output_sha256": sha256_hex(output),
            "output_hex": hex(output),
            "correctness_verified": true,
            "max_abs_error_f64": max_abs_error_f64,
            "max_abs_error_bound_f64": max_abs_error_bound_f64,
        })
    }

    #[cfg(feature = "cuda-policy-measurement")]
    fn value_u64(value: &Value, field: &str) -> AnyResult<u64> {
        value
            .get(field)
            .and_then(Value::as_u64)
            .ok_or_else(|| format!("measurement field {field} is not a u64").into())
    }

    #[cfg(feature = "cuda-policy-measurement")]
    fn value_f64(value: &Value, field: &str) -> AnyResult<f64> {
        value
            .get(field)
            .and_then(Value::as_f64)
            .filter(|number| number.is_finite())
            .ok_or_else(|| format!("measurement field {field} is not a finite f64").into())
    }

    #[cfg(feature = "cuda-policy-measurement")]
    fn value_str<'a>(value: &'a Value, field: &str) -> AnyResult<&'a str> {
        value
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("measurement field {field} is not a string").into())
    }

    #[cfg(feature = "cuda-policy-measurement")]
    fn value_bool(value: &Value, field: &str) -> AnyResult<bool> {
        value
            .get(field)
            .and_then(Value::as_bool)
            .ok_or_else(|| format!("measurement field {field} is not a boolean").into())
    }

    fn mx_matrices(m: usize, k: usize, n: usize) -> (Vec<f32>, Vec<f32>, Vec<f32>) {
        let mut a = vec![0.0_f32; m * k];
        for row in 0..m {
            for depth in 0..k {
                a[row * k + depth] = if (row + depth).is_multiple_of(2) {
                    1.0
                } else {
                    -1.0
                };
            }
        }
        let mut b = vec![0.0_f32; n * k];
        for column in 0..n {
            for depth in 0..k {
                b[column * k + depth] = if (column + depth).is_multiple_of(2) {
                    1.0
                } else {
                    -1.0
                };
            }
        }
        let mut expected = vec![0.0_f32; m * n];
        for column in 0..n {
            for row in 0..m {
                expected[column * m + row] = if (row + column).is_multiple_of(2) {
                    k as f32
                } else {
                    -(k as f32)
                };
            }
        }
        (a, b, expected)
    }

    fn write_json(path: &Path, value: &Value) -> AnyResult<()> {
        write_and_verify(path, &serde_json::to_vec_pretty(value)?)
    }

    fn write_and_verify(path: &Path, bytes: &[u8]) -> AnyResult<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, bytes)?;
        let readback = fs::read(path)?;
        require(
            readback == bytes,
            &format!("readback mismatch for {}", path.display()),
        )
    }

    fn inventory(root: &Path) -> AnyResult<BTreeMap<String, String>> {
        let mut result = BTreeMap::new();
        let mut pending = vec![root.to_path_buf()];
        while let Some(directory) = pending.pop() {
            for entry in fs::read_dir(&directory)? {
                let path = entry?.path();
                if path.is_dir() {
                    pending.push(path);
                } else {
                    let relative = path
                        .strip_prefix(root)?
                        .to_string_lossy()
                        .replace('\\', "/");
                    result.insert(relative, sha256_hex(&fs::read(path)?));
                }
            }
        }
        Ok(result)
    }

    fn require_f32_bits(label: &str, actual: &[f32], expected: &[f32]) -> AnyResult<()> {
        require(
            actual.len() == expected.len(),
            &format!("{label} length mismatch"),
        )?;
        for (index, (actual, expected)) in actual.iter().zip(expected).enumerate() {
            require(
                actual.to_bits() == expected.to_bits(),
                &format!(
                    "{label} bit mismatch at {index}: expected={expected} ({:08x}) observed={actual} ({:08x})",
                    expected.to_bits(),
                    actual.to_bits()
                ),
            )?;
        }
        Ok(())
    }

    fn f32_bytes(values: &[f32]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(values.len() * 4);
        append_f32(&mut bytes, values);
        bytes
    }

    fn append_f32(bytes: &mut Vec<u8>, values: &[f32]) {
        for value in values {
            bytes.extend_from_slice(&value.to_bits().to_le_bytes());
        }
    }

    fn elapsed_ns(started: Instant) -> AnyResult<u64> {
        u64::try_from(started.elapsed().as_nanos())
            .map_err(|_| "monotonic elapsed nanoseconds exceeded u64".into())
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn require(condition: bool, message: &str) -> AnyResult<()> {
        if condition {
            Ok(())
        } else {
            Err(message.into())
        }
    }
}

#[cfg(feature = "cuda")]
fn main() {
    if let Err(error) = enabled::run() {
        eprintln!("CALYX_FORGE_CUDA_FSV_FAILED: {error}");
        std::process::exit(1);
    }
}
