use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use calyx_forge::{
    AssayQuantSafety, MXFP4_BLOCK_SIZE, MXFP4_MAX_DIM, MXFP8_BLOCK_SIZE, MxFp4Block, MxFp4Codec,
    MxFp8Block, MxFp8Codec, QuantLevel, Quantizer, decode_e4m3, decode_mxfp4_block, encode_mxfp4,
    encode_mxfp4_block, encode_mxfp8, encode_mxfp8_block, gemm_mxfp4_packed, gemm_mxfp8_packed,
    validate_mxfp4_blocks, validate_mxfp8_blocks,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[cfg(feature = "cuda")]
use calyx_forge::{
    MxFp4GemmPlan, MxFp8GemmPlan, init_cuda_native_kernel, pack_mxfp4_a_row_major,
    pack_mxfp4_b_column_major, pack_mxfp8_a_row_major, pack_mxfp8_b_column_major,
};

const M: usize = 16;
const K: usize = 64;
const N: usize = 8;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output_dir = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("usage: mxfp_artifact <output-directory>")?;
    fs::create_dir_all(&output_dir)?;

    let boundary = boundary_vectors(&output_dir)?;
    let (a, b, expected) = known_matrices();
    let a4 = pack_rows_fp4(&a, M, K)?;
    let b4 = pack_rows_fp4(&b, N, K)?;
    let a8 = pack_rows_fp8(&a, M, K)?;
    let b8 = pack_rows_fp8(&b, N, K)?;
    let mut cpu4 = vec![0.0_f32; M * N];
    let mut cpu8 = vec![0.0_f32; M * N];
    gemm_mxfp4_packed(&a4, &b4, M, K, N, &mut cpu4)?;
    gemm_mxfp8_packed(&a8, &b8, M, K, N, &mut cpu8)?;
    require_exact("CPU MXFP4", &cpu4, &expected)?;
    require_exact("CPU MXFP8", &cpu8, &expected)?;
    write_f32_le(&output_dir.join("cpu_mxfp4_output.f32le"), &cpu4)?;
    write_f32_le(&output_dir.join("cpu_mxfp8_output.f32le"), &cpu8)?;

    let throughput = measure_cpu_throughput()?;
    let edges = exercise_edges(&output_dir)?;

    #[cfg(feature = "cuda")]
    let gpu = exercise_gpu(&output_dir, &a, &b, &expected)?;
    #[cfg(not(feature = "cuda"))]
    let gpu = json!({"compiled": false});

    let report = json!({
        "schema": "calyx.forge.mxfp_artifact.v1",
        "execution": execution_evidence()?,
        "source_of_truth": {
            "packed_boundary_files": ["mxfp4_boundary.block", "mxfp8_boundary.block"],
            "payload_files": ["mxfp4_payload.mxoc", "mxfp8_payload.mxoc"],
            "cpu_output_files": ["cpu_mxfp4_output.f32le", "cpu_mxfp8_output.f32le"],
            "gpu_output_files": if cfg!(feature = "cuda") {
                json!(["gpu_mxfp4_output.f32le", "gpu_mxfp8_output.f32le", "mxfp_gemm.cubin"])
            } else {
                json!([])
            },
        },
        "boundary": boundary,
        "known_matrix": {"m": M, "k": K, "n": N, "expected": expected},
        "cpu": {"mxfp4_output": cpu4, "mxfp8_output": cpu8, "throughput": throughput},
        "gpu": gpu,
        "edges": edges,
    });
    let report_bytes = serde_json::to_vec_pretty(&report)?;
    write_and_verify(&output_dir.join("report.json"), &report_bytes)?;
    println!(
        "{}",
        String::from_utf8(fs::read(output_dir.join("report.json"))?)?
    );
    Ok(())
}

fn boundary_vectors(output_dir: &Path) -> Result<Value, Box<dyn std::error::Error>> {
    let pattern = [
        0.0, 0.5, 1.0, 1.5, 2.0, 3.0, 4.0, 6.0, 0.0, -0.5, -1.0, -1.5, -2.0, -3.0, -4.0, -6.0,
    ];
    let mut fp4_values = [0.0_f32; MXFP4_BLOCK_SIZE];
    fp4_values[..16].copy_from_slice(&pattern);
    fp4_values[16..].copy_from_slice(&pattern);
    let fp4 = encode_mxfp4_block(&fp4_values)?;
    let expected_fp4_codes = [
        0x10, 0x32, 0x54, 0x76, 0x90, 0xba, 0xdc, 0xfe, 0x10, 0x32, 0x54, 0x76, 0x90, 0xba, 0xdc,
        0xfe,
    ];
    if fp4.scale_e8m0 != 0x7f || fp4.codes != expected_fp4_codes {
        return Err(format!(
            "MXFP4 OCP boundary mismatch: scale={:02x} codes={:02x?}",
            fp4.scale_e8m0, fp4.codes
        )
        .into());
    }
    let mut fp4_file = fp4.codes.to_vec();
    fp4_file.push(fp4.scale_e8m0);
    write_and_verify(&output_dir.join("mxfp4_boundary.block"), &fp4_file)?;

    let mut fp8_values = [0.0_f32; MXFP8_BLOCK_SIZE];
    fp8_values[..8].copy_from_slice(&[
        0.0,
        2.0_f32.powi(-9),
        1.0,
        -1.0,
        256.0,
        -256.0,
        448.0,
        -448.0,
    ]);
    let fp8 = encode_mxfp8_block(&fp8_values)?;
    let expected_fp8_prefix = [0x00, 0x01, 0x38, 0xb8, 0x78, 0xf8, 0x7e, 0xfe];
    if fp8.scale_e8m0 != 0x7f || fp8.codes[..8] != expected_fp8_prefix {
        return Err(format!(
            "MXFP8 OCP boundary mismatch: scale={:02x} codes={:02x?}",
            fp8.scale_e8m0,
            &fp8.codes[..8]
        )
        .into());
    }
    let mut fp8_file = fp8.codes.to_vec();
    fp8_file.push(fp8.scale_e8m0);
    write_and_verify(&output_dir.join("mxfp8_boundary.block"), &fp8_file)?;

    let safety = AssayQuantSafety {
        baseline_bits: 1.0,
        quantized_bits: 1.0,
        cosine: 1.0,
        far_delta: 0.0,
    };
    let fp4_payload = MxFp4Codec::new(MXFP4_BLOCK_SIZE).encode_assay_checked(
        "fsv:ocp-boundary",
        &fp4_values,
        &safety,
        [0x5a; 32],
    )?;
    let fp8_payload = MxFp8Codec::new(MXFP8_BLOCK_SIZE).encode(&fp8_values)?;
    write_and_verify(&output_dir.join("mxfp4_payload.mxoc"), &fp4_payload.bytes)?;
    write_and_verify(&output_dir.join("mxfp8_payload.mxoc"), &fp8_payload.bytes)?;

    let mut fp4_rne_values = [0.0_f32; MXFP4_BLOCK_SIZE];
    fp4_rne_values[0] = 1.25;
    fp4_rne_values[1] = 1.75;
    fp4_rne_values[MXFP4_BLOCK_SIZE - 1] = 6.0;
    let fp4_rne = decode_mxfp4_block(&encode_mxfp4_block(&fp4_rne_values)?)?;
    if fp4_rne[0].to_bits() != 1.0_f32.to_bits() || fp4_rne[1].to_bits() != 2.0_f32.to_bits() {
        return Err(format!(
            "MXFP4 RNE boundary mismatch: 1.25 -> {}, 1.75 -> {}",
            fp4_rne[0], fp4_rne[1]
        )
        .into());
    }
    let mut fp8_rne_values = [0.0_f32; MXFP8_BLOCK_SIZE];
    fp8_rne_values[0] = 1.0625;
    fp8_rne_values[1] = 1.1875;
    fp8_rne_values[MXFP8_BLOCK_SIZE - 1] = 448.0;
    let fp8_rne_block = encode_mxfp8_block(&fp8_rne_values)?;
    let fp8_rne = [
        decode_e4m3(fp8_rne_block.codes[0])?,
        decode_e4m3(fp8_rne_block.codes[1])?,
    ];
    if fp8_rne[0].to_bits() != 1.0_f32.to_bits() || fp8_rne[1].to_bits() != 1.25_f32.to_bits() {
        return Err(format!(
            "MXFP8 RNE boundary mismatch: 1.0625 -> {}, 1.1875 -> {}",
            fp8_rne[0], fp8_rne[1]
        )
        .into());
    }

    Ok(json!({
        "mxfp4": {
            "codes_hex": hex(&fp4.codes),
            "scale_hex": format!("{:02x}", fp4.scale_e8m0),
            "payload_bytes": fp4_payload.bytes.len(),
            "payload_sha256": sha256_hex(&fp4_payload.bytes)
        },
        "mxfp8": {
            "codes_prefix_hex": hex(&fp8.codes[..8]),
            "scale_hex": format!("{:02x}", fp8.scale_e8m0),
            "payload_bytes": fp8_payload.bytes.len(),
            "payload_sha256": sha256_hex(&fp8_payload.bytes)
        },
        "rne": {
            "scale_forced_to_one_by_block_max": true,
            "e2m1_1_25": fp4_rne[0],
            "e2m1_1_75": fp4_rne[1],
            "e4m3_1_0625": fp8_rne[0],
            "e4m3_1_1875": fp8_rne[1],
        }
    }))
}

fn known_matrices() -> (Vec<f32>, Vec<f32>, Vec<f32>) {
    let mut a = vec![0.0_f32; M * K];
    for row in 0..M {
        for depth in 0..K {
            a[row * K + depth] = if (row + depth).is_multiple_of(2) {
                1.0
            } else {
                -1.0
            };
        }
    }
    let mut b = vec![0.0_f32; N * K];
    for col in 0..N {
        for depth in 0..K {
            b[col * K + depth] = if (col + depth).is_multiple_of(2) {
                1.0
            } else {
                -1.0
            };
        }
    }
    let mut expected = vec![0.0_f32; M * N];
    for col in 0..N {
        for row in 0..M {
            expected[col * M + row] = if (row + col).is_multiple_of(2) {
                K as f32
            } else {
                -(K as f32)
            };
        }
    }
    (a, b, expected)
}

fn measure_cpu_throughput() -> Result<Value, Box<dyn std::error::Error>> {
    const VALUES: usize = 1 << 18;
    let input = (0..VALUES)
        .map(|index| if index.is_multiple_of(2) { 1.0 } else { -1.0 })
        .collect::<Vec<_>>();
    let start = Instant::now();
    let encoded = encode_mxfp4(&input)?;
    let encode_elapsed = start.elapsed();

    const BM: usize = 128;
    const BK: usize = 256;
    const BN: usize = 128;
    let a_blocks = pack_rows_fp4(&vec![1.0_f32; BM * BK], BM, BK)?;
    let b_blocks = pack_rows_fp4(&vec![1.0_f32; BN * BK], BN, BK)?;
    let mut out = vec![0.0_f32; BM * BN];
    let start = Instant::now();
    gemm_mxfp4_packed(&a_blocks, &b_blocks, BM, BK, BN, &mut out)?;
    let gemm_elapsed = start.elapsed();
    if out.iter().any(|value| *value != BK as f32) {
        return Err("CPU throughput GEMM output mismatch".into());
    }
    Ok(json!({
        "conversion_values": VALUES,
        "conversion_blocks": encoded.len(),
        "conversion_seconds": encode_elapsed.as_secs_f64(),
        "conversion_values_per_second": VALUES as f64 / encode_elapsed.as_secs_f64(),
        "gemm_shape": [BM, BK, BN],
        "gemm_seconds": gemm_elapsed.as_secs_f64(),
        "gemm_gflops": (2.0 * BM as f64 * BK as f64 * BN as f64)
            / gemm_elapsed.as_secs_f64() / 1.0e9,
    }))
}

fn exercise_edges(output_dir: &Path) -> Result<Value, Box<dyn std::error::Error>> {
    let before = file_names(output_dir)?;
    let empty_error = encode_mxfp4(&[]).unwrap_err().to_string();
    let after_empty = file_names(output_dir)?;
    ensure_unchanged("empty", &before, &after_empty)?;

    let invalid_scale = MxFp4Block {
        codes: [0; 16],
        scale_e8m0: 0xff,
    };
    let invalid_scale_error = validate_mxfp4_blocks(&[invalid_scale], 32)
        .unwrap_err()
        .to_string();
    let after_invalid_scale = file_names(output_dir)?;
    ensure_unchanged("invalid scale", &before, &after_invalid_scale)?;

    let mut invalid_padding = MxFp8Block {
        codes: [0; 32],
        scale_e8m0: 0,
    };
    invalid_padding.codes[31] = 0x38;
    let invalid_padding_error = validate_mxfp8_blocks(&[invalid_padding], 31)
        .unwrap_err()
        .to_string();
    let after_invalid_padding = file_names(output_dir)?;
    ensure_unchanged("padding", &before, &after_invalid_padding)?;

    let maximum_error = encode_mxfp4(&vec![0.0_f32; MXFP4_MAX_DIM + 1])
        .unwrap_err()
        .to_string();
    let after_maximum = file_names(output_dir)?;
    ensure_unchanged("maximum", &before, &after_maximum)?;

    let fp8_codec = MxFp8Codec::new(MXFP8_BLOCK_SIZE);
    let mut truncated_payload = fp8_codec.encode(&[1.0_f32; MXFP8_BLOCK_SIZE])?;
    truncated_payload.bytes.pop();
    let truncated_payload_error = fp8_codec
        .decode(&truncated_payload)
        .unwrap_err()
        .to_string();
    let after_truncated_payload = file_names(output_dir)?;
    ensure_unchanged("truncated payload", &before, &after_truncated_payload)?;

    let mut mismatched_dtype = fp8_codec.encode(&[1.0_f32; MXFP8_BLOCK_SIZE])?;
    mismatched_dtype.level = QuantLevel::Bits4Fp;
    let mismatched_dtype_error = fp8_codec.decode(&mismatched_dtype).unwrap_err().to_string();
    let after_mismatched_dtype = file_names(output_dir)?;
    ensure_unchanged("mismatched dtype", &before, &after_mismatched_dtype)?;

    Ok(json!({
        "empty": {"before": before, "error": empty_error, "after": after_empty},
        "invalid_scale": {"before": before, "error": invalid_scale_error, "after": after_invalid_scale},
        "noncanonical_padding": {"before": before, "error": invalid_padding_error, "after": after_invalid_padding},
        "maximum_plus_one": {"before": before, "error": maximum_error, "after": after_maximum},
        "truncated_payload": {"before": before, "error": truncated_payload_error, "after": after_truncated_payload},
        "mismatched_dtype": {"before": before, "error": mismatched_dtype_error, "after": after_mismatched_dtype},
    }))
}

#[cfg(feature = "cuda")]
fn exercise_gpu(
    output_dir: &Path,
    a: &[f32],
    b: &[f32],
    expected: &[f32],
) -> Result<Value, Box<dyn std::error::Error>> {
    use calyx_forge::cuda::kernels::MXFP_GEMM_CUBIN;

    let ctx = init_cuda_native_kernel(0, false)?;
    let stream = ctx.inner().default_stream();
    let a4 = pack_mxfp4_a_row_major(a, M, K)?;
    let b4 = pack_mxfp4_b_column_major(b, K, N)?;
    let a8 = pack_mxfp8_a_row_major(a, M, K)?;
    let b8 = pack_mxfp8_b_column_major(b, K, N)?;
    let mut out4 = stream.alloc_zeros(M * N)?;
    let mut out8 = stream.alloc_zeros(M * N)?;
    let mut plan4 = MxFp4GemmPlan::upload(&ctx, &a4, &b4, M, K, N)?;
    plan4.execute(&ctx, &mut out4)?;
    plan4.execute(&ctx, &mut out4)?;
    let mut plan8 = MxFp8GemmPlan::upload(&ctx, &a8, &b8, M, K, N)?;
    plan8.execute(&ctx, &mut out8)?;
    plan8.execute(&ctx, &mut out8)?;
    let observed4 = stream.clone_dtoh(&out4)?;
    let observed8 = stream.clone_dtoh(&out8)?;
    require_exact("GPU MXFP4", &observed4, expected)?;
    require_exact("GPU MXFP8", &observed8, expected)?;
    write_f32_le(&output_dir.join("gpu_mxfp4_output.f32le"), &observed4)?;
    write_f32_le(&output_dir.join("gpu_mxfp8_output.f32le"), &observed8)?;
    write_and_verify(&output_dir.join("mxfp_gemm.cubin"), MXFP_GEMM_CUBIN)?;

    let evidence4 = plan4.evidence();
    let evidence8 = plan8.evidence();
    let throughput = measure_gpu_throughput(&ctx)?;
    ctx.attest_physical_identity()?;
    Ok(json!({
        "compiled": true,
        "device": evidence4.device,
        "compute_capability": evidence4.compute_capability,
        "cubin_bytes": MXFP_GEMM_CUBIN.len(),
        "cubin_sha256": sha256_hex(MXFP_GEMM_CUBIN),
        "mxfp4": evidence_json(&evidence4),
        "mxfp8": evidence_json(&evidence8),
        "mxfp4_output": observed4,
        "mxfp8_output": observed8,
        "throughput": throughput,
        "post_run_physical_attestation": true,
    }))
}

#[cfg(feature = "cuda")]
fn measure_gpu_throughput(
    ctx: &calyx_forge::CudaContext,
) -> Result<Value, Box<dyn std::error::Error>> {
    const TM: usize = 256;
    const TK: usize = 256;
    const TN: usize = 256;
    const RUNS: usize = 10;

    let mut a = vec![0.0_f32; TM * TK];
    for row in 0..TM {
        for depth in 0..TK {
            a[row * TK + depth] = if (row + depth).is_multiple_of(2) {
                1.0
            } else {
                -1.0
            };
        }
    }
    let mut b = vec![0.0_f32; TN * TK];
    for col in 0..TN {
        for depth in 0..TK {
            b[col * TK + depth] = if (col + depth).is_multiple_of(2) {
                1.0
            } else {
                -1.0
            };
        }
    }
    let stream = ctx.inner().default_stream();

    let a4 = pack_mxfp4_a_row_major(&a, TM, TK)?;
    let b4 = pack_mxfp4_b_column_major(&b, TK, TN)?;
    let mut out4 = stream.alloc_zeros(TM * TN)?;
    let mut plan4 = MxFp4GemmPlan::upload(ctx, &a4, &b4, TM, TK, TN)?;
    plan4.execute(ctx, &mut out4)?;
    let started4 = Instant::now();
    for _ in 0..RUNS {
        plan4.execute(ctx, &mut out4)?;
    }
    let elapsed4 = started4.elapsed();
    verify_checkerboard_output(
        "GPU MXFP4 throughput",
        &stream.clone_dtoh(&out4)?,
        TM,
        TK,
        TN,
    )?;

    let a8 = pack_mxfp8_a_row_major(&a, TM, TK)?;
    let b8 = pack_mxfp8_b_column_major(&b, TK, TN)?;
    let mut out8 = stream.alloc_zeros(TM * TN)?;
    let mut plan8 = MxFp8GemmPlan::upload(ctx, &a8, &b8, TM, TK, TN)?;
    plan8.execute(ctx, &mut out8)?;
    let started8 = Instant::now();
    for _ in 0..RUNS {
        plan8.execute(ctx, &mut out8)?;
    }
    let elapsed8 = started8.elapsed();
    verify_checkerboard_output(
        "GPU MXFP8 throughput",
        &stream.clone_dtoh(&out8)?,
        TM,
        TK,
        TN,
    )?;

    let operations = 2.0 * TM as f64 * TK as f64 * TN as f64 * RUNS as f64;
    Ok(json!({
        "shape": [TM, TK, TN],
        "measured_runs": RUNS,
        "warmup_runs": 1,
        "mxfp4_seconds": elapsed4.as_secs_f64(),
        "mxfp4_gflops": operations / elapsed4.as_secs_f64() / 1.0e9,
        "mxfp4_evidence": evidence_json(&plan4.evidence()),
        "mxfp8_seconds": elapsed8.as_secs_f64(),
        "mxfp8_gflops": operations / elapsed8.as_secs_f64() / 1.0e9,
        "mxfp8_evidence": evidence_json(&plan8.evidence()),
    }))
}

#[cfg(feature = "cuda")]
fn verify_checkerboard_output(
    name: &str,
    observed: &[f32],
    m: usize,
    k: usize,
    n: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    if observed.len() != m * n {
        return Err(format!("{name} output length mismatch").into());
    }
    for col in 0..n {
        for row in 0..m {
            let expected = if (row + col).is_multiple_of(2) {
                k as f32
            } else {
                -(k as f32)
            };
            let actual = observed[col * m + row];
            if actual.to_bits() != expected.to_bits() {
                return Err(format!(
                    "{name} mismatch at row={row} col={col}: expected {expected}, got {actual}"
                )
                .into());
            }
        }
    }
    Ok(())
}

#[cfg(feature = "cuda")]
fn evidence_json(evidence: &calyx_forge::MxPackedGemmEvidence) -> Value {
    json!({
        "backend": evidence.backend,
        "element": evidence.element,
        "kernel": evidence.kernel,
        "shape": [evidence.m, evidence.k, evidence.n],
        "k_blocks": evidence.k_blocks,
        "packed_element_bytes": evidence.packed_element_bytes,
        "scale_bytes": evidence.scale_bytes,
        "output_device_bytes": evidence.output_device_bytes,
        "resident_device_bytes": evidence.resident_device_bytes,
        "module_cache_hit_at_creation": evidence.module_cache_hit_at_creation,
        "execution_count": evidence.execution_count,
        "device_selection_authority": evidence.device_selection_authority,
    })
}

fn pack_rows_fp4(
    values: &[f32],
    vectors: usize,
    k: usize,
) -> Result<Vec<MxFp4Block>, Box<dyn std::error::Error>> {
    if values.len() != vectors * k {
        return Err("FP4 matrix length mismatch".into());
    }
    let mut out = Vec::with_capacity(vectors * k.div_ceil(32));
    for vector in values.chunks_exact(k) {
        out.extend(encode_mxfp4(vector)?);
    }
    Ok(out)
}

fn pack_rows_fp8(
    values: &[f32],
    vectors: usize,
    k: usize,
) -> Result<Vec<MxFp8Block>, Box<dyn std::error::Error>> {
    if values.len() != vectors * k {
        return Err("FP8 matrix length mismatch".into());
    }
    let mut out = Vec::with_capacity(vectors * k.div_ceil(32));
    for vector in values.chunks_exact(k) {
        out.extend(encode_mxfp8(vector)?);
    }
    Ok(out)
}

fn require_exact(
    name: &str,
    observed: &[f32],
    expected: &[f32],
) -> Result<(), Box<dyn std::error::Error>> {
    if observed.len() != expected.len() {
        return Err(format!("{name} length mismatch").into());
    }
    for (index, (observed, expected)) in observed.iter().zip(expected).enumerate() {
        if observed.to_bits() != expected.to_bits() {
            return Err(
                format!("{name} mismatch at {index}: expected {expected}, got {observed}").into(),
            );
        }
    }
    Ok(())
}

fn write_f32_le(path: &Path, values: &[f32]) -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = Vec::with_capacity(values.len() * 4);
    for value in values {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    write_and_verify(path, &bytes)
}

fn write_and_verify(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    fs::write(path, bytes)?;
    if fs::read(path)? != bytes {
        return Err(format!("{} independent readback mismatch", path.display()).into());
    }
    Ok(())
}

fn file_names(path: &Path) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut names = fs::read_dir(path)?
        .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    names.sort();
    Ok(names)
}

fn ensure_unchanged(
    edge: &str,
    before: &[String],
    after: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    if before != after {
        return Err(format!("{edge} edge mutated persisted state").into());
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn execution_evidence() -> Result<Value, Box<dyn std::error::Error>> {
    let artifact = std::env::current_exe()?;
    Ok(json!({
        "platform": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "tree_head": std::env::var("ASTRO_FSV_TREE_HEAD").unwrap_or_else(|_| "unset".to_string()),
        "tree_state_sha256": std::env::var("ASTRO_FSV_TREE_STATE_SHA256").unwrap_or_else(|_| "unset".to_string()),
        "artifact": artifact,
        "artifact_sha256": sha256_hex(&fs::read(std::env::current_exe()?)?),
    }))
}

fn hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(TABLE[(byte >> 4) as usize] as char);
        out.push(TABLE[(byte & 0x0f) as usize] as char);
    }
    out
}
