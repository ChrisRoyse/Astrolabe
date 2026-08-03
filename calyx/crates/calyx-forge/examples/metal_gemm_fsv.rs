//! Full State Verification for the Apple Silicon Metal GEMM.
//!
//! Run:  cargo run --release -p calyx-forge --features metal --example metal_gemm_fsv
//!
//! Order matters here. Correctness is established before any timing, because a
//! throughput number from a kernel that computes the wrong answer is worse than
//! no number at all.
//!
//!   1. KNOWN ANSWER. A 2x3 by 3x2 GEMM whose product is computed by hand, so
//!      "correct" is stated in advance. Both backends and both GPU kernels must
//!      land on it exactly.
//!
//!   2. RAGGED SHAPES. The simdgroup kernel works in 32x32 threadgroup tiles and
//!      8x8 matrix fragments, so any dimension that is not a multiple of those
//!      is where it would break. Every case here is checked against the CPU
//!      backend, which has no such structure.
//!
//!   3. MEASURED HEADROOM. Naive vs simdgroup, same process, same device, same
//!      buffer path. A speedup compared across processes is not evidence, which
//!      is why `gemm_naive` is kept reachable rather than deleted.
//!
//! Layout is column-major, matching src/metal/kernels.metal:
//!     a[d * m + row]      A is M x K
//!     b[col * k + d]      B is K x N
//!     out[col * m + row]  out is M x N

use calyx_forge::{Backend, CpuBackend, MetalBackend};
use std::time::Instant;

/// Hand-computed fixture.
///
///   A = [[1, 2, 3],        B = [[ 7,  8],       A*B = [[ 58,  64],
///        [4, 5, 6]]             [ 9, 10],              [139, 154]]
///                               [11, 12]]
///
/// 1*7 + 2*9  + 3*11 =  58      1*8 + 2*10 + 3*12 =  64
/// 4*7 + 5*9  + 6*11 = 139      4*8 + 5*10 + 6*12 = 154
const M: usize = 2;
const K: usize = 3;
const N: usize = 2;
const A: [f32; 6] = [1.0, 4.0, 2.0, 5.0, 3.0, 6.0]; // column-major, ld = m
const B: [f32; 6] = [7.0, 9.0, 11.0, 8.0, 10.0, 12.0]; // column-major, ld = k
const EXPECTED: [f32; 4] = [58.0, 139.0, 64.0, 154.0]; // column-major, ld = m

/// Deterministic, reproducible operands. Values are small and exactly
/// representable so CPU/GPU disagreement means a real defect, not rounding.
fn fill(len: usize, seed: usize) -> Vec<f32> {
    (0..len)
        .map(|i| ((i * 7 + seed * 13) % 17) as f32 * 0.5 - 4.0)
        .collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("== Metal GEMM FSV: known answer, ragged shapes, then measured headroom ==\n");

    let cpu = CpuBackend::new();
    let metal = MetalBackend::new()?;
    println!("cpu   device: {:?}", cpu.device_info());
    println!("metal device: {:?}\n", metal.device_info());

    // ---- 1. Known answer ---------------------------------------------------
    let mut cpu_out = vec![0.0f32; M * N];
    let mut sg_out = vec![0.0f32; M * N];
    let mut naive_out = vec![0.0f32; M * N];
    cpu.gemm(&A, &B, M, K, N, &mut cpu_out)?;
    metal.gemm(&A, &B, M, K, N, &mut sg_out)?;
    metal.gemm_naive(&A, &B, M, K, N, &mut naive_out)?;

    println!("expected        : {EXPECTED:?}");
    println!("cpu             : {cpu_out:?}");
    println!("metal simdgroup : {sg_out:?}");
    println!("metal naive     : {naive_out:?}");
    let ok = cpu_out == EXPECTED && sg_out == EXPECTED && naive_out == EXPECTED;
    println!("\nall three == expected : {ok}");
    if !ok {
        return Err("known-answer GEMM mismatch -- a backend is wrong, not slow".into());
    }
    println!("PASS: every path reproduces an answer stated in advance.\n");

    // ---- 2. Ragged shapes --------------------------------------------------
    // The simdgroup kernel tiles in 32x32 with an 8-deep K step. These shapes
    // deliberately straddle and fall short of both, including the degenerate
    // 1x1x1 case and a K shorter than one fragment.
    println!("ragged shapes (simdgroup vs cpu, exact match required):");
    let shapes = [
        (1usize, 1usize, 1usize),
        (3, 2, 5),
        (7, 5, 3),   // every dim < 8
        (8, 8, 8),   // exactly one fragment
        (31, 9, 33), // straddles the 32 tile, K not a multiple of 8
        (32, 8, 32), // exact tile
        (33, 17, 1), // ragged tile, single output column
        (64, 40, 48),
    ];
    let mut worst_ragged = 0.0f32;
    for (m, k, n) in shapes {
        let a = fill(m * k, m + k);
        let b = fill(k * n, k + n);
        let mut want = vec![0.0f32; m * n];
        let mut got = vec![0.0f32; m * n];
        cpu.gemm(&a, &b, m, k, n, &mut want)?;
        metal.gemm(&a, &b, m, k, n, &mut got)?;
        let mut worst = 0.0f32;
        for (x, y) in want.iter().zip(got.iter()) {
            let d = (x - y).abs() / x.abs().max(1.0);
            if d > worst {
                worst = d;
            }
        }
        let verdict = if worst <= 1e-5 { "ok" } else { "MISMATCH" };
        println!("  {m:3}x{k:3}x{n:3}  worst rel dev {worst:.3e}  {verdict}");
        if worst > worst_ragged {
            worst_ragged = worst;
        }
    }
    if worst_ragged > 1e-5 {
        return Err("ragged-shape mismatch -- the simdgroup tiling is wrong at an edge".into());
    }
    println!("PASS: tiling is correct on every non-multiple shape.\n");

    // ---- 3. Measured headroom ----------------------------------------------
    // 1024^3 is compute-bound (2*n^3 flops over 3*n^2 floats), the regime the
    // project's doctrine says Metal should win. Bandwidth-bound kernels are
    // deliberately not measured here.
    let big = 1024usize;
    let a = fill(big * big, 1);
    let b = fill(big * big, 2);
    let mut out_naive = vec![0.0f32; big * big];
    let mut out_sg = vec![0.0f32; big * big];
    let mut out_cpu = vec![0.0f32; big * big];

    // Warm both pipelines: the first dispatch pays library/pipeline creation,
    // a one-time cost that would otherwise be charged to the measurement.
    metal.gemm_naive(&a, &b, big, big, big, &mut out_naive)?;
    metal.gemm(&a, &b, big, big, big, &mut out_sg)?;

    let t = Instant::now();
    cpu.gemm(&a, &b, big, big, big, &mut out_cpu)?;
    let cpu_ms = t.elapsed().as_secs_f64() * 1000.0;

    let t = Instant::now();
    metal.gemm_naive(&a, &b, big, big, big, &mut out_naive)?;
    let naive_ms = t.elapsed().as_secs_f64() * 1000.0;

    let t = Instant::now();
    metal.gemm(&a, &b, big, big, big, &mut out_sg)?;
    let sg_ms = t.elapsed().as_secs_f64() * 1000.0;

    let flops = 2.0 * (big as f64).powi(3);
    let gflops = |ms: f64| flops / (ms * 1e6);
    println!("{big}x{big}x{big} GEMM (compute-bound):");
    println!("  cpu             {cpu_ms:9.2} ms   {:8.1} GFLOP/s", gflops(cpu_ms));
    println!("  metal naive     {naive_ms:9.2} ms   {:8.1} GFLOP/s", gflops(naive_ms));
    println!("  metal simdgroup {sg_ms:9.2} ms   {:8.1} GFLOP/s", gflops(sg_ms));
    println!("\n  simdgroup vs naive : {:.2}x", naive_ms / sg_ms);
    println!("  simdgroup vs cpu   : {:.2}x", cpu_ms / sg_ms);

    // Agreement at scale is an independent signal that the kernel is sound on
    // real sizes, not just on a 2x2 toy. Tolerance is relative: GPU reductions
    // accumulate in tree order and are not expected to match bit-for-bit.
    let mut worst = 0.0f32;
    for (x, y) in out_cpu.iter().zip(out_sg.iter()) {
        let d = (x - y).abs() / x.abs().max(1.0);
        if d > worst {
            worst = d;
        }
    }
    println!("\n  worst relative deviation simdgroup vs cpu: {worst:.3e}");
    if worst > 1e-4 {
        return Err("large-GEMM divergence beyond tree-order reassociation".into());
    }
    println!("  PASS: large-GEMM agreement within reassociation tolerance.");

    Ok(())
}
