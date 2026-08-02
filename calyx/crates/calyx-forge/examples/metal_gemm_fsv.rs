//! Full State Verification for the Apple Silicon Metal backend.
//!
//! Run:  cargo run --release -p calyx-forge --features metal --example metal_gemm_fsv
//!
//! Two things are proven here, in order:
//!
//!   1. CORRECTNESS against a known answer. A 2x3 by 3x2 GEMM whose product is
//!      computed by hand, so "right" is not a matter of opinion. Both backends
//!      must land on it exactly. If the GPU cannot reproduce arithmetic whose
//!      answer is stated in advance, no timing number from it means anything.
//!
//!   2. HEADROOM, measured. The same embedding-shaped GEMM on the CPU backend
//!      and the Metal backend, wall-clock, on this machine. This is the number
//!      that decides whether investing in simdgroup_matrix / MPSGraph for
//!      gemm_f32 is worth doing -- it is not assumed, it is measured here.
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("== Metal FSV: known-answer correctness, then measured headroom ==\n");

    let cpu = CpuBackend::new();
    let metal = MetalBackend::new()?;

    println!("cpu   device: {:?}", cpu.device_info());
    println!("metal device: {:?}\n", metal.device_info());

    // ---- 1. Known-answer correctness -------------------------------------
    let mut cpu_out = vec![0.0f32; M * N];
    let mut gpu_out = vec![0.0f32; M * N];
    cpu.gemm(&A, &B, M, K, N, &mut cpu_out)?;
    metal.gemm(&A, &B, M, K, N, &mut gpu_out)?;

    println!("expected : {EXPECTED:?}");
    println!("cpu      : {cpu_out:?}");
    println!("metal    : {gpu_out:?}");

    let cpu_ok = cpu_out == EXPECTED;
    let gpu_ok = gpu_out == EXPECTED;
    println!("\ncpu   == expected : {cpu_ok}");
    println!("metal == expected : {gpu_ok}");
    if !cpu_ok || !gpu_ok {
        return Err("known-answer GEMM mismatch -- backend is wrong, not slow".into());
    }
    println!("PASS: the GPU reproduces an answer stated in advance.\n");

    // ---- 2. Measured headroom on an embedding-shaped GEMM ------------------
    // 1024x1024x1024 is compute-bound (2*n^3 flops over 3*n^2 floats), which is
    // the regime the project's own doctrine says Metal should win. Anything
    // bandwidth-bound is deliberately NOT measured here.
    let big = 1024usize;
    let a: Vec<f32> = (0..big * big).map(|i| (i % 17) as f32 * 0.5).collect();
    let b: Vec<f32> = (0..big * big).map(|i| (i % 13) as f32 * 0.25).collect();
    let mut out_cpu = vec![0.0f32; big * big];
    let mut out_gpu = vec![0.0f32; big * big];

    // Warm the GPU: first dispatch pays pipeline/library creation, which is a
    // one-time cost and would otherwise be charged to the measurement.
    metal.gemm(&a, &b, big, big, big, &mut out_gpu)?;

    let t = Instant::now();
    cpu.gemm(&a, &b, big, big, big, &mut out_cpu)?;
    let cpu_ms = t.elapsed().as_secs_f64() * 1000.0;

    let t = Instant::now();
    metal.gemm(&a, &b, big, big, big, &mut out_gpu)?;
    let gpu_ms = t.elapsed().as_secs_f64() * 1000.0;

    let flops = 2.0 * (big as f64).powi(3);
    println!("{big}x{big}x{big} GEMM (compute-bound):");
    println!("  cpu   {cpu_ms:9.2} ms   {:7.1} GFLOP/s", flops / (cpu_ms * 1e6));
    println!("  metal {gpu_ms:9.2} ms   {:7.1} GFLOP/s", flops / (gpu_ms * 1e6));
    println!("  speedup: {:.2}x", cpu_ms / gpu_ms);

    // Cross-check the large result too: agreement here is a second, independent
    // signal that the GPU path is arithmetically sound at scale, not just on a
    // 2x2 toy. Tolerance is relative -- GPU reductions accumulate in tree order
    // and are not expected to match the CPU bit-for-bit (see metal/mod.rs).
    let mut worst = 0.0f32;
    for (x, y) in out_cpu.iter().zip(out_gpu.iter()) {
        let d = (x - y).abs() / x.abs().max(1.0);
        if d > worst {
            worst = d;
        }
    }
    println!("\n  worst relative elementwise deviation cpu vs metal: {worst:.3e}");
    if worst > 1e-4 {
        return Err("large-GEMM divergence beyond tree-order reassociation".into());
    }
    println!("  PASS: large-GEMM agreement within reassociation tolerance.");

    Ok(())
}
