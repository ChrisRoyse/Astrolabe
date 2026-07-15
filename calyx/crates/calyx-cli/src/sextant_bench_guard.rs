use calyx_core::CalyxError;

use crate::error::{CliError, CliResult};

pub(crate) const CALYX_FSV_FLAT_BENCH_MATERIALIZES: &str = "CALYX_FSV_FLAT_BENCH_MATERIALIZES";

const BYTES_PER_F32: u128 = std::mem::size_of::<f32>() as u128;
const GIB: u128 = 1024 * 1024 * 1024;
const MAX_FLAT_BENCH_RAW_DENSE_BYTES: u128 = GIB;

pub(crate) fn require_flat_bench_budget(
    command: &'static str,
    n_cx: usize,
    dim: usize,
) -> CliResult {
    let Some(raw_dense_bytes) = raw_dense_bytes(n_cx, dim) else {
        return Err(flat_bench_error(command, n_cx, dim, None));
    };
    if raw_dense_bytes > MAX_FLAT_BENCH_RAW_DENSE_BYTES {
        return Err(flat_bench_error(command, n_cx, dim, Some(raw_dense_bytes)));
    }
    Ok(())
}

fn raw_dense_bytes(n_cx: usize, dim: usize) -> Option<u128> {
    (n_cx as u128)
        .checked_mul(dim as u128)?
        .checked_mul(BYTES_PER_F32)
}

fn flat_bench_error(
    command: &'static str,
    n_cx: usize,
    dim: usize,
    raw_dense_bytes: Option<u128>,
) -> CliError {
    let size = raw_dense_bytes
        .map(format_bytes)
        .unwrap_or_else(|| "overflow".to_string());
    CliError::Calyx(CalyxError {
        code: CALYX_FSV_FLAT_BENCH_MATERIALIZES,
        message: format!(
            "{command} would materialize {n_cx}x{dim} f32 synthetic rows ({size} raw) in the legacy flat bench path; limit is {} raw",
            format_bytes(MAX_FLAT_BENCH_RAW_DENSE_BYTES)
        ),
        remediation: "use build-partitioned-vault --vectors and bench partitioned-search with .fbin sources",
    })
}

fn format_bytes(bytes: u128) -> String {
    if bytes.is_multiple_of(GIB) {
        format!("{} GiB", bytes / GIB)
    } else {
        format!("{bytes} bytes")
    }
}

