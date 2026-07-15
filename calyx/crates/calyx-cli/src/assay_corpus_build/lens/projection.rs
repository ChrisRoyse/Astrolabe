use calyx_core::{SlotShape, SparseEntry};

pub(crate) const MAX_SPARSE_DENSE_PROJECTION_DIM: u32 = 8192;

pub(crate) fn projected_slot_dim(shape: SlotShape) -> u32 {
    match shape {
        SlotShape::Dense(dim) | SlotShape::Multi { token_dim: dim } => dim,
        SlotShape::Sparse(dim) => projected_sparse_dim(dim),
    }
}

pub(crate) fn slot_projection_name(shape: SlotShape) -> &'static str {
    match shape {
        SlotShape::Dense(_) => "native_dense",
        SlotShape::Multi { .. } => "multi_mean_dense",
        SlotShape::Sparse(dim) => sparse_projection_name(dim),
    }
}

fn projected_sparse_dim(sparse_dim: u32) -> u32 {
    sparse_dim.min(MAX_SPARSE_DENSE_PROJECTION_DIM)
}

fn sparse_projection_name(sparse_dim: u32) -> &'static str {
    if sparse_dim > MAX_SPARSE_DENSE_PROJECTION_DIM {
        "sparse_hash_dense_8192"
    } else {
        "sparse_to_dense"
    }
}

pub(super) fn project_sparse(
    lens: &str,
    row_idx: usize,
    sparse_dim: u32,
    entries: Vec<SparseEntry>,
) -> Result<Vec<f32>, String> {
    let projection_dim = projected_sparse_dim(sparse_dim);
    if projection_dim == 0 {
        return Err(format!(
            "CALYX_FSV_ASSAY_CORPUS_BUILD_SPARSE_PROJECTION_EMPTY: lens={lens} row={row_idx} sparse_dim={sparse_dim}"
        ));
    }
    let mut data = vec![0.0_f32; projection_dim as usize];
    for entry in entries {
        if entry.idx >= sparse_dim || !entry.val.is_finite() {
            return Err(format!(
                "CALYX_FSV_ASSAY_CORPUS_BUILD_SPARSE_INDEX_OUT_OF_RANGE: lens={lens} row={row_idx} idx={} dim={sparse_dim}",
                entry.idx
            ));
        }
        if sparse_dim <= MAX_SPARSE_DENSE_PROJECTION_DIM {
            data[entry.idx as usize] = entry.val;
        } else {
            let (bucket, sign) = sparse_bucket(entry.idx, projection_dim);
            data[bucket] += sign * entry.val;
        }
    }
    if data.iter().all(|value| *value == 0.0) {
        return Err(format!(
            "CALYX_FSV_ASSAY_CORPUS_BUILD_SPARSE_PROJECTION_ZERO: lens={lens} row={row_idx} sparse_dim={sparse_dim} projected_dim={projection_dim}"
        ));
    }
    Ok(data)
}

fn sparse_bucket(idx: u32, projection_dim: u32) -> (usize, f32) {
    let hash = splitmix64(idx as u64);
    let bucket = (hash % projection_dim as u64) as usize;
    let sign = if (hash >> 63) == 0 { 1.0 } else { -1.0 };
    (bucket, sign)
}

fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9E37_79B9_7F4A_7C15);
    value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    value ^ (value >> 31)
}

pub(super) fn project_multi(
    lens: &str,
    row_idx: usize,
    token_dim: u32,
    tokens: Vec<Vec<f32>>,
) -> Result<Vec<f32>, String> {
    let token_dim = token_dim as usize;
    if token_dim == 0 || tokens.is_empty() {
        return Err(format!(
            "CALYX_FSV_ASSAY_CORPUS_BUILD_EMPTY_MULTI: lens={lens} row={row_idx} token_dim={token_dim} tokens={}",
            tokens.len()
        ));
    }
    let mut out = vec![0.0_f32; token_dim];
    for (token_idx, token) in tokens.iter().enumerate() {
        if token.len() != token_dim {
            return Err(format!(
                "CALYX_FSV_ASSAY_CORPUS_BUILD_MULTI_DIM_MISMATCH: lens={lens} row={row_idx} token={token_idx} len={} expected={token_dim}",
                token.len()
            ));
        }
        for (axis, value) in token.iter().enumerate() {
            if !value.is_finite() {
                return Err(format!(
                    "CALYX_FSV_ASSAY_CORPUS_BUILD_MULTI_NON_FINITE: lens={lens} row={row_idx} token={token_idx} axis={axis}"
                ));
            }
            out[axis] += *value;
        }
    }
    let denom = tokens.len() as f32;
    for value in &mut out {
        *value /= denom;
    }
    Ok(out)
}

