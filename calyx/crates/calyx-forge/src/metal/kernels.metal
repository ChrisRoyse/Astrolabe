/*
 * kernels.metal — Calyx Forge Metal compute kernels (#895 GPU backend).
 *
 * Compiled at runtime from this source by MetalBackend::new(). Every kernel
 * mirrors the exact arithmetic the CPU backend performs, with one deliberate
 * difference documented in metal/mod.rs: floating-point accumulation order.
 * A GPU reduction sums in tree order while the CPU sums in ascending-offset
 * chunk order, so results agree to floating-point tolerance but are not
 * bit-identical. That is why the Metal backend is opt-in and never silently
 * substituted for the CPU backend.
 *
 * All matrices are row-major and tightly packed, matching the CPU contract.
 */

#include <metal_stdlib>
using namespace metal;

// Tile edge for the blocked GEMM. 16x16 = 256 threads per threadgroup, which
// is a full occupancy unit on Apple GPUs (SIMD width 32, 8 SIMD groups).
constant uint GEMM_TILE = 16u;

// Threadgroup size for the row-wise reduction kernels. Must match the value the
// host dispatches with, and must be a power of two for the tree reduction.
constant uint REDUCE_TG = 256u;

/*
 * out[m, n] = a[m, k] * b[k, n]
 *
 * Blocked over threadgroup memory: each threadgroup cooperatively stages a
 * GEMM_TILE x GEMM_TILE block of A and of B, then every thread accumulates its
 * own output element across the staged block. This turns k global loads per
 * output element into k/GEMM_TILE, which is the whole point of tiling.
 */
kernel void gemm_f32(
    device const float *a     [[buffer(0)]],
    device const float *b     [[buffer(1)]],
    device float       *out   [[buffer(2)]],
    constant uint3     &dims  [[buffer(3)]],   // (m, k, n)
    uint2 tg_pos              [[threadgroup_position_in_grid]],
    uint2 t_pos               [[thread_position_in_threadgroup]])
{
    const uint m = dims.x;
    const uint k = dims.y;
    const uint n = dims.z;

    threadgroup float a_tile[GEMM_TILE][GEMM_TILE];
    threadgroup float b_tile[GEMM_TILE][GEMM_TILE];

    const uint row = tg_pos.y * GEMM_TILE + t_pos.y;
    const uint col = tg_pos.x * GEMM_TILE + t_pos.x;

    float acc = 0.0f;
    const uint tiles = (k + GEMM_TILE - 1u) / GEMM_TILE;

    for (uint t = 0u; t < tiles; ++t) {
        const uint a_col = t * GEMM_TILE + t_pos.x;
        const uint b_row = t * GEMM_TILE + t_pos.y;

        // Out-of-range lanes stage zeros so the inner product stays correct
        // without a divergent inner loop bound.
        a_tile[t_pos.y][t_pos.x] =
            (row < m && a_col < k) ? a[(ulong)row * k + a_col] : 0.0f;
        b_tile[t_pos.y][t_pos.x] =
            (b_row < k && col < n) ? b[(ulong)b_row * n + col] : 0.0f;

        threadgroup_barrier(mem_flags::mem_threadgroup);

        for (uint i = 0u; i < GEMM_TILE; ++i) {
            acc = fma(a_tile[t_pos.y][i], b_tile[i][t_pos.x], acc);
        }

        threadgroup_barrier(mem_flags::mem_threadgroup);
    }

    if (row < m && col < n) {
        out[(ulong)row * n + col] = acc;
    }
}

/* Tree reduction of a per-thread partial into lane 0 of the threadgroup. */
static inline float reduce_tg_sum(threadgroup float *scratch, uint tid, uint tsize)
{
    for (uint stride = tsize / 2u; stride > 0u; stride >>= 1u) {
        threadgroup_barrier(mem_flags::mem_threadgroup);
        if (tid < stride) {
            scratch[tid] += scratch[tid + stride];
        }
    }
    threadgroup_barrier(mem_flags::mem_threadgroup);
    return scratch[0];
}

/*
 * out[r] = dot(query, candidates[r])
 * One threadgroup per candidate row; threads stride over `dim`.
 */
kernel void dot_batch(
    device const float *query      [[buffer(0)]],
    device const float *candidates [[buffer(1)]],
    device float       *out        [[buffer(2)]],
    constant uint2     &dims       [[buffer(3)]],   // (dim, rows)
    uint  tg_id                    [[threadgroup_position_in_grid]],
    uint  tid                      [[thread_position_in_threadgroup]],
    uint  tsize                    [[threads_per_threadgroup]])
{
    const uint dim = dims.x;
    device const float *row = candidates + (ulong)tg_id * dim;

    threadgroup float scratch[REDUCE_TG];
    float partial = 0.0f;
    for (uint i = tid; i < dim; i += tsize) {
        partial = fma(query[i], row[i], partial);
    }
    scratch[tid] = partial;

    const float total = reduce_tg_sum(scratch, tid, tsize);
    if (tid == 0u) {
        out[tg_id] = total;
    }
}

/*
 * out[r] = sum_i (query[i] - candidates[r][i])^2      (squared L2)
 * Matches cpu::distance::l2_batch, which returns the SQUARED distance.
 */
kernel void l2_batch(
    device const float *query      [[buffer(0)]],
    device const float *candidates [[buffer(1)]],
    device float       *out        [[buffer(2)]],
    constant uint2     &dims       [[buffer(3)]],
    uint  tg_id                    [[threadgroup_position_in_grid]],
    uint  tid                      [[thread_position_in_threadgroup]],
    uint  tsize                    [[threads_per_threadgroup]])
{
    const uint dim = dims.x;
    device const float *row = candidates + (ulong)tg_id * dim;

    threadgroup float scratch[REDUCE_TG];
    float partial = 0.0f;
    for (uint i = tid; i < dim; i += tsize) {
        const float d = query[i] - row[i];
        partial = fma(d, d, partial);
    }
    scratch[tid] = partial;

    const float total = reduce_tg_sum(scratch, tid, tsize);
    if (tid == 0u) {
        out[tg_id] = total;
    }
}

/*
 * Emits the two quantities cosine similarity needs, per candidate row:
 *   parts[2r]     = dot(query, candidates[r])
 *   parts[2r + 1] = sum_i candidates[r][i]^2      (squared norm)
 *
 * The host performs the sqrt, the zero-norm check, and the division. Keeping
 * those on the host is deliberate: it reproduces the CPU backend's fail-closed
 * `check_norm_positive` behaviour exactly, including which row index is named
 * in the error, while the O(rows * dim) work still runs on the GPU.
 */
kernel void cosine_parts(
    device const float *query      [[buffer(0)]],
    device const float *candidates [[buffer(1)]],
    device float       *parts      [[buffer(2)]],
    constant uint2     &dims       [[buffer(3)]],
    uint  tg_id                    [[threadgroup_position_in_grid]],
    uint  tid                      [[thread_position_in_threadgroup]],
    uint  tsize                    [[threads_per_threadgroup]])
{
    const uint dim = dims.x;
    device const float *row = candidates + (ulong)tg_id * dim;

    threadgroup float scratch[REDUCE_TG];

    float partial_dot = 0.0f;
    float partial_sq = 0.0f;
    for (uint i = tid; i < dim; i += tsize) {
        const float c = row[i];
        partial_dot = fma(query[i], c, partial_dot);
        partial_sq = fma(c, c, partial_sq);
    }

    scratch[tid] = partial_dot;
    const float total_dot = reduce_tg_sum(scratch, tid, tsize);

    threadgroup_barrier(mem_flags::mem_threadgroup);
    scratch[tid] = partial_sq;
    const float total_sq = reduce_tg_sum(scratch, tid, tsize);

    if (tid == 0u) {
        parts[2u * tg_id] = total_dot;
        parts[2u * tg_id + 1u] = total_sq;
    }
}

/*
 * Per-row squared norms of a row-major matrix: norms[r] = sum_i vecs[r][i]^2.
 * The host checks each norm before the scaling pass, so a zero-norm row is
 * refused rather than producing NaNs — matching the CPU backend.
 */
kernel void row_norms_sq(
    device const float *vecs  [[buffer(0)]],
    device float       *norms [[buffer(1)]],
    constant uint2     &dims  [[buffer(2)]],   // (dim, rows)
    uint  tg_id               [[threadgroup_position_in_grid]],
    uint  tid                 [[thread_position_in_threadgroup]],
    uint  tsize               [[threads_per_threadgroup]])
{
    const uint dim = dims.x;
    device const float *row = vecs + (ulong)tg_id * dim;

    threadgroup float scratch[REDUCE_TG];
    float partial = 0.0f;
    for (uint i = tid; i < dim; i += tsize) {
        partial = fma(row[i], row[i], partial);
    }
    scratch[tid] = partial;

    const float total = reduce_tg_sum(scratch, tid, tsize);
    if (tid == 0u) {
        norms[tg_id] = total;
    }
}

/*
 * In-place row scaling: vecs[r][i] *= inv_norms[r].
 * Flat 1-D dispatch over all elements; the reciprocal is computed host-side
 * once per row so the division cost is O(rows), not O(rows * dim).
 */
kernel void scale_rows(
    device float       *vecs      [[buffer(0)]],
    device const float *inv_norms [[buffer(1)]],
    constant uint2     &dims      [[buffer(2)]],   // (dim, rows)
    uint gid                      [[thread_position_in_grid]])
{
    const uint dim = dims.x;
    const uint rows = dims.y;
    const ulong total = (ulong)dim * rows;
    if ((ulong)gid >= total) {
        return;
    }
    vecs[gid] *= inv_norms[gid / dim];
}
