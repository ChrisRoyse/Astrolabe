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
#include <metal_simdgroup_matrix>
using namespace metal;

// Simdgroup GEMM geometry (#945). A threadgroup is 128 threads = 4 SIMD groups
// laid out 2x2; it computes a 32x32 output tile. Each SIMD group owns a 16x16
// quadrant, held as a 2x2 grid of 8x8 register fragments. K advances 8 at a
// time because simdgroup_multiply_accumulate consumes 8x8 operands.
constant uint SG_TILE = 32u;   // threadgroup output tile edge
constant uint SG_K = 8u;       // K step == simdgroup matrix edge
constant uint SG_THREADS = 128u;

// Tile edge for the blocked GEMM. 16x16 = 256 threads per threadgroup, which
// is a full occupancy unit on Apple GPUs (SIMD width 32, 8 SIMD groups).
constant uint GEMM_TILE = 16u;

// Row-reduction geometry.
//
// Each row is reduced by ONE SIMD group (32 lanes on Apple GPUs) using the
// hardware simd_sum() instruction, not a threadgroup barrier tree. A 256-thread
// threadgroup therefore retires SIMD_PER_TG = 8 rows concurrently.
//
// This matters: the previous shape gave every row a 256-thread threadgroup and
// log2(256) = 8 barrier rounds to reduce only `dim` elements. For the vector
// sizes this API sees, barrier latency dominated the arithmetic entirely.
// simd_sum needs no barriers and no threadgroup memory.
constant uint SIMD_WIDTH = 32u;
constant uint SIMD_PER_TG = 8u;
constant uint ROWS_PER_TG = SIMD_PER_TG;

/*
 * out[m, n] = a[m, k] * b[k, n]
 *
 * COLUMN-MAJOR, matching Forge's existing GEMM contract (the same layout the
 * CUDA path documents and the CPU path indexes through col_major()):
 *     a[d * m + row]     A is M x K
 *     b[col * k + d]     B is K x N
 *     out[col * m + row] out is M x N
 *
 * Note this differs from the distance/normalize kernels below, which operate on
 * row-major batches of vectors. The two layouts coexist in the Forge API.
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
    /* uint4, not uint3: MSL sizes uint3 at 16 bytes, so a 12-byte upload
     * leaves .z (n) reading past the buffer. Declaring the full 16-byte vector
     * makes the host-side layout unambiguous. .w is unused. */
    constant uint4     &dims  [[buffer(3)]],   // (m, k, n, unused)
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
            (row < m && a_col < k) ? a[(ulong)a_col * m + row] : 0.0f;
        b_tile[t_pos.y][t_pos.x] =
            (b_row < k && col < n) ? b[(ulong)col * k + b_row] : 0.0f;

        threadgroup_barrier(mem_flags::mem_threadgroup);

        for (uint i = 0u; i < GEMM_TILE; ++i) {
            acc = fma(a_tile[t_pos.y][i], b_tile[i][t_pos.x], acc);
        }

        threadgroup_barrier(mem_flags::mem_threadgroup);
    }

    if (row < m && col < n) {
        out[(ulong)col * m + row] = acc;
    }
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
    uint  sg_id                    [[simdgroup_index_in_threadgroup]],
    uint  lane                     [[thread_index_in_simdgroup]])
{
    const uint dim = dims.x;
    const uint rows = dims.y;
    const uint row_idx = tg_id * ROWS_PER_TG + sg_id;
    // row_idx is uniform across a SIMD group, so the whole group exits together
    // and no lane reaches simd_sum() with a divergent partner.
    if (row_idx >= rows) {
        return;
    }
    device const float *row = candidates + (ulong)row_idx * dim;

    float partial = 0.0f;
    for (uint i = lane; i < dim; i += SIMD_WIDTH) {
        partial = fma(query[i], row[i], partial);
    }
    const float total = simd_sum(partial);
    if (lane == 0u) {
        out[row_idx] = total;
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
    uint  sg_id                    [[simdgroup_index_in_threadgroup]],
    uint  lane                     [[thread_index_in_simdgroup]])
{
    const uint dim = dims.x;
    const uint rows = dims.y;
    const uint row_idx = tg_id * ROWS_PER_TG + sg_id;
    if (row_idx >= rows) {
        return;
    }
    device const float *row = candidates + (ulong)row_idx * dim;

    float partial = 0.0f;
    for (uint i = lane; i < dim; i += SIMD_WIDTH) {
        const float d = query[i] - row[i];
        partial = fma(d, d, partial);
    }
    const float total = simd_sum(partial);
    if (lane == 0u) {
        out[row_idx] = total;
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
    uint  sg_id                    [[simdgroup_index_in_threadgroup]],
    uint  lane                     [[thread_index_in_simdgroup]])
{
    const uint dim = dims.x;
    const uint rows = dims.y;
    const uint row_idx = tg_id * ROWS_PER_TG + sg_id;
    if (row_idx >= rows) {
        return;
    }
    device const float *row = candidates + (ulong)row_idx * dim;

    float partial_dot = 0.0f;
    float partial_sq = 0.0f;
    // One pass over the row produces both quantities; the candidate value is
    // loaded once and used twice.
    for (uint i = lane; i < dim; i += SIMD_WIDTH) {
        const float c = row[i];
        partial_dot = fma(query[i], c, partial_dot);
        partial_sq = fma(c, c, partial_sq);
    }
    const float total_dot = simd_sum(partial_dot);
    const float total_sq = simd_sum(partial_sq);

    if (lane == 0u) {
        parts[2u * row_idx] = total_dot;
        parts[2u * row_idx + 1u] = total_sq;
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
    uint  sg_id               [[simdgroup_index_in_threadgroup]],
    uint  lane                [[thread_index_in_simdgroup]])
{
    const uint dim = dims.x;
    const uint rows = dims.y;
    const uint row_idx = tg_id * ROWS_PER_TG + sg_id;
    if (row_idx >= rows) {
        return;
    }
    device const float *row = vecs + (ulong)row_idx * dim;

    float partial = 0.0f;
    for (uint i = lane; i < dim; i += SIMD_WIDTH) {
        partial = fma(row[i], row[i], partial);
    }
    const float total = simd_sum(partial);
    if (lane == 0u) {
        norms[row_idx] = total;
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

/*
 * gemm_f32_simdgroup — GEMM on Apple's hardware matrix units (#945).
 *
 * ROW-MAJOR: C[M][N] = A[M][K] * B[K][N], lda=K, ldb=N, ldc=N.
 *
 * Forge's GEMM contract is column-major, but this kernel is deliberately
 * row-major, because a column-major problem IS a row-major one with the
 * operands swapped — no transpose flag and no strided loads needed:
 *
 *     out[col*m + row] = sum_d a[d*m + row] * b[col*k + d]      (Forge, col-major)
 *     C'[i*ldc + j]    = sum_d A'[i*lda + d] * B'[d*ldb + j]    (this kernel)
 *
 * substituting i=col, j=row gives A'=b (n x k, ld=k), B'=a (k x m, ld=m),
 * C'=out (n x m, ld=m). The host therefore dispatches this with M=n, K=k, N=m
 * and buffers (b, a, out). See MetalBackend::gemm.
 *
 * Why this is faster than gemm_f32: that kernel gives each thread ONE output
 * element and one scalar accumulator, so the multiply-add units run at scalar
 * rate. Here a 32-lane SIMD group cooperatively issues an 8x8x8 matrix
 * multiply-accumulate on the matrix hardware, and each SIMD group keeps four
 * 8x8 accumulators live in registers across the whole K loop. The threadgroup
 * stages A and B in threadgroup memory ONCE per K-step and all four SIMD groups
 * reuse it, which is what cuts global-memory traffic.
 *
 * Ragged shapes: staging zero-fills out-of-range elements, so the matrix ops
 * always see full 8x8 tiles and M/N/K need not be multiples of anything. Zeros
 * contribute nothing to a sum, and the final write-out is bounds-checked, so an
 * edge tile computes garbage columns into threadgroup memory and then discards
 * them rather than writing past the buffer.
 */
kernel void gemm_f32_simdgroup(
    device const float *a    [[buffer(0)]],
    device const float *b    [[buffer(1)]],
    device float       *out  [[buffer(2)]],
    /* uint4 for the same reason gemm_f32 uses it: MSL sizes uint3 at 16 bytes,
     * so a 12-byte upload would leave .z reading past the buffer. */
    constant uint4     &dims [[buffer(3)]],   // (M, K, N, unused)
    uint2 tg_pos             [[threadgroup_position_in_grid]],
    uint  tid                [[thread_index_in_threadgroup]],
    uint  sgid               [[simdgroup_index_in_threadgroup]])
{
    const uint m_dim = dims.x;
    const uint k_dim = dims.y;
    const uint n_dim = dims.z;
    const uint lda = k_dim;
    const uint ldb = n_dim;
    const uint ldc = n_dim;

    threadgroup float a_stage[SG_TILE * SG_K];    // 32 x 8
    threadgroup float b_stage[SG_K * SG_TILE];    // 8 x 32
    threadgroup float c_stage[SG_TILE * SG_TILE]; // 32 x 32

    const uint row0 = tg_pos.y * SG_TILE;
    const uint col0 = tg_pos.x * SG_TILE;

    /* 4 SIMD groups as a 2x2 grid over the 32x32 tile: each owns 16x16. */
    const uint sg_r = sgid / 2u;
    const uint sg_c = sgid % 2u;

    simdgroup_float8x8 acc[2][2];
    for (uint i = 0u; i < 2u; ++i) {
        for (uint j = 0u; j < 2u; ++j) {
            acc[i][j] = simdgroup_float8x8(0.0f);
        }
    }

    for (uint kb = 0u; kb < k_dim; kb += SG_K) {
        /* 256 staged elements, 128 threads: two each, coalesced by construction. */
        for (uint s = tid; s < SG_TILE * SG_K; s += SG_THREADS) {
            const uint r = s / SG_K;
            const uint d = s % SG_K;
            const uint gr = row0 + r;
            const uint gd = kb + d;
            a_stage[s] = (gr < m_dim && gd < k_dim) ? a[(ulong)gr * lda + gd] : 0.0f;
        }
        for (uint s = tid; s < SG_K * SG_TILE; s += SG_THREADS) {
            const uint d = s / SG_TILE;
            const uint c = s % SG_TILE;
            const uint gd = kb + d;
            const uint gc = col0 + c;
            b_stage[s] = (gd < k_dim && gc < n_dim) ? b[(ulong)gd * ldb + gc] : 0.0f;
        }
        threadgroup_barrier(mem_flags::mem_threadgroup);

        simdgroup_float8x8 a_frag[2];
        simdgroup_float8x8 b_frag[2];
        for (uint i = 0u; i < 2u; ++i) {
            simdgroup_load(a_frag[i], &a_stage[(sg_r * 16u + i * 8u) * SG_K], SG_K);
        }
        for (uint j = 0u; j < 2u; ++j) {
            simdgroup_load(b_frag[j], &b_stage[sg_c * 16u + j * 8u], SG_TILE);
        }
        for (uint i = 0u; i < 2u; ++i) {
            for (uint j = 0u; j < 2u; ++j) {
                simdgroup_multiply_accumulate(acc[i][j], a_frag[i], b_frag[j], acc[i][j]);
            }
        }

        /* Second barrier: the next iteration overwrites the staging buffers, so
         * every SIMD group must be done reading them before that happens. */
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }

    for (uint i = 0u; i < 2u; ++i) {
        for (uint j = 0u; j < 2u; ++j) {
            simdgroup_store(acc[i][j],
                            &c_stage[(sg_r * 16u + i * 8u) * SG_TILE + sg_c * 16u + j * 8u],
                            SG_TILE);
        }
    }
    threadgroup_barrier(mem_flags::mem_threadgroup);

    for (uint s = tid; s < SG_TILE * SG_TILE; s += SG_THREADS) {
        const uint r = s / SG_TILE;
        const uint c = s % SG_TILE;
        const uint gr = row0 + r;
        const uint gc = col0 + c;
        if (gr < m_dim && gc < n_dim) {
            out[(ulong)gr * ldc + gc] = c_stage[s];
        }
    }
}
