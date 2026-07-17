#include <cuda_runtime.h>
#include <stdint.h>

// OCP MX operands are laid out with K as the contiguous/blocked axis:
//   A codes: M rows of ceil(K/32) blocks
//   B codes: N columns of ceil(K/32) blocks
//   scales:  one UE8M0 byte per corresponding 32-value block
// Output is column-major (M x N), matching Forge's existing GEMM contract.
//
// Each CUDA block is exactly one warp and computes one 16x8 output tile using
// Blackwell's native block-scaled MMA instructions. There is no element decode,
// F32 operand materialization, scalar K loop, or backend fallback in this path.

namespace {

constexpr unsigned kWarpSize = 32;
constexpr unsigned kStatusScaleNan = 0x40000000u;
constexpr unsigned kStatusOutputBase = 0x80000000u;

__device__ __forceinline__ uint32_t load_four_bytes(const uint8_t* base) {
  return uint32_t(base[0]) | (uint32_t(base[1]) << 8) |
         (uint32_t(base[2]) << 16) | (uint32_t(base[3]) << 24);
}

__device__ __forceinline__ uint32_t load_fp4_eight(
    const uint8_t* codes, unsigned vector, unsigned k_start,
    unsigned vectors, unsigned k_blocks) {
  if (vector >= vectors || k_start >= k_blocks * 32u) {
    return 0;
  }
  const uint8_t* ptr = codes +
      (size_t(vector) * size_t(k_blocks) * 16u) + (k_start >> 1);
  return load_four_bytes(ptr);
}

__device__ __forceinline__ uint32_t load_fp8_four(
    const uint8_t* codes, unsigned vector, unsigned k_start,
    unsigned vectors, unsigned k_blocks) {
  if (vector >= vectors || k_start >= k_blocks * 32u) {
    return 0;
  }
  const uint8_t* ptr = codes +
      (size_t(vector) * size_t(k_blocks) * 32u) + k_start;
  return load_four_bytes(ptr);
}

__device__ __forceinline__ uint8_t load_scale(
    const uint8_t* scales, unsigned vector, unsigned block,
    unsigned vectors, unsigned k_blocks) {
  if (vector >= vectors || block >= k_blocks) {
    // UE8M0 byte zero is the canonical scale for an all-zero padding block.
    return 0;
  }
  return scales[size_t(vector) * size_t(k_blocks) + block];
}

__device__ __forceinline__ bool e4m3_word_has_nan(uint32_t value) {
  return ((value & 0x7fu) == 0x7fu) ||
         (((value >> 8) & 0x7fu) == 0x7fu) ||
         (((value >> 16) & 0x7fu) == 0x7fu) ||
         (((value >> 24) & 0x7fu) == 0x7fu);
}

__device__ __forceinline__ void record_status(uint32_t* status, uint32_t code) {
  atomicCAS(status, 0u, code);
}

__device__ __forceinline__ void mma_mxfp4_e2m1_ue8m0(
    float& d0, float& d1, float& d2, float& d3,
    uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3,
    uint32_t b0, uint32_t b1, uint16_t sfa, uint16_t sfb) {
  const float c0 = d0;
  const float c1 = d1;
  const float c2 = d2;
  const float c3 = d3;
  constexpr uint16_t bid_a = 0;
  constexpr uint16_t tid_a = 0;
  constexpr uint16_t bid_b = 0;
  constexpr uint16_t tid_b = 0;
  asm volatile(
      "mma.sync.aligned.kind::mxf4nvf4.block_scale.scale_vec::2X."
      "m16n8k64.row.col.f32.e2m1.e2m1.f32.ue8m0 "
      "{%0, %1, %2, %3},"
      "{%4, %5, %6, %7},"
      "{%8, %9},"
      "{%10, %11, %12, %13},"
      "{%14}, {%15, %16}, {%17}, {%18, %19};\n"
      : "=f"(d0), "=f"(d1), "=f"(d2), "=f"(d3)
      : "r"(a0), "r"(a1), "r"(a2), "r"(a3),
        "r"(b0), "r"(b1),
        "f"(c0), "f"(c1), "f"(c2), "f"(c3),
        "r"(uint32_t(sfa)), "h"(bid_a), "h"(tid_a),
        "r"(uint32_t(sfb)), "h"(bid_b), "h"(tid_b));
}

__device__ __forceinline__ void mma_mxfp8_e4m3_ue8m0(
    float& d0, float& d1, float& d2, float& d3,
    uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3,
    uint32_t b0, uint32_t b1, uint8_t sfa, uint8_t sfb) {
  const float c0 = d0;
  const float c1 = d1;
  const float c2 = d2;
  const float c3 = d3;
  constexpr uint16_t bid_a = 0;
  constexpr uint16_t tid_a = 0;
  constexpr uint16_t bid_b = 0;
  constexpr uint16_t tid_b = 0;
  asm volatile(
      "mma.sync.aligned.kind::mxf8f6f4.block_scale.scale_vec::1X."
      "m16n8k32.row.col.f32.e4m3.e4m3.f32.ue8m0 "
      "{%0, %1, %2, %3},"
      "{%4, %5, %6, %7},"
      "{%8, %9},"
      "{%10, %11, %12, %13},"
      "{%14}, {%15, %16}, {%17}, {%18, %19};\n"
      : "=f"(d0), "=f"(d1), "=f"(d2), "=f"(d3)
      : "r"(a0), "r"(a1), "r"(a2), "r"(a3),
        "r"(b0), "r"(b1),
        "f"(c0), "f"(c1), "f"(c2), "f"(c3),
        "r"(uint32_t(sfa)), "h"(bid_a), "h"(tid_a),
        "r"(uint32_t(sfb)), "h"(bid_b), "h"(tid_b));
}

__device__ __forceinline__ void store_tile(
    float d0, float d1, float d2, float d3,
    unsigned lane, unsigned tile_m, unsigned tile_n,
    unsigned m, unsigned n, float* out, uint32_t* status) {
  const unsigned lane_m = lane >> 2;
  const unsigned lane_n = (lane & 3u) << 1;
  const unsigned rows[4] = {
      tile_m + lane_m, tile_m + lane_m,
      tile_m + lane_m + 8u, tile_m + lane_m + 8u};
  const unsigned cols[4] = {
      tile_n + lane_n, tile_n + lane_n + 1u,
      tile_n + lane_n, tile_n + lane_n + 1u};
  const float values[4] = {d0, d1, d2, d3};
  #pragma unroll
  for (int i = 0; i < 4; ++i) {
    if (rows[i] < m && cols[i] < n) {
      const size_t output_index = size_t(cols[i]) * size_t(m) + rows[i];
      if (!isfinite(values[i])) {
        const uint32_t bounded = output_index >= 0x3fffffffu
            ? 0x3fffffffu : uint32_t(output_index + 1u);
        record_status(status, kStatusOutputBase | bounded);
      } else {
        out[output_index] = values[i];
      }
    }
  }
}

}  // namespace

extern "C" __global__ __launch_bounds__(kWarpSize)
void gemm_mxfp4_e2m1_fp32_accum_kernel(
    const uint8_t* a_codes, const uint8_t* a_scales,
    const uint8_t* b_codes, const uint8_t* b_scales,
    unsigned m, unsigned k, unsigned n, unsigned k_blocks,
    float* out, uint32_t* status) {
  const unsigned lane = threadIdx.x;
  const unsigned tile_m = blockIdx.y * 16u;
  const unsigned tile_n = blockIdx.x * 8u;
  const unsigned t0 = lane & 3u;
  const unsigned t1 = lane >> 2;
  const unsigned scale_row = tile_m + ((lane & 1u) << 3) + (lane >> 2);
  const unsigned scale_col = tile_n + (lane >> 2);
  float d0 = 0.0f;
  float d1 = 0.0f;
  float d2 = 0.0f;
  float d3 = 0.0f;

  const unsigned rounded_k = ((k_blocks + 1u) & ~1u) * 32u;
  for (unsigned k_base = 0; k_base < rounded_k; k_base += 64u) {
    const unsigned block_base = k_base >> 5;
    const uint8_t sfa0 = load_scale(a_scales, scale_row, block_base, m, k_blocks);
    const uint8_t sfa1 = load_scale(a_scales, scale_row, block_base + 1u, m, k_blocks);
    const uint8_t sfb0 = load_scale(b_scales, scale_col, block_base, n, k_blocks);
    const uint8_t sfb1 = load_scale(b_scales, scale_col, block_base + 1u, n, k_blocks);
    const bool invalid_scale = sfa0 == 0xffu || sfa1 == 0xffu ||
                               sfb0 == 0xffu || sfb1 == 0xffu;
    if (__any_sync(0xffffffffu, invalid_scale)) {
      if (lane == 0) {
        record_status(status, kStatusScaleNan | (block_base + 1u));
      }
      return;
    }

    const unsigned a_row0 = tile_m + t1;
    const unsigned a_row1 = a_row0 + 8u;
    const unsigned b_col = tile_n + t1;
    const unsigned k_lane = k_base + t0 * 8u;
    const uint32_t a0 = load_fp4_eight(a_codes, a_row0, k_lane, m, k_blocks);
    const uint32_t a1 = load_fp4_eight(a_codes, a_row1, k_lane, m, k_blocks);
    const uint32_t a2 = load_fp4_eight(a_codes, a_row0, k_lane + 32u, m, k_blocks);
    const uint32_t a3 = load_fp4_eight(a_codes, a_row1, k_lane + 32u, m, k_blocks);
    const uint32_t b0 = load_fp4_eight(b_codes, b_col, k_lane, n, k_blocks);
    const uint32_t b1 = load_fp4_eight(b_codes, b_col, k_lane + 32u, n, k_blocks);
    const uint16_t sfa = uint16_t(sfa0) | (uint16_t(sfa1) << 8);
    const uint16_t sfb = uint16_t(sfb0) | (uint16_t(sfb1) << 8);
    mma_mxfp4_e2m1_ue8m0(d0, d1, d2, d3,
                          a0, a1, a2, a3, b0, b1, sfa, sfb);
  }

  store_tile(d0, d1, d2, d3, lane, tile_m, tile_n, m, n, out, status);
}

extern "C" __global__ __launch_bounds__(kWarpSize)
void gemm_mxfp8_e4m3_fp32_accum_kernel(
    const uint8_t* a_codes, const uint8_t* a_scales,
    const uint8_t* b_codes, const uint8_t* b_scales,
    unsigned m, unsigned k, unsigned n, unsigned k_blocks,
    float* out, uint32_t* status) {
  const unsigned lane = threadIdx.x;
  const unsigned tile_m = blockIdx.y * 16u;
  const unsigned tile_n = blockIdx.x * 8u;
  const unsigned t0 = lane & 3u;
  const unsigned t1 = lane >> 2;
  const unsigned scale_row = tile_m + ((lane & 1u) << 3) + (lane >> 2);
  const unsigned scale_col = tile_n + (lane >> 2);
  float d0 = 0.0f;
  float d1 = 0.0f;
  float d2 = 0.0f;
  float d3 = 0.0f;

  for (unsigned block = 0; block < k_blocks; ++block) {
    const uint8_t sfa = load_scale(a_scales, scale_row, block, m, k_blocks);
    const uint8_t sfb = load_scale(b_scales, scale_col, block, n, k_blocks);
    const unsigned a_row0 = tile_m + t1;
    const unsigned a_row1 = a_row0 + 8u;
    const unsigned b_col = tile_n + t1;
    const unsigned k_lane = block * 32u + t0 * 4u;
    const uint32_t a0 = load_fp8_four(a_codes, a_row0, k_lane, m, k_blocks);
    const uint32_t a1 = load_fp8_four(a_codes, a_row1, k_lane, m, k_blocks);
    const uint32_t a2 = load_fp8_four(a_codes, a_row0, k_lane + 16u, m, k_blocks);
    const uint32_t a3 = load_fp8_four(a_codes, a_row1, k_lane + 16u, m, k_blocks);
    const uint32_t b0 = load_fp8_four(b_codes, b_col, k_lane, n, k_blocks);
    const uint32_t b1 = load_fp8_four(b_codes, b_col, k_lane + 16u, n, k_blocks);
    const bool invalid = sfa == 0xffu || sfb == 0xffu ||
        e4m3_word_has_nan(a0) || e4m3_word_has_nan(a1) ||
        e4m3_word_has_nan(a2) || e4m3_word_has_nan(a3) ||
        e4m3_word_has_nan(b0) || e4m3_word_has_nan(b1);
    if (__any_sync(0xffffffffu, invalid)) {
      if (lane == 0) {
        record_status(status, kStatusScaleNan | (block + 1u));
      }
      return;
    }
    mma_mxfp8_e4m3_ue8m0(d0, d1, d2, d3,
                          a0, a1, a2, a3, b0, b1, sfa, sfb);
  }

  store_tile(d0, d1, d2, d3, lane, tile_m, tile_n, m, n, out, status);
}
