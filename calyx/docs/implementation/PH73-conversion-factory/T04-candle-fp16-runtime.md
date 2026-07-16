# PH73 T04 - Candle Precision and Device Runtime

## Scope

`LensRuntime::CandleLocal` freezes the model artifact set, execution device,
model precision, pooling policy, normalization policy, context limit, and exact
execution semantics. Legacy `candle-fp16` manifests remain readable only when
their full contract is explicit; new commissioning uses `--runtime candle`.

## Runtime Contract

- `execution_device`: required `cpu` or `cuda:<ordinal>`. It is part of lens
  identity. Missing legacy values fail for explicit migration rather than
  becoming `cuda:0`.
- model dtype: `f16`, `bf16`, or `f32`; CPU execution requires a distinct F32
  identity.
- accumulation dtype: F32. Candle's process-global F32/F16/BF16 reduced
  precision GEMM switches are set false and verified before and after model
  load/inference.
- output dtype: dense F32 after one model forward, deterministic fixed-order
  pooling, and the declared norm policy.
- pooling: `mean` or `cls`. Unknown model ids have no global model-specific
  default and must declare dtype and pooling explicitly.
- config: parsed exactly from the frozen bytes. There is no layer-normalization
  epsilon rewrite, second-precision replay, or silent CPU retry.
- CUDA auto policy: select CPU only when the binary has no CUDA feature or the
  driver reports no device. Driver/runtime, ordinal, allocation, model-load,
  and inference failures after CUDA selection fail loud with stage/device/dtype
  context.
- contract: v3 hashes model id, max tokens, execution device, model dtype,
  pooling, normalization, and the exact-config/single-execution/F32-accumulation
  policy. Artifact drift or execution-policy drift creates a different lens or
  a frozen-violation error.

## Guards

- Missing/corrupt artifacts: `CALYX_LENS_CONFIG_INVALID` or
  `CALYX_LENS_FROZEN_VIOLATION`.
- Missing/invalid device or CPU half precision: `CALYX_LENS_CONFIG_INVALID`.
- Invalid CUDA ordinal: `CALYX_CANDLE_CUDA_DEVICE_INVALID`.
- CUDA initialization/load/inference failure: `CALYX_LENS_UNREACHABLE` with
  stage, frozen device, declared/executed model dtype, F32 accumulation, and F32
  output context.
- Dimension mismatch: `CALYX_LENS_DIM_MISMATCH`.
- NaN/Inf/zero norm: `CALYX_LENS_NUMERICAL_INVARIANT`.
- CUDA allocation OOM: `CALYX_VRAM_OOM`.

## LensForge

`calyx lens commission --runtime candle --dtype <f16|bf16|f32> --device
<auto|cuda|cpu>` downloads and freezes `model.safetensors`, `tokenizer.json`,
`config.json`, and present tokenizer sidecars. The command resolves auto device
placement before naming/writing, requires an empty output directory, runs the
real batch preflight, writes an execution-device manifest, registers it, and
verifies catalog readback. Failed/frozen outputs are not overwritten.

## Required FSV

Source of truth is the canonical Windows workspace plus the commissioned
manifest/artifacts and Aster catalog rows:

- native GNU CUDA build fingerprinted to an exact commit and binary hash;
- actual artifact hashes/byte counts and explicit manifest device/dtype;
- F16/BF16/F32 real-model vectors compared with the F32 semantic baseline;
- separate declared, executed, accumulation, and output dtype readback;
- `nvidia-smi`/NVML process, utilization, and memory evidence during inference;
- repeated vector hashes/norms plus known paraphrase/unrelated cosine ordering;
- CPU/F32 companion behavior from a no-CUDA build or explicit CPU contract;
- invalid dtype/device, missing device, non-empty output, and artifact-tamper
  edges with before/after catalog and file-state readback;
- `target/` absent after the contiguous manual verification batch.

No test suite or CI result is accepted as verification.
