use std::env;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde::Deserialize;
use sha2::{Digest, Sha256};

const CUDA_ARCH: &str = "sm_120a";
const CUDA_CCBIN_ENV: &str = "FORGE_CUDA_CCBIN";
const EXPECTED_CUDA_TOOLKIT_VERSION: &str = "13.3.0";
const EXPECTED_CUDA_VERSION_MANIFEST_SHA256: &str =
    "7a600527fedf8205de85a506d7bcc01c3d85a6a8db45f030523797eeb2a356cb";
const EXPECTED_NVCC_RELEASE: &str = "13.3";
const EXPECTED_NVCC_VERSION: &str = "V13.3.33";
const EXPECTED_NVCC_BUILD: &str = "cuda_13.3.r13.3/compiler.37862127_0";
const EXPECTED_NVCC_SHA256: &str =
    "7d22bb271001d342f35dadd83132205ad656c9697f3d5438d8a48214c3528d5c";
const EXPECTED_HOST_COMPILER_SHA256: &str =
    "b192a7a622e59e934589b7b45bc242ddd531bad0c0e0911c60547db2d626a343";
const POLICY_PATH: &str = "cuda-kernel-policy-v1.json";
const POLICY_SCHEMA: &str = "calyx.forge.cuda-kernel-policy.v1";
const POLICY_MEASUREMENT_SCHEMA: &str = "calyx.forge.cuda-kernel-measurement.v1";
const BUILD_SCHEMA: &str = "calyx.forge.cuda-kernel-build.v1";
const PENDING_MEASUREMENT_NOTE: &str = "Transient bootstrap record used only by the explicit cuda-policy-measurement build. Replace with physical RTX 5090 measurements before production verification.";
const MEASUREMENT_ROUNDS: usize = 5;
const MEASUREMENT_WARM_RUNS: u64 = 100;
const EXPECTED_DEVICE_NAME: &str = "NVIDIA GeForce RTX 5090";
const EXPECTED_DEVICE_UUID: &str = "GPU-de2d5475-3447-83c3-1539-876a7257ae8a";
const EXPECTED_DEVICE_PCI_BUS_ID: &str = "0000:01:00.0";
const MODULE_KIND_DECISION_RULE: &str = "require PTX/CUBIN bit parity for every kernel/FMAD pair, then select exact-sm_120a CUBIN to eliminate driver JIT and unused production PTX";
const FMAD_DECISION_RULE: &str = "select the lower measured distance max-absolute-error; if equal, select the lower sum of per-kernel median CUBIN warm totals";

struct ToolkitComponentSpec {
    name: &'static str,
    relative_path: &'static str,
    expected_sha256: &'static str,
}

const TOOLKIT_COMPONENTS: &[ToolkitComponentSpec] = &[
    ToolkitComponentSpec {
        name: "nvcc.exe",
        relative_path: "bin/nvcc.exe",
        expected_sha256: EXPECTED_NVCC_SHA256,
    },
    ToolkitComponentSpec {
        name: "cicc.exe",
        relative_path: "nvvm/bin/cicc.exe",
        expected_sha256: "a1e730f8a002ceb970736ea6890a77a457b186c9696bf648e5c391331f5d49ba",
    },
    ToolkitComponentSpec {
        name: "ptxas.exe",
        relative_path: "bin/ptxas.exe",
        expected_sha256: "10bc9ae3c12501609edbef725774b9d0297f9e3c421fa45e6b5146cd48f624f8",
    },
    ToolkitComponentSpec {
        name: "fatbinary.exe",
        relative_path: "bin/fatbinary.exe",
        expected_sha256: "e856de32c63e664a2e1dfad933efe19e9a05ae53ade926be34d22fc96cbb61c5",
    },
];

struct Kernel {
    name: &'static str,
    source: &'static str,
    cubin_env: &'static str,
    measurement_env_prefix: &'static str,
    entry_points: &'static [&'static str],
}

const KERNELS: &[Kernel] = &[
    Kernel {
        name: "distance",
        source: "src/cuda/kernels/distance.cu",
        cubin_env: "FORGE_DISTANCE_CUBIN_PATH",
        measurement_env_prefix: "FORGE_DISTANCE",
        entry_points: &[
            "cosine_batch_f32",
            "dot_batch_f32",
            "l2_batch_f32",
            "normalize_rows_f32",
        ],
    },
    Kernel {
        name: "topk",
        source: "src/cuda/kernels/topk.cu",
        cubin_env: "FORGE_TOPK_CUBIN_PATH",
        measurement_env_prefix: "FORGE_TOPK",
        entry_points: &["bitonic_topk_f32"],
    },
    Kernel {
        name: "mxfp_gemm",
        source: "src/cuda/kernels/mxfp4_gemm.cu",
        cubin_env: "FORGE_MXFP_GEMM_CUBIN_PATH",
        measurement_env_prefix: "FORGE_MXFP_GEMM",
        entry_points: &[
            "gemm_mxfp4_e2m1_fp32_accum_kernel",
            "gemm_mxfp8_e4m3_fp32_accum_kernel",
        ],
    },
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KernelPolicy {
    schema: String,
    status: String,
    measurement_issue: u64,
    decision: KernelDecision,
    measurement: serde_json::Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KernelDecision {
    module_kind: String,
    fmad: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingMeasurement {
    note: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MeasuredKernelPolicy {
    schema: String,
    measured_at_utc: String,
    source: MeasurementSource,
    device: MeasurementDevice,
    toolchain: MeasurementToolchain,
    protocol: MeasurementProtocol,
    decision_evidence: MeasurementDecisionEvidence,
    results: Vec<MeasurementResult>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MeasurementSource {
    report_tree_sha: String,
    report_sha256: String,
    report_bytes: u64,
    evidence_inventory_sha256: String,
    measurement_json_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MeasurementDevice {
    name: String,
    uuid: String,
    pci_bus_id: String,
    compute_capability: [u32; 2],
    driver_version: String,
    runtime_ordinal: u32,
    driver_ordinal: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MeasurementToolchain {
    toolkit_version: String,
    version_manifest_sha256: String,
    nvcc_version: String,
    nvcc_build: String,
    nvcc_sha256: String,
    host_compiler_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MeasurementProtocol {
    rounds: usize,
    warm_runs: u64,
    ordering: String,
    module_kind_decision_rule: String,
    fmad_decision_rule: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MeasurementDecisionEvidence {
    cubin_ptx_bit_parity: bool,
    distance_max_abs_error_fmad_off: f64,
    distance_max_abs_error_fmad_on: f64,
    cubin_warm_median_sum_ns_fmad_off: u64,
    cubin_warm_median_sum_ns_fmad_on: u64,
    cubin_module_load_median_sum_ns: u64,
    ptx_module_load_median_sum_ns: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MeasurementResult {
    module_name: String,
    module_kind: String,
    fmad: bool,
    artifact_bytes: u64,
    artifact_sha256: String,
    output_bytes: u64,
    output_sha256: String,
    correctness_verified: bool,
    max_abs_error_f64: f64,
    max_abs_error_bound_f64: f64,
    module_load_ns: Vec<u64>,
    function_load_ns: Vec<u64>,
    first_dispatch_ns: Vec<u64>,
    warm_total_ns: Vec<u64>,
}

struct NvccAttestation {
    release: String,
    version: String,
    build: String,
    sha256: String,
}

struct ToolkitComponentAttestation {
    name: &'static str,
    sha256: String,
}

struct ToolkitAttestation {
    version: String,
    version_manifest_sha256: String,
    components: Vec<ToolkitComponentAttestation>,
}

struct ModuleAttestation {
    name: &'static str,
    source_sha256: String,
    module_sha256: String,
    module_bytes: u64,
    entry_points: &'static [&'static str],
}

fn main() {
    if !cuda_feature_enabled() {
        println!("cargo:warning=cuda feature not enabled, skipping kernel compilation");
        return;
    }
    require_windows_target();

    let manifest_dir = PathBuf::from(required_env("CARGO_MANIFEST_DIR"));
    let out_dir = PathBuf::from(required_env("OUT_DIR"));
    let kernel_out_dir = out_dir.join("forge-cuda-kernels");
    std::fs::create_dir_all(&kernel_out_dir).unwrap_or_else(|error| {
        panic!(
            "CALYX_FORGE_CUDA_OUTPUT_CREATE_FAILED: path={} detail={error}",
            kernel_out_dir.display()
        )
    });

    println!("cargo:rerun-if-env-changed=CUDA_PATH");
    println!("cargo:rerun-if-env-changed={CUDA_CCBIN_ENV}");
    println!("cargo:rerun-if-changed={POLICY_PATH}");

    let policy_path = manifest_dir.join(POLICY_PATH);
    let (policy, measured_policy, policy_sha256) = read_policy(&policy_path);
    let nvcc = locate_nvcc();
    let host_compiler = locate_cuda_host_compiler();
    let host_compiler_sha256 = sha256_file(&host_compiler);
    if host_compiler_sha256 != EXPECTED_HOST_COMPILER_SHA256 {
        panic!(
            "CALYX_FORGE_CUDA_HOST_COMPILER_HASH_MISMATCH: path={} expected={} observed={host_compiler_sha256}; restore the pinned Visual C++ host compiler selected by the native Windows launcher",
            host_compiler.display(),
            EXPECTED_HOST_COMPILER_SHA256
        );
    }
    let toolkit_attestation = attest_cuda_toolkit(&nvcc);
    let nvcc_attestation = attest_nvcc(&nvcc);
    let measurement = measurement_feature_enabled();

    let mut modules = Vec::with_capacity(KERNELS.len());
    for kernel in KERNELS {
        let source = manifest_dir.join(kernel.source);
        println!("cargo:rerun-if-changed={}", kernel.source);
        require_file(
            &source,
            "CALYX_FORGE_CUDA_KERNEL_SOURCE_MISSING",
            "CUDA kernel source",
        );

        let chosen_cubin = if measurement {
            compile_measurement_matrix(
                &nvcc,
                &host_compiler,
                kernel,
                &source,
                &kernel_out_dir,
                policy.decision.fmad,
            )
        } else {
            let cubin = kernel_out_dir.join(format!("{}.cubin", kernel.name));
            compile_kernel(
                &nvcc,
                &host_compiler,
                &source,
                &cubin,
                OutputKind::Cubin,
                policy.decision.fmad,
            );
            cubin
        };
        validate_output(&chosen_cubin, kernel.name, "cubin");
        println!(
            "cargo:rustc-env={}={}",
            kernel.cubin_env,
            chosen_cubin.display()
        );
        modules.push(ModuleAttestation {
            name: kernel.name,
            source_sha256: sha256_file(&source),
            module_sha256: sha256_file(&chosen_cubin),
            module_bytes: file_len(&chosen_cubin),
            entry_points: kernel.entry_points,
        });
    }
    validate_selected_modules(&policy, measured_policy.as_ref(), &modules);

    generate_build_attestation(
        &out_dir.join("forge_cuda_kernel_build.rs"),
        &toolkit_attestation,
        &nvcc_attestation,
        &host_compiler_sha256,
        &policy,
        &policy_sha256,
        &modules,
    );
    println!(
        "cargo:warning=CALYX_FORGE_CUDA_BUILD_ATTESTED toolkit={} toolkit_manifest_sha256={} nvcc={} release={} build={} nvcc_sha256={} target={} module_kind=cubin fmad={} policy_sha256={}",
        toolkit_attestation.version,
        toolkit_attestation.version_manifest_sha256,
        nvcc_attestation.version,
        nvcc_attestation.release,
        nvcc_attestation.build,
        nvcc_attestation.sha256,
        CUDA_ARCH,
        policy.decision.fmad,
        policy_sha256
    );
}

fn cuda_feature_enabled() -> bool {
    env::var_os("CARGO_FEATURE_CUDA").is_some()
}

fn measurement_feature_enabled() -> bool {
    env::var_os("CARGO_FEATURE_CUDA_POLICY_MEASUREMENT").is_some()
}

fn require_windows_target() {
    let target_os = required_env("CARGO_CFG_TARGET_OS");
    if target_os != "windows" {
        panic!(
            "CALYX_FORGE_CUDA_TARGET_UNSUPPORTED: target_os={target_os}; the current exact CUDA kernel contract is Windows-only"
        );
    }
}

fn locate_nvcc() -> PathBuf {
    let cuda_path = env::var_os("CUDA_PATH").unwrap_or_else(|| {
        panic!(
            "CALYX_FORGE_CUDA_PATH_MISSING: CUDA_PATH must name the exact CUDA 13.3.33 toolkit root"
        )
    });
    let nvcc = PathBuf::from(cuda_path).join("bin").join("nvcc.exe");
    require_file(&nvcc, "CALYX_FORGE_CUDA_NVCC_MISSING", "CUDA compiler");
    nvcc
}

fn locate_cuda_host_compiler() -> PathBuf {
    let raw = env::var_os(CUDA_CCBIN_ENV).unwrap_or_else(|| {
        panic!(
            "CALYX_FORGE_CUDA_HOST_COMPILER_MISSING: {CUDA_CCBIN_ENV} must point to the exact cl.exe or its Hostx64\\x64 directory"
        )
    });
    let path = PathBuf::from(raw);
    let compiler = if path.is_dir() {
        path.join("cl.exe")
    } else {
        path
    };
    require_file(
        &compiler,
        "CALYX_FORGE_CUDA_HOST_COMPILER_INVALID",
        "CUDA host compiler",
    );
    if !compiler
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case("cl.exe"))
    {
        panic!(
            "CALYX_FORGE_CUDA_HOST_COMPILER_INVALID: path={} must name cl.exe",
            compiler.display()
        );
    }
    compiler
}

fn attest_cuda_toolkit(nvcc: &Path) -> ToolkitAttestation {
    let bin_dir = nvcc.parent().unwrap_or_else(|| {
        panic!(
            "CALYX_FORGE_CUDA_TOOLKIT_LAYOUT_INVALID: nvcc path has no bin directory: {}",
            nvcc.display()
        )
    });
    let toolkit_root = bin_dir.parent().unwrap_or_else(|| {
        panic!(
            "CALYX_FORGE_CUDA_TOOLKIT_LAYOUT_INVALID: nvcc bin path has no toolkit root: {}",
            nvcc.display()
        )
    });
    let version_manifest = toolkit_root.join("version.json");
    require_file(
        &version_manifest,
        "CALYX_FORGE_CUDA_VERSION_MANIFEST_MISSING",
        "CUDA toolkit version manifest",
    );
    let version_manifest_bytes = std::fs::read(&version_manifest).unwrap_or_else(|error| {
        panic!(
            "CALYX_FORGE_CUDA_VERSION_MANIFEST_READ_FAILED: path={} detail={error}",
            version_manifest.display()
        )
    });
    let version_manifest_sha256 = sha256_bytes(&version_manifest_bytes);
    if version_manifest_sha256 != EXPECTED_CUDA_VERSION_MANIFEST_SHA256 {
        panic!(
            "CALYX_FORGE_CUDA_VERSION_MANIFEST_HASH_MISMATCH: path={} expected={} observed={version_manifest_sha256}; reinstall the pinned CUDA 13.3 toolkit",
            version_manifest.display(),
            EXPECTED_CUDA_VERSION_MANIFEST_SHA256
        );
    }
    let manifest: serde_json::Value = serde_json::from_slice(&version_manifest_bytes)
        .unwrap_or_else(|error| {
            panic!(
                "CALYX_FORGE_CUDA_VERSION_MANIFEST_INVALID: path={} detail={error}",
                version_manifest.display()
            )
        });
    let toolkit_version = manifest
        .get("cuda")
        .and_then(|cuda| cuda.get("version"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| {
            panic!(
                "CALYX_FORGE_CUDA_VERSION_MANIFEST_INVALID: path={} omits cuda.version",
                version_manifest.display()
            )
        });
    if toolkit_version != EXPECTED_CUDA_TOOLKIT_VERSION {
        panic!(
            "CALYX_FORGE_CUDA_TOOLKIT_VERSION_MISMATCH: expected={EXPECTED_CUDA_TOOLKIT_VERSION} observed={toolkit_version}"
        );
    }
    let manifest_nvcc_version = manifest
        .get("cuda_nvcc")
        .and_then(|cuda| cuda.get("version"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| {
            panic!(
                "CALYX_FORGE_CUDA_VERSION_MANIFEST_INVALID: path={} omits cuda_nvcc.version",
                version_manifest.display()
            )
        });
    if manifest_nvcc_version != EXPECTED_NVCC_VERSION.trim_start_matches('V') {
        panic!(
            "CALYX_FORGE_CUDA_TOOLKIT_NVCC_VERSION_MISMATCH: expected={} observed={manifest_nvcc_version}",
            EXPECTED_NVCC_VERSION.trim_start_matches('V')
        );
    }

    let mut components = Vec::with_capacity(TOOLKIT_COMPONENTS.len());
    for component in TOOLKIT_COMPONENTS {
        let path = toolkit_root.join(component.relative_path);
        require_file(
            &path,
            "CALYX_FORGE_CUDA_TOOLKIT_COMPONENT_MISSING",
            component.name,
        );
        let sha256 = sha256_file(&path);
        if sha256 != component.expected_sha256 {
            panic!(
                "CALYX_FORGE_CUDA_TOOLKIT_COMPONENT_HASH_MISMATCH: component={} path={} expected={} observed={sha256}; reinstall the pinned CUDA 13.3.33 compiler toolchain",
                component.name,
                path.display(),
                component.expected_sha256
            );
        }
        components.push(ToolkitComponentAttestation {
            name: component.name,
            sha256,
        });
    }
    ToolkitAttestation {
        version: toolkit_version.to_string(),
        version_manifest_sha256,
        components,
    }
}

fn attest_nvcc(nvcc: &Path) -> NvccAttestation {
    let output = Command::new(nvcc)
        .arg("--version")
        .output()
        .unwrap_or_else(|error| {
            panic!(
                "CALYX_FORGE_CUDA_NVCC_EXEC_FAILED: command={} --version detail={error}",
                nvcc.display()
            )
        });
    let output = require_success(nvcc, &["--version".to_string()], output);
    let stdout = String::from_utf8(output.stdout).unwrap_or_else(|error| {
        panic!("CALYX_FORGE_CUDA_NVCC_VERSION_INVALID: stdout is not UTF-8: {error}")
    });
    if !output.stderr.is_empty() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!(
            "CALYX_FORGE_CUDA_NVCC_VERSION_INVALID: nvcc --version emitted unexpected stderr: {stderr}"
        );
    }
    let release_line = stdout
        .lines()
        .find(|line| line.starts_with("Cuda compilation tools, release "))
        .unwrap_or_else(|| {
            panic!(
                "CALYX_FORGE_CUDA_NVCC_VERSION_INVALID: missing exact release line in stdout={stdout:?}"
            )
        });
    let expected_release_line =
        format!("Cuda compilation tools, release {EXPECTED_NVCC_RELEASE}, {EXPECTED_NVCC_VERSION}");
    if release_line != expected_release_line {
        panic!(
            "CALYX_FORGE_CUDA_NVCC_VERSION_MISMATCH: expected={expected_release_line:?} observed={release_line:?}"
        );
    }
    let build_line = stdout
        .lines()
        .find(|line| line.starts_with("Build "))
        .unwrap_or_else(|| {
            panic!(
                "CALYX_FORGE_CUDA_NVCC_VERSION_INVALID: missing exact build line in stdout={stdout:?}"
            )
        });
    let observed_build = build_line
        .strip_prefix("Build ")
        .expect("checked build prefix");
    if observed_build != EXPECTED_NVCC_BUILD {
        panic!(
            "CALYX_FORGE_CUDA_NVCC_BUILD_MISMATCH: expected={EXPECTED_NVCC_BUILD} observed={observed_build}"
        );
    }
    let sha256 = sha256_file(nvcc);
    if sha256 != EXPECTED_NVCC_SHA256 {
        panic!(
            "CALYX_FORGE_CUDA_NVCC_HASH_MISMATCH: path={} expected={} observed={sha256}; reinstall the pinned CUDA 13.3.33 toolkit",
            nvcc.display(),
            EXPECTED_NVCC_SHA256
        );
    }
    NvccAttestation {
        release: EXPECTED_NVCC_RELEASE.to_string(),
        version: EXPECTED_NVCC_VERSION.to_string(),
        build: EXPECTED_NVCC_BUILD.to_string(),
        sha256,
    }
}

fn read_policy(path: &Path) -> (KernelPolicy, Option<MeasuredKernelPolicy>, String) {
    require_file(
        path,
        "CALYX_FORGE_CUDA_POLICY_MISSING",
        "CUDA kernel policy",
    );
    let bytes = std::fs::read(path).unwrap_or_else(|error| {
        panic!(
            "CALYX_FORGE_CUDA_POLICY_READ_FAILED: path={} detail={error}",
            path.display()
        )
    });
    let policy: KernelPolicy = serde_json::from_slice(&bytes).unwrap_or_else(|error| {
        panic!(
            "CALYX_FORGE_CUDA_POLICY_INVALID: path={} detail={error}",
            path.display()
        )
    });
    if policy.schema != POLICY_SCHEMA {
        panic!(
            "CALYX_FORGE_CUDA_POLICY_SCHEMA_MISMATCH: expected={POLICY_SCHEMA} observed={}",
            policy.schema
        );
    }
    if policy.measurement_issue != 492 {
        panic!(
            "CALYX_FORGE_CUDA_POLICY_ISSUE_MISMATCH: expected=492 observed={}",
            policy.measurement_issue
        );
    }
    if policy.decision.module_kind != "cubin" {
        panic!(
            "CALYX_FORGE_CUDA_POLICY_MODULE_KIND_INVALID: expected=cubin observed={}",
            policy.decision.module_kind
        );
    }
    if !policy.measurement.is_object() {
        panic!("CALYX_FORGE_CUDA_POLICY_INVALID: measurement must be a JSON object");
    }
    let measured = match policy.status.as_str() {
        "measurement-pending" => {
            if !measurement_feature_enabled() {
                panic!(
                    "CALYX_FORGE_CUDA_POLICY_UNMEASURED: the production build refuses the transient measurement-pending policy; run the explicit cuda-policy-measurement FSV and persist its decision"
                );
            }
            if policy.decision.fmad {
                panic!(
                    "CALYX_FORGE_CUDA_POLICY_PENDING_DECISION_INVALID: the transient measurement build must use the declared fmad=false bootstrap baseline"
                );
            }
            let pending: PendingMeasurement = serde_json::from_value(policy.measurement.clone())
                .unwrap_or_else(|error| {
                    panic!("CALYX_FORGE_CUDA_POLICY_PENDING_INVALID: measurement detail={error}")
                });
            if pending.note != PENDING_MEASUREMENT_NOTE {
                panic!(
                    "CALYX_FORGE_CUDA_POLICY_PENDING_INVALID: the transient note differs from the one explicit measurement bootstrap contract"
                );
            }
            None
        }
        "measured" => {
            let measured: MeasuredKernelPolicy = serde_json::from_value(policy.measurement.clone())
                .unwrap_or_else(|error| {
                    panic!(
                        "CALYX_FORGE_CUDA_POLICY_MEASUREMENT_INVALID: measurement detail={error}"
                    )
                });
            validate_measured_policy(&policy.decision, &measured);
            Some(measured)
        }
        status => panic!(
            "CALYX_FORGE_CUDA_POLICY_STATUS_INVALID: expected one of measurement-pending|measured observed={status}"
        ),
    };
    (policy, measured, sha256_bytes(&bytes))
}

fn validate_measured_policy(decision: &KernelDecision, measured: &MeasuredKernelPolicy) {
    if measured.schema != POLICY_MEASUREMENT_SCHEMA {
        panic!(
            "CALYX_FORGE_CUDA_POLICY_MEASUREMENT_SCHEMA_MISMATCH: expected={POLICY_MEASUREMENT_SCHEMA} observed={}",
            measured.schema
        );
    }
    if measured.measured_at_utc.len() < 20 || !measured.measured_at_utc.ends_with('Z') {
        panic!(
            "CALYX_FORGE_CUDA_POLICY_MEASURED_AT_INVALID: expected a non-empty UTC timestamp ending in Z observed={:?}",
            measured.measured_at_utc
        );
    }
    require_sha256(
        "source.report_tree_sha",
        &measured.source.report_tree_sha,
        40,
    );
    require_sha256("source.report_sha256", &measured.source.report_sha256, 64);
    require_sha256(
        "source.evidence_inventory_sha256",
        &measured.source.evidence_inventory_sha256,
        64,
    );
    require_sha256(
        "source.measurement_json_sha256",
        &measured.source.measurement_json_sha256,
        64,
    );
    if measured.source.report_bytes == 0 {
        panic!("CALYX_FORGE_CUDA_POLICY_MEASUREMENT_INVALID: source.report_bytes must be positive");
    }
    if measured.device.name != EXPECTED_DEVICE_NAME
        || measured.device.uuid != EXPECTED_DEVICE_UUID
        || measured.device.pci_bus_id != EXPECTED_DEVICE_PCI_BUS_ID
        || measured.device.compute_capability != [12, 0]
        || measured.device.runtime_ordinal != 0
        || measured.device.driver_ordinal != 0
        || measured.device.driver_version.trim().is_empty()
    {
        panic!(
            "CALYX_FORGE_CUDA_POLICY_DEVICE_INVALID: expected name={EXPECTED_DEVICE_NAME:?} uuid={EXPECTED_DEVICE_UUID} pci={} capability=12.0 ordinals=0/0; observed name={:?} uuid={} pci={} capability={}.{} ordinals={}/{} driver={:?}",
            EXPECTED_DEVICE_PCI_BUS_ID,
            measured.device.name,
            measured.device.uuid,
            measured.device.pci_bus_id,
            measured.device.compute_capability[0],
            measured.device.compute_capability[1],
            measured.device.runtime_ordinal,
            measured.device.driver_ordinal,
            measured.device.driver_version
        );
    }
    if measured.toolchain.toolkit_version != EXPECTED_CUDA_TOOLKIT_VERSION
        || measured.toolchain.version_manifest_sha256 != EXPECTED_CUDA_VERSION_MANIFEST_SHA256
        || measured.toolchain.nvcc_version != EXPECTED_NVCC_VERSION
        || measured.toolchain.nvcc_build != EXPECTED_NVCC_BUILD
        || measured.toolchain.nvcc_sha256 != EXPECTED_NVCC_SHA256
        || measured.toolchain.host_compiler_sha256 != EXPECTED_HOST_COMPILER_SHA256
    {
        panic!(
            "CALYX_FORGE_CUDA_POLICY_TOOLCHAIN_INVALID: measured toolchain does not equal the pinned CUDA 13.3.33/host-compiler contract"
        );
    }
    if measured.protocol.rounds != MEASUREMENT_ROUNDS
        || measured.protocol.warm_runs != MEASUREMENT_WARM_RUNS
        || measured.protocol.ordering != "round-robin-rotated-and-reversed-v1"
        || measured.protocol.module_kind_decision_rule != MODULE_KIND_DECISION_RULE
        || measured.protocol.fmad_decision_rule != FMAD_DECISION_RULE
    {
        panic!(
            "CALYX_FORGE_CUDA_POLICY_PROTOCOL_INVALID: the measured protocol differs from the frozen five-round/100-warm-run decision contract"
        );
    }
    if measured.results.len() != KERNELS.len() * 4 {
        panic!(
            "CALYX_FORGE_CUDA_POLICY_RESULT_COUNT_INVALID: expected={} observed={}",
            KERNELS.len() * 4,
            measured.results.len()
        );
    }
    for kernel in KERNELS {
        for module_kind in ["ptx", "cubin"] {
            for fmad in [false, true] {
                let matches = measured
                    .results
                    .iter()
                    .filter(|result| {
                        result.module_name == kernel.name
                            && result.module_kind == module_kind
                            && result.fmad == fmad
                    })
                    .collect::<Vec<_>>();
                if matches.len() != 1 {
                    panic!(
                        "CALYX_FORGE_CUDA_POLICY_RESULT_MATRIX_INVALID: module={} kind={} fmad={} matches={}",
                        kernel.name,
                        module_kind,
                        fmad,
                        matches.len()
                    );
                }
                validate_measurement_result(matches[0]);
            }
        }
    }

    for kernel in KERNELS {
        for fmad in [false, true] {
            let ptx = find_measurement_result(measured, kernel.name, "ptx", fmad);
            let cubin = find_measurement_result(measured, kernel.name, "cubin", fmad);
            if ptx.output_sha256 != cubin.output_sha256
                || ptx.output_bytes != cubin.output_bytes
                || ptx.max_abs_error_f64 != cubin.max_abs_error_f64
                || ptx.max_abs_error_bound_f64 != cubin.max_abs_error_bound_f64
            {
                panic!(
                    "CALYX_FORGE_CUDA_POLICY_PTX_CUBIN_PARITY_FAILED: module={} fmad={} ptx_output={} cubin_output={} ptx_error={} cubin_error={}",
                    kernel.name,
                    fmad,
                    ptx.output_sha256,
                    cubin.output_sha256,
                    ptx.max_abs_error_f64,
                    cubin.max_abs_error_f64
                );
            }
        }
    }

    let distance_error_off = distance_max_abs_error(measured, false);
    let distance_error_on = distance_max_abs_error(measured, true);
    let cubin_warm_off = warm_median_sum(measured, "cubin", Some(false));
    let cubin_warm_on = warm_median_sum(measured, "cubin", Some(true));
    let cubin_load = module_load_median_sum(measured, "cubin");
    let ptx_load = module_load_median_sum(measured, "ptx");
    let evidence = &measured.decision_evidence;
    if !evidence.cubin_ptx_bit_parity
        || evidence.distance_max_abs_error_fmad_off != distance_error_off
        || evidence.distance_max_abs_error_fmad_on != distance_error_on
        || evidence.cubin_warm_median_sum_ns_fmad_off != cubin_warm_off
        || evidence.cubin_warm_median_sum_ns_fmad_on != cubin_warm_on
        || evidence.cubin_module_load_median_sum_ns != cubin_load
        || evidence.ptx_module_load_median_sum_ns != ptx_load
    {
        panic!(
            "CALYX_FORGE_CUDA_POLICY_DECISION_EVIDENCE_INVALID: stored decision summary differs from the physical result matrix"
        );
    }
    let measured_fmad = if distance_error_off < distance_error_on {
        false
    } else if distance_error_on < distance_error_off {
        true
    } else if cubin_warm_off < cubin_warm_on {
        false
    } else if cubin_warm_on < cubin_warm_off {
        true
    } else {
        panic!(
            "CALYX_FORGE_CUDA_POLICY_FMAD_DECISION_AMBIGUOUS: accuracy and CUBIN median warm totals are exactly tied; collect a fresh physical measurement"
        );
    };
    if decision.fmad != measured_fmad {
        panic!(
            "CALYX_FORGE_CUDA_POLICY_FMAD_DECISION_INVALID: policy={} measurement={measured_fmad} distance_error_off={distance_error_off} distance_error_on={distance_error_on} warm_off={cubin_warm_off} warm_on={cubin_warm_on}",
            decision.fmad
        );
    }
}

fn validate_measurement_result(result: &MeasurementResult) {
    require_sha256("result.artifact_sha256", &result.artifact_sha256, 64);
    require_sha256("result.output_sha256", &result.output_sha256, 64);
    if result.artifact_bytes == 0
        || result.output_bytes == 0
        || !result.correctness_verified
        || !result.max_abs_error_f64.is_finite()
        || result.max_abs_error_f64 < 0.0
        || !result.max_abs_error_bound_f64.is_finite()
        || result.max_abs_error_bound_f64 < 0.0
        || result.max_abs_error_f64 > result.max_abs_error_bound_f64
    {
        panic!(
            "CALYX_FORGE_CUDA_POLICY_RESULT_INVALID: module={} kind={} fmad={} artifact_bytes={} output_bytes={} correctness={} max_abs_error={} max_abs_error_bound={}",
            result.module_name,
            result.module_kind,
            result.fmad,
            result.artifact_bytes,
            result.output_bytes,
            result.correctness_verified,
            result.max_abs_error_f64,
            result.max_abs_error_bound_f64
        );
    }
    let expected_output_bytes = match result.module_name.as_str() {
        "distance" => 128 * 4,
        "topk" => 32 * 8,
        "mxfp_gemm" => 16 * 8 * 4,
        other => panic!("CALYX_FORGE_CUDA_POLICY_RESULT_INVALID: unknown module={other}"),
    };
    if result.output_bytes != expected_output_bytes {
        panic!(
            "CALYX_FORGE_CUDA_POLICY_RESULT_OUTPUT_SIZE_INVALID: module={} expected={} observed={}",
            result.module_name, expected_output_bytes, result.output_bytes
        );
    }
    for (name, values) in [
        ("module_load_ns", &result.module_load_ns),
        ("function_load_ns", &result.function_load_ns),
        ("first_dispatch_ns", &result.first_dispatch_ns),
        ("warm_total_ns", &result.warm_total_ns),
    ] {
        if values.len() != MEASUREMENT_ROUNDS || values.contains(&0) {
            panic!(
                "CALYX_FORGE_CUDA_POLICY_RESULT_TIMING_INVALID: module={} kind={} fmad={} field={name} expected_positive_count={} observed={values:?}",
                result.module_name, result.module_kind, result.fmad, MEASUREMENT_ROUNDS
            );
        }
    }
}

fn find_measurement_result<'a>(
    measured: &'a MeasuredKernelPolicy,
    module_name: &str,
    module_kind: &str,
    fmad: bool,
) -> &'a MeasurementResult {
    measured
        .results
        .iter()
        .find(|result| {
            result.module_name == module_name
                && result.module_kind == module_kind
                && result.fmad == fmad
        })
        .unwrap_or_else(|| {
            panic!(
                "CALYX_FORGE_CUDA_POLICY_RESULT_MISSING: module={module_name} kind={module_kind} fmad={fmad}"
            )
        })
}

fn distance_max_abs_error(measured: &MeasuredKernelPolicy, fmad: bool) -> f64 {
    ["ptx", "cubin"]
        .iter()
        .map(|kind| find_measurement_result(measured, "distance", kind, fmad).max_abs_error_f64)
        .fold(0.0_f64, f64::max)
}

fn warm_median_sum(measured: &MeasuredKernelPolicy, module_kind: &str, fmad: Option<bool>) -> u64 {
    KERNELS
        .iter()
        .flat_map(|kernel| {
            [false, true]
                .into_iter()
                .filter(move |candidate| fmad.is_none_or(|expected| *candidate == expected))
                .map(move |candidate| {
                    median(
                        &find_measurement_result(measured, kernel.name, module_kind, candidate)
                            .warm_total_ns,
                    )
                })
        })
        .try_fold(0_u64, u64::checked_add)
        .unwrap_or_else(|| {
            panic!("CALYX_FORGE_CUDA_POLICY_TIMING_OVERFLOW: warm median sum exceeds u64")
        })
}

fn module_load_median_sum(measured: &MeasuredKernelPolicy, module_kind: &str) -> u64 {
    measured
        .results
        .iter()
        .filter(|result| result.module_kind == module_kind)
        .map(|result| median(&result.module_load_ns))
        .try_fold(0_u64, u64::checked_add)
        .unwrap_or_else(|| {
            panic!("CALYX_FORGE_CUDA_POLICY_TIMING_OVERFLOW: module-load median sum exceeds u64")
        })
}

fn median(values: &[u64]) -> u64 {
    let mut ordered = values.to_vec();
    ordered.sort_unstable();
    ordered[ordered.len() / 2]
}

fn require_sha256(field: &str, value: &str, length: usize) {
    if value.len() != length
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        panic!(
            "CALYX_FORGE_CUDA_POLICY_HASH_INVALID: field={field} expected_lower_hex_length={length} observed={value:?}"
        );
    }
}

fn validate_selected_modules(
    policy: &KernelPolicy,
    measured: Option<&MeasuredKernelPolicy>,
    modules: &[ModuleAttestation],
) {
    let Some(measured) = measured else {
        if policy.status != "measurement-pending" {
            panic!(
                "CALYX_FORGE_CUDA_POLICY_MEASUREMENT_MISSING: status={} has no parsed measurement",
                policy.status
            );
        }
        return;
    };
    for module in modules {
        let selected =
            find_measurement_result(measured, module.name, "cubin", policy.decision.fmad);
        if module.module_sha256 != selected.artifact_sha256
            || module.module_bytes != selected.artifact_bytes
        {
            panic!(
                "CALYX_FORGE_CUDA_SELECTED_ARTIFACT_MISMATCH: module={} fmad={} measured_bytes={} built_bytes={} measured_sha256={} built_sha256={}; source/compiler/output drift requires a fresh physical measurement",
                module.name,
                policy.decision.fmad,
                selected.artifact_bytes,
                module.module_bytes,
                selected.artifact_sha256,
                module.module_sha256
            );
        }
    }
}

fn compile_measurement_matrix(
    nvcc: &Path,
    host_compiler: &Path,
    kernel: &Kernel,
    source: &Path,
    out_dir: &Path,
    selected_fmad: bool,
) -> PathBuf {
    let mut selected = None;
    for fmad in [false, true] {
        for output_kind in [OutputKind::Ptx, OutputKind::Cubin] {
            let fmad_label = if fmad { "on" } else { "off" };
            let extension = output_kind.extension();
            let path = out_dir.join(format!("{}.fmad-{fmad_label}.{extension}", kernel.name));
            compile_kernel(nvcc, host_compiler, source, &path, output_kind, fmad);
            validate_output(&path, kernel.name, extension);
            let env_name = format!(
                "{}_FMAD_{}_{}_PATH",
                kernel.measurement_env_prefix,
                fmad_label.to_ascii_uppercase(),
                extension.to_ascii_uppercase()
            );
            println!("cargo:rustc-env={env_name}={}", path.display());
            if output_kind == OutputKind::Cubin && fmad == selected_fmad {
                selected = Some(path);
            }
        }
    }
    selected.expect("measurement matrix always includes selected CUBIN")
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum OutputKind {
    Ptx,
    Cubin,
}

impl OutputKind {
    const fn flag(self) -> &'static str {
        match self {
            Self::Ptx => "--ptx",
            Self::Cubin => "-cubin",
        }
    }

    const fn extension(self) -> &'static str {
        match self {
            Self::Ptx => "ptx",
            Self::Cubin => "cubin",
        }
    }
}

fn compile_kernel(
    nvcc: &Path,
    host_compiler: &Path,
    source: &Path,
    output: &Path,
    output_kind: OutputKind,
    fmad: bool,
) {
    let args = compiler_args(source, output, output_kind, host_compiler, fmad);
    let process_output = Command::new(nvcc)
        .args(&args)
        .output()
        .unwrap_or_else(|error| {
            panic!(
                "CALYX_FORGE_CUDA_NVCC_EXEC_FAILED: command={} {} detail={error}",
                nvcc.display(),
                args.join(" ")
            )
        });
    let process_output = require_success(nvcc, &args, process_output);
    let expected_stdout = format!(
        "{}\r\n",
        source
            .file_name()
            .and_then(|name| name.to_str())
            .expect("validated CUDA source has a UTF-8 filename")
    );
    if process_output.stdout != expected_stdout.as_bytes() || !process_output.stderr.is_empty() {
        panic!(
            "CALYX_FORGE_CUDA_NVCC_UNEXPECTED_OUTPUT: command={} {} expected_stdout={expected_stdout:?} observed_stdout={:?} stderr={:?}",
            nvcc.display(),
            args.join(" "),
            String::from_utf8_lossy(&process_output.stdout),
            String::from_utf8_lossy(&process_output.stderr)
        );
    }
}

fn compiler_args(
    source: &Path,
    output: &Path,
    output_kind: OutputKind,
    host_compiler: &Path,
    fmad: bool,
) -> Vec<String> {
    let host_dir = host_compiler
        .parent()
        .expect("validated cl.exe always has a parent");
    vec![
        format!("-arch={CUDA_ARCH}"),
        "-O3".to_string(),
        "--ftz=false".to_string(),
        "--prec-div=true".to_string(),
        "--prec-sqrt=true".to_string(),
        format!("--fmad={fmad}"),
        "--compiler-bindir".to_string(),
        host_dir.display().to_string(),
        output_kind.flag().to_string(),
        "-o".to_string(),
        output.display().to_string(),
        source.display().to_string(),
    ]
}

fn generate_build_attestation(
    path: &Path,
    toolkit: &ToolkitAttestation,
    nvcc: &NvccAttestation,
    host_compiler_sha256: &str,
    policy: &KernelPolicy,
    policy_sha256: &str,
    modules: &[ModuleAttestation],
) {
    let flags = [
        format!("-arch={CUDA_ARCH}"),
        "-O3".to_string(),
        "--ftz=false".to_string(),
        "--prec-div=true".to_string(),
        "--prec-sqrt=true".to_string(),
        format!("--fmad={}", policy.decision.fmad),
        "-cubin".to_string(),
    ];
    let mut source = String::new();
    writeln!(
        source,
        "pub const CUDA_KERNEL_BUILD_ATTESTATION: CudaKernelBuildAttestation = CudaKernelBuildAttestation {{"
    )
    .unwrap();
    writeln!(source, "    schema: {BUILD_SCHEMA:?},").unwrap();
    writeln!(source, "    toolkit_version: {:?},", toolkit.version).unwrap();
    writeln!(
        source,
        "    toolkit_version_manifest_sha256: {:?},",
        toolkit.version_manifest_sha256
    )
    .unwrap();
    writeln!(source, "    toolkit_components: &[").unwrap();
    for component in &toolkit.components {
        writeln!(
            source,
            "        CudaToolkitComponentAttestation {{ name: {:?}, sha256: {:?} }},",
            component.name, component.sha256
        )
        .unwrap();
    }
    writeln!(source, "    ],").unwrap();
    writeln!(source, "    nvcc_release: {:?},", nvcc.release).unwrap();
    writeln!(source, "    nvcc_version: {:?},", nvcc.version).unwrap();
    writeln!(source, "    nvcc_build: {:?},", nvcc.build).unwrap();
    writeln!(source, "    nvcc_sha256: {:?},", nvcc.sha256).unwrap();
    writeln!(
        source,
        "    host_compiler_sha256: {host_compiler_sha256:?},"
    )
    .unwrap();
    writeln!(source, "    target: {CUDA_ARCH:?},").unwrap();
    writeln!(source, "    module_kind: \"cubin\",").unwrap();
    writeln!(source, "    fmad: {},", policy.decision.fmad).unwrap();
    writeln!(source, "    compiler_flags: &[").unwrap();
    for flag in &flags {
        writeln!(source, "        {flag:?},").unwrap();
    }
    writeln!(source, "    ],").unwrap();
    writeln!(source, "    policy_record_sha256: {policy_sha256:?},").unwrap();
    writeln!(source, "    modules: &[").unwrap();
    for module in modules {
        writeln!(
            source,
            "        CudaKernelModuleAttestation {{ name: {:?}, source_sha256: {:?}, module_sha256: {:?}, module_bytes: {}, entry_points: &[",
            module.name, module.source_sha256, module.module_sha256, module.module_bytes
        )
        .unwrap();
        for entry in module.entry_points {
            writeln!(source, "            {entry:?},").unwrap();
        }
        writeln!(source, "        ] }},").unwrap();
    }
    writeln!(source, "    ],").unwrap();
    writeln!(source, "}};").unwrap();
    std::fs::write(path, source.as_bytes()).unwrap_or_else(|error| {
        panic!(
            "CALYX_FORGE_CUDA_ATTESTATION_WRITE_FAILED: path={} detail={error}",
            path.display()
        )
    });
    let readback = std::fs::read(path).unwrap_or_else(|error| {
        panic!(
            "CALYX_FORGE_CUDA_ATTESTATION_READBACK_FAILED: path={} detail={error}",
            path.display()
        )
    });
    if readback != source.as_bytes() {
        panic!(
            "CALYX_FORGE_CUDA_ATTESTATION_READBACK_MISMATCH: path={}",
            path.display()
        );
    }
}

fn validate_output(path: &Path, kernel: &str, kind: &str) {
    require_file(
        path,
        "CALYX_FORGE_CUDA_KERNEL_OUTPUT_MISSING",
        "compiled CUDA kernel",
    );
    let bytes = file_len(path);
    if bytes == 0 {
        panic!(
            "CALYX_FORGE_CUDA_KERNEL_OUTPUT_EMPTY: kernel={kernel} kind={kind} path={}",
            path.display()
        );
    }
}

fn require_success(command: &Path, args: &[String], output: Output) -> Output {
    if output.status.success() {
        return output;
    }
    panic!(
        "CALYX_FORGE_CUDA_COMMAND_FAILED: command={} {} status={} stdout={:?} stderr={:?}",
        command.display(),
        args.join(" "),
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn require_file(path: &Path, code: &str, label: &str) {
    if !path.is_file() {
        panic!("{code}: {label} is not a file: {}", path.display());
    }
}

fn required_env(name: &str) -> String {
    env::var(name).unwrap_or_else(|error| panic!("{name} is required: {error}"))
}

fn file_len(path: &Path) -> u64 {
    std::fs::metadata(path)
        .unwrap_or_else(|error| panic!("metadata failed for {}: {error}", path.display()))
        .len()
}

fn sha256_file(path: &Path) -> String {
    let bytes = std::fs::read(path)
        .unwrap_or_else(|error| panic!("read failed for {}: {error}", path.display()));
    sha256_bytes(&bytes)
}

fn sha256_bytes(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
