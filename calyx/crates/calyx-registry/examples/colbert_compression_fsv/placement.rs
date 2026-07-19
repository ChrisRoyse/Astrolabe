use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};

use calyx_core::{
    Input, LensId, Modality, OnnxCudaExecutionEvidence, RuntimeExecutionAttestation, SlotVector,
};
use calyx_registry::{
    NormPolicy, ONNX_COLBERT_RUNTIME_ID, ONNX_CUSTOM_RUNTIME_ID,
    ONNX_EXECUTION_EVIDENCE_STORE_DIRECTORY, OnnxColbertFileSpec, OnnxColbertLens, OnnxFileSpec,
    OnnxLens, OnnxProviderPolicy, PoolingPolicy, Registry, validate_cpu_onnx_execution_attestation,
    validate_cuda_onnx_execution_attestation,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

type AnyResult<T> = Result<T, Box<dyn Error>>;

const ATTESTATION_FILE: &str = "execution-attestation.json";
const PROBE_RECEIPT_FILE: &str = "placement-receipt.json";
const PROBE_RECEIPT_SCHEMA: &str = "astrolabe.issue605.onnx-placement-probe.v1";
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
const MAX_INVENTORY_ENTRIES: usize = 16_384;
const MAX_INVENTORY_DEPTH: usize = 64;
const MAX_INVENTORY_FILE_BYTES: u64 = 4 * 1024 * 1024 * 1024;

#[derive(Clone, Copy)]
pub enum RuntimeKind {
    Custom,
    Colbert,
}

impl RuntimeKind {
    const fn runtime_id(self) -> &'static str {
        match self {
            Self::Custom => ONNX_CUSTOM_RUNTIME_ID,
            Self::Colbert => ONNX_COLBERT_RUNTIME_ID,
        }
    }
}

#[derive(Clone, Copy)]
pub struct ProbeKind {
    runtime: RuntimeKind,
    policy: OnnxProviderPolicy,
    expected_placement: ExpectedPlacement,
}

#[derive(Clone, Copy)]
enum ExpectedPlacement {
    StrictAllCuda,
    ClassifiedCpuMetadata,
    ExplicitCpu,
}

impl ProbeKind {
    pub fn parse(raw: &str) -> AnyResult<Self> {
        match raw {
            "custom-cuda-all" => Ok(Self {
                runtime: RuntimeKind::Custom,
                policy: OnnxProviderPolicy::CudaFailLoud,
                expected_placement: ExpectedPlacement::StrictAllCuda,
            }),
            "colbert-cuda-all" => Ok(Self {
                runtime: RuntimeKind::Colbert,
                policy: OnnxProviderPolicy::CudaFailLoud,
                expected_placement: ExpectedPlacement::StrictAllCuda,
            }),
            "custom-cuda-metadata" => Ok(Self {
                runtime: RuntimeKind::Custom,
                policy: OnnxProviderPolicy::CudaFailLoud,
                expected_placement: ExpectedPlacement::ClassifiedCpuMetadata,
            }),
            "colbert-cuda-metadata" => Ok(Self {
                runtime: RuntimeKind::Colbert,
                policy: OnnxProviderPolicy::CudaFailLoud,
                expected_placement: ExpectedPlacement::ClassifiedCpuMetadata,
            }),
            "custom-cpu" => Ok(Self {
                runtime: RuntimeKind::Custom,
                policy: OnnxProviderPolicy::CpuExplicit,
                expected_placement: ExpectedPlacement::ExplicitCpu,
            }),
            "colbert-cpu" => Ok(Self {
                runtime: RuntimeKind::Colbert,
                policy: OnnxProviderPolicy::CpuExplicit,
                expected_placement: ExpectedPlacement::ExplicitCpu,
            }),
            _ => Err(format!(
                "unsupported placement probe {raw:?}; expected custom-cuda-all, colbert-cuda-all, custom-cuda-metadata, colbert-cuda-metadata, custom-cpu, or colbert-cpu"
            )
            .into()),
        }
    }

    const fn label(self) -> &'static str {
        match (self.runtime, self.expected_placement) {
            (RuntimeKind::Custom, ExpectedPlacement::StrictAllCuda) => "custom-cuda-all",
            (RuntimeKind::Colbert, ExpectedPlacement::StrictAllCuda) => "colbert-cuda-all",
            (RuntimeKind::Custom, ExpectedPlacement::ClassifiedCpuMetadata) => {
                "custom-cuda-metadata"
            }
            (RuntimeKind::Colbert, ExpectedPlacement::ClassifiedCpuMetadata) => {
                "colbert-cuda-metadata"
            }
            (RuntimeKind::Custom, ExpectedPlacement::ExplicitCpu) => "custom-cpu",
            (RuntimeKind::Colbert, ExpectedPlacement::ExplicitCpu) => "colbert-cpu",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct FileReceipt {
    relative_path: String,
    bytes: u64,
    sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct DirectoryReceipt {
    exists: bool,
    directories: Vec<String>,
    files: Vec<FileReceipt>,
    digest_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct InputArtifactReceipt {
    label: String,
    path: PathBuf,
    bytes: u64,
    sha256: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct PersistedProbeReceipt {
    schema: String,
    issue: u64,
    probe: String,
    lens_id: LensId,
    runtime: String,
    policy: String,
    inputs: Vec<InputArtifactReceipt>,
    expected_vector_sha256: String,
    vector_sha256: String,
    vector_kind: String,
    scalar_count: u64,
    finite_scalar_count: u64,
    vector: SlotVector,
    attestation: RuntimeExecutionAttestation,
    cuda_evidence: Option<OnnxCudaExecutionEvidence>,
}

pub fn probe(
    kind: ProbeKind,
    model: &Path,
    tokenizer: &Path,
    config: &Path,
    input_file: &Path,
    expected_vector_sha256: &str,
    state_root: &Path,
) -> AnyResult<()> {
    let model_parent = model
        .parent()
        .ok_or("placement probe model path has no parent")?;
    let evidence_root = model_parent.join(ONNX_EXECUTION_EVIDENCE_STORE_DIRECTORY);
    let state_before = directory_receipt(state_root)?;
    let evidence_before = directory_receipt(&evidence_root)?;
    println!(
        "{}",
        json!({
            "event": "placement_probe_before",
            "issue": 605,
            "probe": kind.label(),
            "model": model,
            "input_file": input_file,
            "source_of_truth": state_root,
            "state": state_before,
            "diagnostic_evidence_store": evidence_before,
        })
    );

    let result = if state_before.exists {
        Err(format!(
            "placement probe state root already exists: {}",
            state_root.display()
        )
        .into())
    } else {
        execute_probe(
            kind,
            model,
            tokenizer,
            config,
            input_file,
            expected_vector_sha256,
            state_root,
        )
    };
    let state_after = directory_receipt(state_root)?;
    let evidence_after = directory_receipt(&evidence_root)?;
    match result {
        Ok(readback) => {
            let exact_files = state_after
                .files
                .iter()
                .map(|file| file.relative_path.as_str())
                .collect::<Vec<_>>();
            if !state_after.exists
                || !state_after.directories.is_empty()
                || exact_files != [ATTESTATION_FILE, PROBE_RECEIPT_FILE]
            {
                return Err(format!(
                    "accepted placement probe did not publish the exact flat two-file state contract: directories={:?} files={exact_files:?}",
                    state_after.directories
                )
                .into());
            }
            println!(
                "{}",
                json!({
                    "event": "placement_probe_after",
                    "issue": 605,
                    "probe": kind.label(),
                    "source_of_truth": state_root,
                    "state": state_after,
                    "diagnostic_evidence_store": evidence_after,
                    "accepted": true,
                })
            );
            println!(
                "{}",
                json!({
                    "event": "placement_probe_success",
                    "issue": 605,
                    "probe": kind.label(),
                    "readback": readback,
                })
            );
            Ok(())
        }
        Err(error) => {
            println!(
                "{}",
                json!({
                    "event": "placement_probe_after",
                    "issue": 605,
                    "probe": kind.label(),
                    "source_of_truth": state_root,
                    "state": state_after,
                    "diagnostic_evidence_store": evidence_after,
                    "accepted": false,
                })
            );
            if state_after.exists {
                return Err(format!(
                    "rejected placement probe mutated downstream state {} before failing: {error}",
                    state_root.display()
                )
                .into());
            }
            println!(
                "{}",
                json!({
                    "event": "placement_probe_rejected",
                    "issue": 605,
                    "probe": kind.label(),
                    "error": super::structured_error(error.as_ref()),
                    "downstream_mutation": false,
                })
            );
            Err(error)
        }
    }
}

pub fn validate_saved(kind: ProbeKind, path: &Path) -> AnyResult<()> {
    let before = input_artifact_receipt("saved_attestation", path)?;
    println!(
        "{}",
        json!({
            "event": "saved_attestation_before",
            "issue": 605,
            "probe": kind.label(),
            "source_of_truth": before,
        })
    );
    let result = (|| -> AnyResult<_> {
        let bytes = fs::read(path)?;
        let attestation: RuntimeExecutionAttestation = serde_json::from_slice(&bytes)?;
        let evidence = validate_expected_placement(kind, &attestation)?;
        let after = input_artifact_receipt("saved_attestation", path)?;
        if after != before {
            return Err(format!(
                "saved attestation drifted during validation: before={before:?} after={after:?}"
            )
            .into());
        }
        Ok((after, evidence))
    })();
    match result {
        Ok((after, evidence)) => {
            println!(
                "{}",
                json!({
                    "event": "saved_attestation_after",
                    "issue": 605,
                    "probe": kind.label(),
                    "source_of_truth": after,
                    "accepted": true,
                    "expected_runtime": kind.runtime.runtime_id(),
                    "evidence": evidence,
                })
            );
            Ok(())
        }
        Err(error) => {
            let after = input_artifact_receipt("saved_attestation", path)?;
            println!(
                "{}",
                json!({
                    "event": "saved_attestation_after",
                    "issue": 605,
                    "probe": kind.label(),
                    "source_of_truth": after,
                    "accepted": false,
                    "error": super::structured_error(error.as_ref()),
                })
            );
            Err(error)
        }
    }
}

fn execute_probe(
    kind: ProbeKind,
    model: &Path,
    tokenizer: &Path,
    config: &Path,
    input_file: &Path,
    expected_vector_sha256: &str,
    state_root: &Path,
) -> AnyResult<PersistedProbeReceipt> {
    validate_sha256("expected vector", expected_vector_sha256)?;
    let inputs_before = input_artifact_receipts(model, tokenizer, config, input_file)?;
    let (registry, lens_id) = register_probe(kind, model, tokenizer, config)?;
    let input = Input::new(Modality::Text, fs::read(input_file)?);
    let vectors = registry.measure_batch(lens_id, &[input])?;
    let [vector] = <[SlotVector; 1]>::try_from(vectors).map_err(|vectors| {
        format!(
            "real placement probe returned {} vectors instead of one",
            vectors.len()
        )
    })?;
    let (vector_kind, scalar_count, finite_scalar_count) = scan_vector(&vector)?;
    if scalar_count == 0 || finite_scalar_count != scalar_count {
        return Err(format!(
            "real placement probe output is empty or non-finite: total={scalar_count} finite={finite_scalar_count}"
        )
        .into());
    }
    let vector_sha256 = slot_vector_sha256(&vector)?;
    if vector_sha256 != expected_vector_sha256 {
        return Err(format!(
            "real placement probe vector digest mismatch: expected={expected_vector_sha256} observed={vector_sha256} kind={vector_kind} scalars={scalar_count}"
        )
        .into());
    }
    let attestation = registry
        .execution_attestation(lens_id)?
        .ok_or("real placement probe returned no execution attestation")?;
    let cuda_evidence = validate_expected_placement(kind, &attestation)?;
    let inputs_after = input_artifact_receipts(model, tokenizer, config, input_file)?;
    if inputs_after != inputs_before {
        return Err(format!(
            "placement probe input artifacts drifted during real execution: before={inputs_before:?} after={inputs_after:?}"
        )
        .into());
    }
    let receipt = PersistedProbeReceipt {
        schema: PROBE_RECEIPT_SCHEMA.to_string(),
        issue: 605,
        probe: kind.label().to_string(),
        lens_id,
        runtime: kind.runtime.runtime_id().to_string(),
        policy: kind.policy.as_str().to_string(),
        inputs: inputs_after,
        expected_vector_sha256: expected_vector_sha256.to_string(),
        vector_sha256,
        vector_kind: vector_kind.to_string(),
        scalar_count,
        finite_scalar_count,
        vector,
        attestation,
        cuda_evidence,
    };
    publish_and_reopen_receipt(kind, state_root, &receipt)
}

fn register_probe(
    kind: ProbeKind,
    model: &Path,
    tokenizer: &Path,
    config: &Path,
) -> AnyResult<(Registry, LensId)> {
    let mut registry = Registry::new();
    let lens_id = match kind.runtime {
        RuntimeKind::Custom => {
            let spec = OnnxFileSpec::text(
                "issue605-custom-placement-probe",
                "issue605-custom-placement-probe",
                model,
                tokenizer,
                config,
                PoolingPolicy::Mean,
                NormPolicy::Finite,
            )
            .with_provider_policy(kind.policy);
            let lens = OnnxLens::from_files(spec)?;
            let contract = lens.contract().clone();
            let spec = lens.lens_spec();
            registry.register_frozen_with_spec(lens, contract, spec)?
        }
        RuntimeKind::Colbert => {
            let spec = OnnxColbertFileSpec::text(
                "issue605-colbert-placement-probe",
                "issue605-colbert-placement-probe",
                model,
                tokenizer,
                config,
            )
            .with_provider_policy(kind.policy);
            let lens = OnnxColbertLens::from_files(spec)?;
            let contract = lens.contract().clone();
            let spec = lens.lens_spec();
            registry.register_frozen_with_spec(lens, contract, spec)?
        }
    };
    Ok((registry, lens_id))
}

fn validate_expected_placement(
    kind: ProbeKind,
    attestation: &RuntimeExecutionAttestation,
) -> AnyResult<Option<OnnxCudaExecutionEvidence>> {
    match kind.expected_placement {
        ExpectedPlacement::ExplicitCpu => {
            validate_cpu_onnx_execution_attestation(attestation, kind.runtime.runtime_id())?;
            Ok(None)
        }
        ExpectedPlacement::StrictAllCuda | ExpectedPlacement::ClassifiedCpuMetadata => {
            let evidence =
                validate_cuda_onnx_execution_attestation(attestation, kind.runtime.runtime_id())?;
            let final_cpu = evidence.final_graph_placement.cpu_metadata_nodes;
            let profile_cpu = evidence.first_inference_profile.cpu_metadata_nodes;
            let expected = match kind.expected_placement {
                ExpectedPlacement::StrictAllCuda => final_cpu == 0 && profile_cpu == 0,
                ExpectedPlacement::ClassifiedCpuMetadata => {
                    final_cpu > 0 && profile_cpu == final_cpu
                }
                ExpectedPlacement::ExplicitCpu => unreachable!(),
            };
            if !expected {
                return Err(format!(
                    "CUDA placement class mismatch for {}: expected={} final_cpu_metadata={} profile_cpu_metadata={} final_cuda={} profile_cuda={}",
                    kind.label(),
                    match kind.expected_placement {
                        ExpectedPlacement::StrictAllCuda => "strict_all_cuda",
                        ExpectedPlacement::ClassifiedCpuMetadata => "classified_cpu_metadata",
                        ExpectedPlacement::ExplicitCpu => unreachable!(),
                    },
                    final_cpu,
                    profile_cpu,
                    evidence.final_graph_placement.cuda_compute_nodes,
                    evidence.first_inference_profile.cuda_compute_nodes
                )
                .into());
            }
            Ok(Some(evidence))
        }
    }
}

fn scan_vector(vector: &SlotVector) -> AnyResult<(&'static str, u64, u64)> {
    let (kind, scalar_count, finite_scalar_count) = match vector {
        SlotVector::Dense { data, .. } => {
            let (total, finite) = scan_scalars(data.iter())?;
            ("dense", total, finite)
        }
        SlotVector::Sparse { entries, .. } => {
            let (total, finite) = scan_scalars(entries.iter().map(|entry| &entry.val))?;
            ("sparse", total, finite)
        }
        SlotVector::Multi { tokens, .. } => {
            let (total, finite) = scan_scalars(tokens.iter().flat_map(|token| token.iter()))?;
            ("multi", total, finite)
        }
        SlotVector::Absent { reason } => {
            return Err(format!("real placement probe returned Absent: {reason:?}").into());
        }
    };
    Ok((kind, scalar_count, finite_scalar_count))
}

fn scan_scalars<'a>(mut values: impl Iterator<Item = &'a f32>) -> AnyResult<(u64, u64)> {
    values.try_fold((0u64, 0u64), |(total, finite), value| {
        let total = total
            .checked_add(1)
            .ok_or("vector scalar count exceeds u64")?;
        let finite = if value.is_finite() {
            finite
                .checked_add(1)
                .ok_or("finite vector scalar count exceeds u64")?
        } else {
            finite
        };
        Ok((total, finite))
    })
}

fn input_artifact_receipts(
    model: &Path,
    tokenizer: &Path,
    config: &Path,
    input_file: &Path,
) -> AnyResult<Vec<InputArtifactReceipt>> {
    [
        ("model", model),
        ("tokenizer", tokenizer),
        ("config", config),
        ("input", input_file),
    ]
    .into_iter()
    .map(|(label, path)| input_artifact_receipt(label, path))
    .collect()
}

fn input_artifact_receipt(label: &str, path: &Path) -> AnyResult<InputArtifactReceipt> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(format!(
            "{label} must be one regular non-reparse file: {}",
            path.display()
        )
        .into());
    }
    let canonical = fs::canonicalize(path)?;
    let bytes = fs::read(&canonical)?;
    let observed_bytes = u64::try_from(bytes.len())?;
    if observed_bytes != metadata.len() {
        return Err(format!(
            "{label} changed while hashing: metadata_bytes={} observed_bytes={} path={}",
            metadata.len(),
            observed_bytes,
            canonical.display()
        )
        .into());
    }
    Ok(InputArtifactReceipt {
        label: label.to_string(),
        path: canonical,
        bytes: observed_bytes,
        sha256: sha256_bytes(bytes),
    })
}

fn slot_vector_sha256(vector: &SlotVector) -> AnyResult<String> {
    let mut hash = Sha256::new();
    hash_part(&mut hash, b"astrolabe.issue605.slot-vector.v1")?;
    match vector {
        SlotVector::Dense { dim, data } => {
            hash_part(&mut hash, b"dense")?;
            hash_part(&mut hash, &dim.to_be_bytes())?;
            hash_part(&mut hash, &u64::try_from(data.len())?.to_be_bytes())?;
            for value in data {
                hash_part(&mut hash, &value.to_bits().to_be_bytes())?;
            }
        }
        SlotVector::Sparse { dim, entries } => {
            hash_part(&mut hash, b"sparse")?;
            hash_part(&mut hash, &dim.to_be_bytes())?;
            hash_part(&mut hash, &u64::try_from(entries.len())?.to_be_bytes())?;
            for entry in entries {
                hash_part(&mut hash, &entry.idx.to_be_bytes())?;
                hash_part(&mut hash, &entry.val.to_bits().to_be_bytes())?;
            }
        }
        SlotVector::Multi { token_dim, tokens } => {
            hash_part(&mut hash, b"multi")?;
            hash_part(&mut hash, &token_dim.to_be_bytes())?;
            hash_part(&mut hash, &u64::try_from(tokens.len())?.to_be_bytes())?;
            for token in tokens {
                hash_part(&mut hash, &u64::try_from(token.len())?.to_be_bytes())?;
                for value in token {
                    hash_part(&mut hash, &value.to_bits().to_be_bytes())?;
                }
            }
        }
        SlotVector::Absent { reason } => {
            return Err(format!("cannot hash absent placement vector: {reason:?}").into());
        }
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn publish_and_reopen_receipt(
    kind: ProbeKind,
    state_root: &Path,
    receipt: &PersistedProbeReceipt,
) -> AnyResult<PersistedProbeReceipt> {
    let parent = state_root
        .parent()
        .ok_or("placement state root has no parent")?;
    let pending_root = parent.join(format!(
        ".issue605-placement-{}-{}.pending",
        kind.label(),
        std::process::id()
    ));
    if pending_root.exists() {
        return Err(format!(
            "placement pending root already exists: {}",
            pending_root.display()
        )
        .into());
    }
    fs::create_dir(&pending_root)?;
    let attestation_bytes = serde_json::to_vec_pretty(&receipt.attestation)?;
    let receipt_bytes = serde_json::to_vec_pretty(receipt)?;
    write_synced_new(&pending_root.join(ATTESTATION_FILE), &attestation_bytes)?;
    write_synced_new(&pending_root.join(PROBE_RECEIPT_FILE), &receipt_bytes)?;
    let pending_attestation = fs::read(pending_root.join(ATTESTATION_FILE))?;
    let pending_receipt = fs::read(pending_root.join(PROBE_RECEIPT_FILE))?;
    if pending_attestation != attestation_bytes || pending_receipt != receipt_bytes {
        return Err("pending placement receipt bytes differ from the serialized contract".into());
    }
    let pending_attestation: RuntimeExecutionAttestation =
        serde_json::from_slice(&pending_attestation)?;
    let pending_receipt: PersistedProbeReceipt = serde_json::from_slice(&pending_receipt)?;
    if pending_attestation != receipt.attestation || pending_receipt != *receipt {
        return Err("pending placement receipt semantic readback differs".into());
    }
    validate_reopened_probe(kind, &pending_receipt)?;
    fs::rename(&pending_root, state_root)?;

    let final_attestation_bytes = fs::read(state_root.join(ATTESTATION_FILE))?;
    let final_receipt_bytes = fs::read(state_root.join(PROBE_RECEIPT_FILE))?;
    if final_attestation_bytes != attestation_bytes || final_receipt_bytes != receipt_bytes {
        return Err("published placement receipt bytes differ after atomic rename".into());
    }
    let final_attestation: RuntimeExecutionAttestation =
        serde_json::from_slice(&final_attestation_bytes)?;
    let final_receipt: PersistedProbeReceipt = serde_json::from_slice(&final_receipt_bytes)?;
    if final_attestation != final_receipt.attestation || final_receipt != *receipt {
        return Err("published placement receipt semantic readback differs".into());
    }
    validate_reopened_probe(kind, &final_receipt)?;
    Ok(final_receipt)
}

fn write_synced_new(path: &Path, bytes: &[u8]) -> AnyResult<()> {
    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    Ok(())
}

fn validate_reopened_probe(kind: ProbeKind, receipt: &PersistedProbeReceipt) -> AnyResult<()> {
    if receipt.schema != PROBE_RECEIPT_SCHEMA
        || receipt.issue != 605
        || receipt.probe != kind.label()
        || receipt.runtime != kind.runtime.runtime_id()
        || receipt.policy != kind.policy.as_str()
    {
        return Err(format!(
            "placement receipt identity mismatch for {}: {receipt:?}",
            kind.label()
        )
        .into());
    }
    validate_sha256("expected vector", &receipt.expected_vector_sha256)?;
    validate_sha256("observed vector", &receipt.vector_sha256)?;
    let observed_vector_sha256 = slot_vector_sha256(&receipt.vector)?;
    let (kind_name, scalar_count, finite_scalar_count) = scan_vector(&receipt.vector)?;
    if receipt.expected_vector_sha256 != receipt.vector_sha256
        || observed_vector_sha256 != receipt.vector_sha256
        || kind_name != receipt.vector_kind
        || scalar_count != receipt.scalar_count
        || finite_scalar_count != receipt.finite_scalar_count
        || scalar_count == 0
        || finite_scalar_count != scalar_count
    {
        return Err(format!(
            "reopened placement vector contract mismatch: expected_digest={} recorded_digest={} observed_digest={observed_vector_sha256} kind={kind_name}/{} scalars={scalar_count}/{} finite={finite_scalar_count}/{}",
            receipt.expected_vector_sha256,
            receipt.vector_sha256,
            receipt.vector_kind,
            receipt.scalar_count,
            receipt.finite_scalar_count
        )
        .into());
    }
    let observed_evidence = validate_expected_placement(kind, &receipt.attestation)?;
    if observed_evidence != receipt.cuda_evidence {
        return Err("reopened placement evidence differs from persisted typed evidence".into());
    }
    for expected in &receipt.inputs {
        let observed = input_artifact_receipt(&expected.label, &expected.path)?;
        if observed != *expected {
            return Err(format!(
                "reopened placement input drifted: expected={expected:?} observed={observed:?}"
            )
            .into());
        }
    }
    Ok(())
}

fn validate_sha256(label: &str, value: &str) -> AnyResult<()> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(format!("{label} SHA-256 is not canonical lowercase hex: {value:?}").into())
    }
}

fn directory_receipt(root: &Path) -> AnyResult<DirectoryReceipt> {
    let metadata = match fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(DirectoryReceipt {
                exists: false,
                directories: Vec::new(),
                files: Vec::new(),
                digest_sha256: sha256_bytes([]),
            });
        }
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(format!("inventory root is not a directory: {}", root.display()).into());
    }
    let mut paths = Vec::new();
    let mut directories = Vec::new();
    let mut entries = 0usize;
    collect_files(root, root, 0, &mut entries, &mut directories, &mut paths)?;
    paths.sort();
    directories.sort();
    let mut files = Vec::with_capacity(paths.len());
    let mut digest = Sha256::new();
    for relative_path in &directories {
        hash_part(&mut digest, b"directory")?;
        hash_part(&mut digest, relative_path.as_bytes())?;
    }
    for path in paths {
        let relative = path.strip_prefix(root)?;
        let relative_path = relative
            .to_str()
            .ok_or("inventory path is not UTF-8")?
            .replace('\\', "/");
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.len() > MAX_INVENTORY_FILE_BYTES {
            return Err(format!(
                "inventory file exceeds categorical byte bound {MAX_INVENTORY_FILE_BYTES}: {} has {} bytes",
                path.display(),
                metadata.len()
            )
            .into());
        }
        let bytes = fs::read(&path)?;
        if u64::try_from(bytes.len())? != metadata.len() {
            return Err(format!("inventory file changed while read: {}", path.display()).into());
        }
        let sha256 = sha256_bytes(&bytes);
        hash_part(&mut digest, b"file")?;
        hash_part(&mut digest, relative_path.as_bytes())?;
        hash_part(&mut digest, &bytes)?;
        files.push(FileReceipt {
            relative_path,
            bytes: u64::try_from(bytes.len())?,
            sha256,
        });
    }
    Ok(DirectoryReceipt {
        exists: true,
        directories,
        files,
        digest_sha256: format!("{:x}", digest.finalize()),
    })
}

fn collect_files(
    root: &Path,
    directory: &Path,
    depth: usize,
    entries: &mut usize,
    directories: &mut Vec<String>,
    out: &mut Vec<PathBuf>,
) -> AnyResult<()> {
    if depth > MAX_INVENTORY_DEPTH {
        return Err(format!(
            "inventory exceeds categorical depth bound {MAX_INVENTORY_DEPTH}: {}",
            directory.display()
        )
        .into());
    }
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        *entries = entries
            .checked_add(1)
            .ok_or("inventory entry count exceeds usize")?;
        if *entries > MAX_INVENTORY_ENTRIES {
            return Err(format!(
                "inventory exceeds categorical entry bound {MAX_INVENTORY_ENTRIES} under {}",
                root.display()
            )
            .into());
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink()
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(format!(
                "manual placement inventory refuses symlink/reparse entry under {}: {}",
                root.display(),
                path.display()
            )
            .into());
        }
        if metadata.is_dir() {
            let relative = path
                .strip_prefix(root)?
                .to_str()
                .ok_or("inventory directory path is not UTF-8")?
                .replace('\\', "/");
            directories.push(relative);
            collect_files(root, &path, depth + 1, entries, directories, out)?;
        } else if metadata.is_file() {
            out.push(path);
        } else {
            return Err(format!(
                "inventory entry is not a file or directory: {}",
                path.display()
            )
            .into());
        }
    }
    Ok(())
}

fn hash_part(hash: &mut Sha256, bytes: &[u8]) -> AnyResult<()> {
    hash.update(u64::try_from(bytes.len())?.to_be_bytes());
    hash.update(bytes);
    Ok(())
}

fn sha256_bytes(bytes: impl AsRef<[u8]>) -> String {
    format!("{:x}", Sha256::digest(bytes.as_ref()))
}
