use std::path::Path;
use std::str::FromStr;

use calyx_core::{
    CalyxError, OnnxCommittedSessionPlacementEvidence, OnnxCudaExecutionEvidence,
    OnnxFirstInferencePlacementEvidence, Result, RuntimeExecutionAttestation,
};
use calyx_forge::PinnedCudaDeviceIdentity;

pub const ONNX_CUSTOM_RUNTIME_ID: &str = "onnx-custom";
pub const ONNX_COLBERT_RUNTIME_ID: &str = "onnx-colbert";
pub const ONNX_FASTEMBED_RUNTIME_ID: &str = "onnx-fastembed-5.16.0-owned";

/// Serializes one already-observed CUDA ONNX receipt through the same strict
/// contract used by every consumer.
pub(super) fn serialize_cuda_onnx_execution_evidence(
    evidence: &OnnxCudaExecutionEvidence,
) -> Result<String> {
    validate_evidence(evidence)?;
    serde_json::to_string(evidence).map_err(|error| {
        invalid(format!(
            "serialize structured CUDA ONNX execution evidence failed: {error}"
        ))
    })
}

/// Validates a retained CUDA ONNX attestation without accepting legacy labels,
/// substring matches, inferred placement, or provider/device fallbacks.
pub fn validate_cuda_onnx_execution_attestation(
    attestation: &RuntimeExecutionAttestation,
    expected_runtime: &str,
) -> Result<OnnxCudaExecutionEvidence> {
    if expected_runtime.trim().is_empty() || attestation.runtime != expected_runtime {
        return Err(invalid(format!(
            "expected exact runtime {expected_runtime:?}, observed {:?}",
            attestation.runtime
        )));
    }
    let total = attestation.total_compute_nodes.ok_or_else(|| {
        invalid("runtime attestation omitted committed-session total compute nodes")
    })?;
    let cpu = attestation.cpu_compute_nodes.ok_or_else(|| {
        invalid("runtime attestation omitted committed-session CPU compute nodes")
    })?;
    if total == 0 {
        return Err(invalid(
            "runtime attestation reported zero committed-session compute nodes",
        ));
    }
    if cpu != 0 || cpu > total {
        return Err(placement(format!(
            "runtime attestation placed cpu_nodes={cpu}/{total}; CUDA fail-loud execution requires exactly zero CPU nodes"
        )));
    }

    let evidence: OnnxCudaExecutionEvidence =
        serde_json::from_str(&attestation.evidence).map_err(|error| {
            invalid(format!(
                "execution evidence is not the strict current structured CUDA ONNX receipt: {error}"
            ))
        })?;
    validate_evidence(&evidence)?;
    if evidence.committed_session.total_compute_nodes != total
        || evidence.committed_session.cpu_compute_nodes != cpu
    {
        return Err(invalid(format!(
            "outer committed-session counts total={total} cpu={cpu} differ from structured evidence total={} cpu={}",
            evidence.committed_session.total_compute_nodes,
            evidence.committed_session.cpu_compute_nodes
        )));
    }

    let expected_provider = format!(
        "api24={};profile={}",
        evidence.committed_session.providers, evidence.first_inference_profile.providers
    );
    if attestation.provider != expected_provider {
        return Err(placement(format!(
            "provider receipt differs from the exact committed-session/profile evidence: expected {expected_provider:?}, observed {:?}",
            attestation.provider
        )));
    }

    let physical_device = PinnedCudaDeviceIdentity::from_str(
        &evidence.retained_stream.physical_device,
    )
    .map_err(|error| {
        placement(format!(
            "retained stream physical device {:?} is not a stable PCI+GPU-UUID identity: {error}",
            evidence.retained_stream.physical_device
        ))
    })?;
    let canonical_device = physical_device.canonical_execution_token();
    if evidence.retained_stream.physical_device != canonical_device
        || attestation.device != canonical_device
    {
        return Err(placement(format!(
            "execution device must exactly equal retained canonical physical identity {canonical_device:?}; observed device={:?} stream_identity={:?}",
            attestation.device, evidence.retained_stream.physical_device
        )));
    }
    Ok(evidence)
}

fn validate_evidence(evidence: &OnnxCudaExecutionEvidence) -> Result<()> {
    validate_stream_address(&evidence.retained_stream.stream_address)?;
    validate_committed_session(&evidence.committed_session)?;
    validate_first_inference(&evidence.first_inference_profile)?;
    if evidence.profile_path.trim() != evidence.profile_path
        || evidence.profile_path.is_empty()
        || !Path::new(&evidence.profile_path).is_absolute()
    {
        return Err(invalid(format!(
            "profile path must be a nonblank absolute canonical path, observed {:?}",
            evidence.profile_path
        )));
    }
    if evidence.profile_sha256.len() != 64
        || !evidence
            .profile_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(format!(
            "profile SHA-256 must be exactly 64 lowercase hexadecimal characters, observed {:?}",
            evidence.profile_sha256
        )));
    }
    Ok(())
}

fn validate_stream_address(address: &str) -> Result<()> {
    let Some(hex) = address.strip_prefix("0x") else {
        return Err(invalid(format!(
            "retained CUDA stream address must use canonical 0x-prefixed hexadecimal form, observed {address:?}"
        )));
    };
    if hex.is_empty()
        || hex.bytes().all(|byte| byte == b'0')
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(format!(
            "retained CUDA stream address is null or noncanonical: {address:?}"
        )));
    }
    Ok(())
}

fn validate_committed_session(placement: &OnnxCommittedSessionPlacementEvidence) -> Result<()> {
    validate_exclusive_cuda_counts(
        "committed API-24 session",
        placement.total_compute_nodes,
        placement.cuda_compute_nodes,
        placement.cpu_compute_nodes,
        &placement.providers,
    )?;
    let Some(operators) = placement
        .assigned_operators
        .strip_prefix("CUDAExecutionProvider:[")
        .and_then(|value| value.strip_suffix(']'))
    else {
        return Err(invalid(format!(
            "committed-session assigned operators must be one exact CUDAExecutionProvider list, observed {:?}",
            placement.assigned_operators
        )));
    };
    if operators.is_empty()
        || operators
            .split(',')
            .any(|operator| operator.is_empty() || operator.trim() != operator)
    {
        return Err(invalid(format!(
            "committed-session assigned-operator list is empty or noncanonical: {:?}",
            placement.assigned_operators
        )));
    }
    Ok(())
}

fn validate_first_inference(placement: &OnnxFirstInferencePlacementEvidence) -> Result<()> {
    validate_exclusive_cuda_counts(
        "first real synchronized inference profile",
        placement.total_compute_nodes,
        placement.cuda_compute_nodes,
        placement.cpu_compute_nodes,
        &placement.providers,
    )
}

fn validate_exclusive_cuda_counts(
    stage: &str,
    total: u64,
    cuda: u64,
    cpu: u64,
    providers: &str,
) -> Result<()> {
    if total == 0 {
        return Err(invalid(format!("{stage} reported zero compute nodes")));
    }
    if cpu != 0 || cuda != total {
        return Err(placement(format!(
            "{stage} requires exclusive CUDA placement, observed cuda={cuda}/{total} cpu={cpu}"
        )));
    }
    let expected = format!("CUDAExecutionProvider:{total}");
    if providers != expected {
        return Err(placement(format!(
            "{stage} provider summary must be exactly {expected:?}, observed {providers:?}"
        )));
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: "CALYX_ONNX_EXECUTION_ATTESTATION_INVALID",
        message: message.into(),
        remediation: "use the Calyx-owned ONNX session path that records exact API-24 assignment, retained stream/device identity, and first-real-inference profile as the current structured receipt; legacy or incomplete evidence is never accepted",
    }
}

fn placement(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: "CALYX_ONNX_EXECUTION_PLACEMENT_MISMATCH",
        message: message.into(),
        remediation: "use a CUDA-compatible graph whose every committed and executed compute node is on CUDAExecutionProvider, with one retained stream bound to the frozen physical device; never enable or retry on CPU",
    }
}
