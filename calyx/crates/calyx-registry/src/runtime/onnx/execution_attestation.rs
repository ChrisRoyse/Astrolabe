use std::collections::{BTreeMap, BTreeSet};
use std::path::Component;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use calyx_core::{
    CalyxError, OnnxApi24PartitionNodeEvidence, OnnxApi24PartitionReceiptEvidence,
    OnnxCudaExecutionEvidence, OnnxCudaExecutionEvidenceKind, OnnxFinalGraphNodeEvidence,
    OnnxFinalGraphPlacementEvidence, OnnxFirstInferencePlacementEvidence, OnnxPlacementNodeRole,
    OnnxProfiledNodeEvidence, Result, RuntimeExecutionAttestation,
};
use calyx_forge::PinnedCudaDeviceIdentity;
use sha2::{Digest, Sha256};

use super::cpu_fallback_audit::{
    API24_PARTITION_RECEIPT_SCHEMA, AssignedNode, CommittedGraphAssignment,
    reconcile_profile_with_optimized_graph, validate_partition_receipt,
};
use super::evidence_artifact::{
    MAX_OPTIMIZED_GRAPH_BYTES, MAX_PROFILE_TRACE_BYTES, STORE_DIRECTORY,
};
use super::placement_contract::{
    CUDA_PLACEMENT_CLASSIFIER_VERSION, CudaPlacementContract, classify_profiled_cuda_placement,
    inspect_optimized_graph,
};

const CPU_PROVIDER: &str = "CPUExecutionProvider";
const CUDA_PROVIDER: &str = "CUDAExecutionProvider";

pub const ONNX_CUSTOM_RUNTIME_ID: &str = "onnx-custom";
pub const ONNX_COLBERT_RUNTIME_ID: &str = "onnx-colbert";
pub const ONNX_FASTEMBED_RUNTIME_ID: &str = "onnx-fastembed-5.16.0-owned";
const CPU_EVIDENCE_PREFIX: &str =
    "onnx_api24_committed_session_after_first_real_host_materialized_inference;assigned_operators=";

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
    if expected_runtime.is_empty()
        || expected_runtime.trim() != expected_runtime
        || attestation.runtime != expected_runtime
    {
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
            "runtime attestation reported zero substantive CUDA compute nodes",
        ));
    }
    if cpu != 0 {
        return Err(placement(format!(
            "runtime attestation reports cpu_compute_nodes={cpu}; classified CPU shape metadata is not substantive compute and outer CPU compute must remain exactly zero"
        )));
    }

    let evidence: OnnxCudaExecutionEvidence =
        serde_json::from_str(&attestation.evidence).map_err(|error| {
            invalid(format!(
                "execution evidence is not the strict current structured CUDA ONNX receipt: {error}"
            ))
        })?;
    validate_evidence(&evidence)?;
    if evidence.final_graph_placement.cuda_compute_nodes != total
        || evidence.first_inference_profile.cuda_compute_nodes != total
    {
        return Err(invalid(format!(
            "outer substantive-compute count {total} differs from committed/profile CUDA counts {}/{}",
            evidence.final_graph_placement.cuda_compute_nodes,
            evidence.first_inference_profile.cuda_compute_nodes
        )));
    }

    let expected_provider = format!(
        "partition={};final={};profile={};placement_contract={}",
        evidence.api24_partition.providers,
        evidence.final_graph_placement.providers,
        evidence.first_inference_profile.providers,
        evidence.placement_contract_sha256
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

/// Validates an explicitly commissioned CPU ONNX receipt without accepting a
/// CUDA fallback, inferred provider, provider substring, or missing real-run
/// evidence.
pub fn validate_cpu_onnx_execution_attestation(
    attestation: &RuntimeExecutionAttestation,
    expected_runtime: &str,
) -> Result<()> {
    if expected_runtime.is_empty()
        || expected_runtime.trim() != expected_runtime
        || attestation.runtime != expected_runtime
    {
        return Err(invalid(format!(
            "expected exact explicit-CPU runtime {expected_runtime:?}, observed {:?}",
            attestation.runtime
        )));
    }
    let total = attestation
        .total_compute_nodes
        .ok_or_else(|| invalid("explicit-CPU runtime attestation omitted total compute nodes"))?;
    let cpu = attestation
        .cpu_compute_nodes
        .ok_or_else(|| invalid("explicit-CPU runtime attestation omitted CPU compute nodes"))?;
    let expected_provider = format!("{CPU_PROVIDER}:{total}");
    let assigned_operators = attestation
        .evidence
        .strip_prefix(CPU_EVIDENCE_PREFIX)
        .ok_or_else(|| {
            invalid(format!(
                "explicit-CPU execution evidence has no exact real-run/API-24 prefix: {:?}",
                attestation.evidence
            ))
        })?;
    if total == 0
        || cpu != total
        || attestation.device != "cpu"
        || attestation.provider != expected_provider
        || !assigned_operators.starts_with("CPUExecutionProvider:[")
        || !assigned_operators.ends_with(']')
        || assigned_operators.contains("CUDAExecutionProvider")
    {
        return Err(placement(format!(
            "explicit-CPU execution receipt is not entirely and truthfully CPU: expected_runtime={expected_runtime:?} expected_provider={expected_provider:?} total={total} cpu={cpu} observed={attestation:?}"
        )));
    }
    Ok(())
}

fn validate_evidence(evidence: &OnnxCudaExecutionEvidence) -> Result<()> {
    if evidence.kind
        != OnnxCudaExecutionEvidenceKind::Api24PartitionV2FinalGraphClassifiedV2AndFirstExactInferenceProfile
    {
        return Err(invalid("unsupported CUDA ONNX evidence discriminator"));
    }
    validate_stream_address(&evidence.retained_stream.stream_address)?;
    if evidence.classifier_version != CUDA_PLACEMENT_CLASSIFIER_VERSION {
        return Err(invalid(format!(
            "placement classifier must be exactly {CUDA_PLACEMENT_CLASSIFIER_VERSION:?}, observed {:?}",
            evidence.classifier_version
        )));
    }
    let opset_domains = validate_opset_inventory(evidence)?;
    validate_absolute_path("optimized graph", &evidence.optimized_graph_path)?;
    if evidence.optimized_graph_bytes == 0 {
        return Err(invalid(
            "optimized graph receipt reports a zero-byte GraphProto",
        ));
    }
    validate_sha256("optimized graph", &evidence.optimized_graph_sha256)?;
    validate_sha256("API-24 partition receipt", &evidence.api24_partition_sha256)?;
    validate_sha256(
        "final graph placement",
        &evidence.final_graph_placement_sha256,
    )?;
    validate_sha256(
        "CPU shape-metadata proof",
        &evidence.cpu_metadata_proof_sha256,
    )?;
    validate_sha256("placement contract", &evidence.placement_contract_sha256)?;
    validate_absolute_path("first-inference profile", &evidence.profile_path)?;
    if evidence.profile_path == evidence.optimized_graph_path {
        return Err(invalid(format!(
            "optimized graph and first-inference profile must be distinct immutable artifacts, but both use {:?}",
            evidence.profile_path
        )));
    }
    let graph_model_parent = Path::new(&evidence.optimized_graph_path)
        .ancestors()
        .nth(6)
        .ok_or_else(|| invalid("optimized graph CAS path has no model parent"))?;
    let profile_model_parent = Path::new(&evidence.profile_path)
        .ancestors()
        .nth(6)
        .ok_or_else(|| invalid("first-inference profile CAS path has no model parent"))?;
    if graph_model_parent != profile_model_parent {
        return Err(invalid(format!(
            "optimized graph and first-inference profile do not share one exact model-owned evidence root: graph_parent={} profile_parent={}",
            graph_model_parent.display(),
            profile_model_parent.display()
        )));
    }
    if evidence.profile_bytes == 0 {
        return Err(invalid(
            "first-inference profile receipt reports zero bytes",
        ));
    }
    validate_sha256("first-inference profile", &evidence.profile_sha256)?;
    let expected_contract_sha256 = hash_length_delimited(&[
        evidence.classifier_version.as_bytes(),
        evidence.opset_sha256.as_bytes(),
        evidence.optimized_graph_sha256.as_bytes(),
        evidence.api24_partition_sha256.as_bytes(),
        evidence.final_graph_placement_sha256.as_bytes(),
        evidence.profile_sha256.as_bytes(),
        evidence.cpu_metadata_proof_sha256.as_bytes(),
    ])?;
    if evidence.placement_contract_sha256 != expected_contract_sha256 {
        return Err(invalid(format!(
            "placement-contract SHA-256 does not bind the classifier/opset/graph/partition/final-placement/profile/proof fields: expected {expected_contract_sha256}, observed {}",
            evidence.placement_contract_sha256
        )));
    }
    validate_api24_partition(&evidence.api24_partition)?;
    validate_api24_partition_sha256(evidence)?;
    validate_final_graph_placement(&evidence.final_graph_placement, &opset_domains)?;
    validate_final_graph_placement_sha256(evidence)?;
    validate_cpu_metadata_proof_sha256(evidence)?;
    validate_first_inference(&evidence.first_inference_profile)?;
    validate_final_profile_identity(
        &evidence.final_graph_placement,
        &evidence.first_inference_profile,
    )?;
    let optimized_graph_bytes = validate_artifact_bytes(
        "optimized graph",
        &evidence.optimized_graph_path,
        evidence.optimized_graph_bytes,
        &evidence.optimized_graph_sha256,
        "optimized",
        "onnx",
        MAX_OPTIMIZED_GRAPH_BYTES,
    )?;
    let profile_bytes = validate_artifact_bytes(
        "first-inference profile",
        &evidence.profile_path,
        evidence.profile_bytes,
        &evidence.profile_sha256,
        "profiles",
        "json",
        MAX_PROFILE_TRACE_BYTES,
    )?;
    validate_artifact_semantics(evidence, &optimized_graph_bytes, &profile_bytes)
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

fn validate_api24_partition(receipt: &OnnxApi24PartitionReceiptEvidence) -> Result<()> {
    if receipt.schema != super::cpu_fallback_audit::API24_PARTITION_RECEIPT_SCHEMA
        || receipt.subgraph_count == 0
        || receipt.total_nodes == 0
    {
        return Err(invalid(format!(
            "API-24 partition receipt has invalid schema/counts: schema={:?} subgraphs={} total={}",
            receipt.schema, receipt.subgraph_count, receipt.total_nodes
        )));
    }
    validate_node_count(
        "API-24 partition receipt",
        receipt.nodes.len(),
        receipt.total_nodes,
    )?;
    let mut cuda = 0u64;
    let mut cpu = 0u64;
    let mut names = BTreeSet::new();
    let mut expected_subgraph = 0u64;
    let mut expected_node = 0u64;
    let mut operators = BTreeMap::<&str, BTreeSet<String>>::new();
    for (position, node) in receipt.nodes.iter().enumerate() {
        validate_partition_node(position, node, expected_subgraph, expected_node, &mut names)?;
        match node.provider.as_str() {
            CUDA_PROVIDER => increment_count(
                &mut cuda,
                "API-24 CUDA partition node inventory exceeds u64",
            )?,
            CPU_PROVIDER => {
                increment_count(&mut cpu, "API-24 CPU partition node inventory exceeds u64")?
            }
            provider => {
                return Err(placement(format!(
                    "API-24 partition node {:?} uses unknown provider {provider:?}",
                    node.name
                )));
            }
        }
        let qualified = if node.domain.is_empty() {
            node.operator.clone()
        } else {
            format!("{}::{}", node.domain, node.operator)
        };
        operators
            .entry(node.provider.as_str())
            .or_default()
            .insert(qualified);
        expected_node = expected_node
            .checked_add(1)
            .ok_or_else(|| invalid("API-24 node ordinal exceeds u64"))?;
        let next = position
            .checked_add(1)
            .and_then(|position| receipt.nodes.get(position));
        if next.is_some_and(|next| next.subgraph_index != node.subgraph_index) {
            expected_subgraph = expected_subgraph
                .checked_add(1)
                .ok_or_else(|| invalid("API-24 subgraph ordinal exceeds u64"))?;
            expected_node = 0;
        }
    }
    if expected_subgraph
        .checked_add(1)
        .is_none_or(|count| count != receipt.subgraph_count)
        || cuda != receipt.cuda_nodes
        || cpu != receipt.cpu_nodes
        || cuda
            .checked_add(cpu)
            .is_none_or(|count| count != receipt.total_nodes)
        || cuda == 0
    {
        return Err(placement(format!(
            "API-24 partition counts are inconsistent: subgraphs={}/{} total={} cuda={}/{} cpu={}/{}",
            expected_subgraph.saturating_add(1),
            receipt.subgraph_count,
            receipt.total_nodes,
            cuda,
            receipt.cuda_nodes,
            cpu,
            receipt.cpu_nodes
        )));
    }
    let expected_providers = provider_summary(cuda, cpu);
    if receipt.providers != expected_providers {
        return Err(placement(format!(
            "API-24 partition provider summary must be {expected_providers:?}, observed {:?}",
            receipt.providers
        )));
    }
    let expected_operators = operators
        .into_iter()
        .map(|(provider, operators)| {
            format!(
                "{provider}:[{}]",
                operators.into_iter().collect::<Vec<_>>().join(",")
            )
        })
        .collect::<Vec<_>>()
        .join(";");
    if receipt.assigned_operators != expected_operators {
        return Err(placement(format!(
            "API-24 assigned-operator summary must be {expected_operators:?}, observed {:?}",
            receipt.assigned_operators
        )));
    }
    Ok(())
}

fn validate_partition_node(
    position: usize,
    node: &OnnxApi24PartitionNodeEvidence,
    expected_subgraph: u64,
    expected_node: u64,
    names: &mut BTreeSet<String>,
) -> Result<()> {
    if node.subgraph_index != expected_subgraph
        || node.node_index_in_subgraph != expected_node
        || node.name.trim().is_empty()
        || node.name.trim() != node.name
        || !names.insert(node.name.clone())
    {
        return Err(invalid(format!(
            "API-24 partition node position {position} is not canonical: observed subgraph={} node={} name={:?}, expected subgraph={expected_subgraph} node={expected_node}",
            node.subgraph_index, node.node_index_in_subgraph, node.name
        )));
    }
    validate_operator("API-24 partition", &node.name, &node.operator)?;
    if node.domain.trim() != node.domain
        || node.domain.contains(',')
        || node.domain.contains(';')
        || node.domain.contains('[')
        || node.domain.contains(']')
    {
        return Err(invalid(format!(
            "API-24 partition node {:?} has ambiguous domain {:?}",
            node.name, node.domain
        )));
    }
    Ok(())
}

fn validate_api24_partition_sha256(evidence: &OnnxCudaExecutionEvidence) -> Result<()> {
    let receipt = &evidence.api24_partition;
    let mut owned_parts = vec![
        receipt.schema.as_bytes().to_vec(),
        receipt.subgraph_count.to_be_bytes().to_vec(),
    ];
    for node in &receipt.nodes {
        owned_parts.push(node.subgraph_index.to_be_bytes().to_vec());
        owned_parts.push(node.node_index_in_subgraph.to_be_bytes().to_vec());
        owned_parts.push(node.provider.as_bytes().to_vec());
        owned_parts.push(node.name.as_bytes().to_vec());
        owned_parts.push(node.domain.as_bytes().to_vec());
        owned_parts.push(node.operator.as_bytes().to_vec());
    }
    let parts = owned_parts.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let expected = hash_length_delimited(&parts)?;
    if evidence.api24_partition_sha256 != expected {
        return Err(invalid(format!(
            "API-24 partition SHA-256 does not bind exact schema/ordinal/provider/name/domain/operator fields: expected {expected}, observed {}",
            evidence.api24_partition_sha256
        )));
    }
    Ok(())
}

fn validate_final_graph_placement(
    receipt: &OnnxFinalGraphPlacementEvidence,
    opset_domains: &BTreeSet<String>,
) -> Result<()> {
    validate_classified_counts(
        "post-fusion final graph",
        receipt.total_graph_nodes,
        receipt.cuda_compute_nodes,
        receipt.cpu_metadata_nodes,
        receipt.unclassified_cpu_nodes,
        receipt.inter_provider_memcpy_nodes,
        &receipt.providers,
    )?;
    validate_node_count(
        "post-fusion final graph",
        receipt.nodes.len(),
        receipt.total_graph_nodes,
    )?;

    let mut cuda = 0u64;
    let mut cpu_metadata = 0u64;
    let mut previous_name: Option<&str> = None;
    let mut operators = BTreeMap::<&str, BTreeSet<String>>::new();
    for (index, node) in receipt.nodes.iter().enumerate() {
        validate_final_graph_node(index, node, previous_name, opset_domains)?;
        previous_name = Some(&node.name);
        match node.role {
            OnnxPlacementNodeRole::CudaCompute => {
                increment_count(&mut cuda, "committed CUDA node inventory exceeds u64")?
            }
            OnnxPlacementNodeRole::CpuShapeMetadata => increment_count(
                &mut cpu_metadata,
                "committed CPU metadata inventory exceeds u64",
            )?,
        }
        let qualified = if node.domain.is_empty() {
            node.operator.clone()
        } else {
            format!("{}::{}", node.domain, node.operator)
        };
        operators
            .entry(node.provider.as_str())
            .or_default()
            .insert(qualified);
    }
    if cuda != receipt.cuda_compute_nodes || cpu_metadata != receipt.cpu_metadata_nodes {
        return Err(placement(format!(
            "committed API-24 role inventory reports cuda_compute={cuda} cpu_metadata={cpu_metadata}, but count fields report cuda_compute={} cpu_metadata={}",
            receipt.cuda_compute_nodes, receipt.cpu_metadata_nodes
        )));
    }
    let expected_operators = operators
        .into_iter()
        .map(|(provider, operators)| {
            format!(
                "{provider}:[{}]",
                operators.into_iter().collect::<Vec<_>>().join(",")
            )
        })
        .collect::<Vec<_>>()
        .join(";");
    if receipt.assigned_operators != expected_operators {
        return Err(invalid(format!(
            "committed assigned-operator summary is not the exact deterministic projection of its node inventory: expected {expected_operators:?}, observed {:?}",
            receipt.assigned_operators
        )));
    }
    Ok(())
}

fn validate_first_inference(receipt: &OnnxFirstInferencePlacementEvidence) -> Result<()> {
    validate_classified_counts(
        "first real synchronized inference profile",
        receipt.total_graph_nodes,
        receipt.cuda_compute_nodes,
        receipt.cpu_metadata_nodes,
        receipt.unclassified_cpu_nodes,
        receipt.inter_provider_memcpy_nodes,
        &receipt.providers,
    )?;
    validate_node_count(
        "first real synchronized inference profile",
        receipt.nodes.len(),
        receipt.total_graph_nodes,
    )?;

    let mut cuda = 0u64;
    let mut cpu_metadata = 0u64;
    let mut previous_name: Option<&str> = None;
    let mut node_indices = BTreeSet::new();
    for (index, node) in receipt.nodes.iter().enumerate() {
        validate_profiled_node(index, node, previous_name)?;
        previous_name = Some(&node.name);
        if !node_indices.insert(node.node_index) {
            return Err(invalid(format!(
                "first-inference profile repeats ORT node_index={} at node {:?}",
                node.node_index, node.name
            )));
        }
        match node.role {
            OnnxPlacementNodeRole::CudaCompute => {
                increment_count(&mut cuda, "profile CUDA node inventory exceeds u64")?
            }
            OnnxPlacementNodeRole::CpuShapeMetadata => increment_count(
                &mut cpu_metadata,
                "profile CPU metadata inventory exceeds u64",
            )?,
        }
    }
    if cuda != receipt.cuda_compute_nodes || cpu_metadata != receipt.cpu_metadata_nodes {
        return Err(placement(format!(
            "first-inference role inventory reports cuda_compute={cuda} cpu_metadata={cpu_metadata}, but count fields report cuda_compute={} cpu_metadata={}",
            receipt.cuda_compute_nodes, receipt.cpu_metadata_nodes
        )));
    }
    Ok(())
}

fn validate_classified_counts(
    stage: &str,
    total: u64,
    cuda: u64,
    cpu_metadata: u64,
    unclassified_cpu: u64,
    memcpy: u64,
    providers: &str,
) -> Result<()> {
    if total == 0 || cuda == 0 {
        return Err(invalid(format!(
            "{stage} must report a nonempty graph with substantive CUDA compute, observed total={total} cuda_compute={cuda}"
        )));
    }
    let classified = cuda.checked_add(cpu_metadata).ok_or_else(|| {
        invalid(format!(
            "{stage} classified CUDA+CPU-metadata count exceeds u64"
        ))
    })?;
    if classified != total {
        return Err(placement(format!(
            "{stage} graph count is not exhaustively classified: total={total} cuda_compute={cuda} cpu_metadata={cpu_metadata}"
        )));
    }
    if unclassified_cpu != 0 || memcpy != 0 {
        return Err(placement(format!(
            "{stage} admits forbidden execution: unclassified_cpu={unclassified_cpu} inter_provider_memcpy={memcpy}; both must be exactly zero"
        )));
    }
    let expected = provider_summary(cuda, cpu_metadata);
    if providers != expected {
        return Err(placement(format!(
            "{stage} provider summary must be the exact deterministic classified count {expected:?}, observed {providers:?}"
        )));
    }
    Ok(())
}

fn validate_final_graph_node(
    index: usize,
    node: &OnnxFinalGraphNodeEvidence,
    previous_name: Option<&str>,
    opset_domains: &BTreeSet<String>,
) -> Result<()> {
    validate_sorted_node_name("post-fusion final graph", index, &node.name, previous_name)?;
    validate_operator("post-fusion final graph", &node.name, &node.operator)?;
    validate_provider_role(
        "post-fusion final graph",
        &node.name,
        &node.operator,
        &node.provider,
        node.role,
    )?;
    match node.role {
        OnnxPlacementNodeRole::CudaCompute => {
            if node.max_output_elements.is_some() || node.output_dtypes.is_some() {
                return Err(invalid(format!(
                    "committed CUDA compute node {:?} carries CPU metadata proof fields",
                    node.name
                )));
            }
        }
        OnnxPlacementNodeRole::CpuShapeMetadata => {
            let max_output_elements = node.max_output_elements.ok_or_else(|| {
                invalid(format!(
                    "committed CPU shape-metadata node {:?} omits max_output_elements",
                    node.name
                ))
            })?;
            if max_output_elements == 0 {
                return Err(invalid(format!(
                    "committed CPU shape-metadata node {:?} has a zero static output bound",
                    node.name
                )));
            }
            let output_dtypes = node.output_dtypes.as_deref().ok_or_else(|| {
                invalid(format!(
                    "committed CPU shape-metadata node {:?} omits output_dtypes",
                    node.name
                ))
            })?;
            validate_output_dtypes(&node.name, output_dtypes, node.role)?;
        }
    }
    if node.domain.trim() != node.domain
        || node.domain.contains(',')
        || node.domain.contains(';')
        || node.domain.contains(':')
        || node.domain.contains('[')
        || node.domain.contains(']')
    {
        return Err(invalid(format!(
            "committed node {:?} has a noncanonical or ambiguous ONNX domain {:?}",
            node.name, node.domain
        )));
    }
    let canonical_domain = if node.domain.is_empty() || node.domain == "ai.onnx" {
        "ai.onnx"
    } else {
        node.domain.as_str()
    };
    if !opset_domains.contains(canonical_domain) {
        return Err(invalid(format!(
            "committed node {:?} domain {canonical_domain:?} has no matching canonical opset inventory entry",
            node.name
        )));
    }
    Ok(())
}

fn validate_profiled_node(
    index: usize,
    node: &OnnxProfiledNodeEvidence,
    previous_name: Option<&str>,
) -> Result<()> {
    validate_sorted_node_name("first-inference profile", index, &node.name, previous_name)?;
    validate_operator("first-inference profile", &node.name, &node.operator)?;
    if node.domain.trim() != node.domain
        || node.domain.contains(',')
        || node.domain.contains(';')
        || node.domain.contains('[')
        || node.domain.contains(']')
    {
        return Err(invalid(format!(
            "profile node {:?} has a noncanonical or ambiguous ONNX domain {:?}",
            node.name, node.domain
        )));
    }
    validate_provider_role(
        "first-inference profile",
        &node.name,
        &node.operator,
        &node.provider,
        node.role,
    )?;
    let dtypes = validate_output_dtypes(&node.name, &node.output_dtypes, node.role)?;
    validate_output_accounting(node, &dtypes)
}

fn validate_sorted_node_name(
    stage: &str,
    index: usize,
    name: &str,
    previous_name: Option<&str>,
) -> Result<()> {
    if name.is_empty() || name.trim() != name {
        return Err(invalid(format!(
            "{stage} node {index} has an empty or noncanonical identity {name:?}"
        )));
    }
    if let Some(previous) = previous_name
        && previous >= name
    {
        return Err(invalid(format!(
            "{stage} node inventory is not strictly name-sorted and unique at {previous:?} then {name:?}"
        )));
    }
    Ok(())
}

fn validate_operator(stage: &str, name: &str, operator: &str) -> Result<()> {
    if operator.is_empty()
        || operator.trim() != operator
        || operator
            .chars()
            .any(|character| matches!(character, ',' | ';' | '[' | ']'))
    {
        return Err(invalid(format!(
            "{stage} node {name:?} has an empty, noncanonical, or summary-ambiguous operator {operator:?}"
        )));
    }
    if is_memcpy_operator(operator) {
        return Err(placement(format!(
            "{stage} node {name:?} is a forbidden inter-provider transfer operator {operator}"
        )));
    }
    Ok(())
}

fn validate_provider_role(
    stage: &str,
    name: &str,
    operator: &str,
    provider: &str,
    role: OnnxPlacementNodeRole,
) -> Result<()> {
    let expected = match role {
        OnnxPlacementNodeRole::CudaCompute => CUDA_PROVIDER,
        OnnxPlacementNodeRole::CpuShapeMetadata => CPU_PROVIDER,
    };
    if provider != expected {
        return Err(placement(format!(
            "{stage} node {name:?} ({operator}) role {role:?} requires provider {expected}, observed {provider:?}"
        )));
    }
    Ok(())
}

fn validate_output_dtypes<'a>(
    name: &str,
    raw: &'a str,
    role: OnnxPlacementNodeRole,
) -> Result<Vec<(&'a str, u64)>> {
    if raw.is_empty() || raw.trim() != raw {
        return Err(invalid(format!(
            "profile node {name:?} has an empty or noncanonical output dtype set {raw:?}"
        )));
    }
    let mut previous: Option<&str> = None;
    let mut dtypes = Vec::new();
    for dtype in raw.split(',') {
        if dtype.is_empty() || dtype.trim() != dtype || previous.is_some_and(|item| item >= dtype) {
            return Err(invalid(format!(
                "profile node {name:?} output dtypes are not a strictly sorted unique canonical set: {raw:?}"
            )));
        }
        let bits = runtime_dtype_bits(dtype).ok_or_else(|| {
            invalid(format!(
                "profile node {name:?} reports unsupported output dtype {dtype:?}"
            ))
        })?;
        if role == OnnxPlacementNodeRole::CpuShapeMetadata && !is_metadata_dtype(dtype) {
            return Err(placement(format!(
                "CPU shape-metadata node {name:?} produced substantive/nonmetadata dtype {dtype:?}"
            )));
        }
        previous = Some(dtype);
        dtypes.push((dtype, bits));
    }
    Ok(dtypes)
}

fn validate_output_accounting(
    node: &OnnxProfiledNodeEvidence,
    dtypes: &[(&str, u64)],
) -> Result<()> {
    if (node.output_elements == 0) != (node.output_size == 0) {
        return Err(invalid(format!(
            "profile node {:?} has inconsistent zero-state output_elements={} output_size={}",
            node.name, node.output_elements, node.output_size
        )));
    }
    if node.role == OnnxPlacementNodeRole::CpuShapeMetadata && node.output_elements == 0 {
        return Err(placement(format!(
            "CPU shape-metadata node {:?} produced an empty runtime output",
            node.name
        )));
    }
    if dtypes.len() == 1 && dtypes[0].1 >= 8 {
        let expected = node
            .output_elements
            .checked_mul(dtypes[0].1 / 8)
            .ok_or_else(|| {
                invalid(format!(
                    "profile node {:?} output byte accounting exceeds u64",
                    node.name
                ))
            })?;
        if node.output_size != expected {
            return Err(invalid(format!(
                "profile node {:?} output_size={} differs from {} elements of dtype {} ({} bytes)",
                node.name, node.output_size, node.output_elements, dtypes[0].0, expected
            )));
        }
    } else if node.output_elements != 0 {
        let min_bits = dtypes
            .iter()
            .map(|(_, bits)| *bits)
            .min()
            .ok_or_else(|| invalid("profile output dtype set unexpectedly empty"))?;
        let max_bits = dtypes
            .iter()
            .map(|(_, bits)| *bits)
            .max()
            .ok_or_else(|| invalid("profile output dtype set unexpectedly empty"))?;
        let minimum = node
            .output_elements
            .checked_mul(min_bits)
            .and_then(|bits| bits.checked_add(7))
            .map(|bits| bits / 8)
            .ok_or_else(|| invalid("profile minimum output byte accounting exceeds u64"))?;
        let maximum_bytes_per_element = max_bits
            .checked_add(7)
            .map(|bits| bits / 8)
            .ok_or_else(|| invalid("profile output dtype width exceeds u64"))?;
        let maximum = node
            .output_elements
            .checked_mul(maximum_bytes_per_element)
            .ok_or_else(|| invalid("profile maximum output byte accounting exceeds u64"))?;
        if node.output_size < minimum || node.output_size > maximum {
            return Err(invalid(format!(
                "profile node {:?} output_size={} is outside dtype-implied bounds {minimum}..={maximum} for {} elements",
                node.name, node.output_size, node.output_elements
            )));
        }
    }
    Ok(())
}

fn validate_final_profile_identity(
    committed: &OnnxFinalGraphPlacementEvidence,
    profile: &OnnxFirstInferencePlacementEvidence,
) -> Result<()> {
    if committed.total_graph_nodes != profile.total_graph_nodes
        || committed.cuda_compute_nodes != profile.cuda_compute_nodes
        || committed.cpu_metadata_nodes != profile.cpu_metadata_nodes
    {
        return Err(placement(format!(
            "committed/profile classified counts differ: committed total={} cuda_compute={} cpu_metadata={}; profile total={} cuda_compute={} cpu_metadata={}",
            committed.total_graph_nodes,
            committed.cuda_compute_nodes,
            committed.cpu_metadata_nodes,
            profile.total_graph_nodes,
            profile.cuda_compute_nodes,
            profile.cpu_metadata_nodes
        )));
    }
    for (committed_node, profiled_node) in committed.nodes.iter().zip(&profile.nodes) {
        if committed_node.name != profiled_node.name
            || committed_node.domain != profiled_node.domain
            || committed_node.operator != profiled_node.operator
            || committed_node.provider != profiled_node.provider
            || committed_node.role != profiled_node.role
        {
            return Err(placement(format!(
                "final-graph/profile node identity drift at final={:?}/{:?}/{:?}/{:?}/{:?}, profile={:?}/{:?}/{:?}/{:?}/{:?}",
                committed_node.name,
                committed_node.domain,
                committed_node.operator,
                committed_node.provider,
                committed_node.role,
                profiled_node.name,
                profiled_node.domain,
                profiled_node.operator,
                profiled_node.provider,
                profiled_node.role
            )));
        }
        if committed_node.role == OnnxPlacementNodeRole::CpuShapeMetadata {
            let max_output_elements = committed_node.max_output_elements.ok_or_else(|| {
                invalid(format!(
                    "committed CPU shape-metadata node {:?} lost its static output bound",
                    committed_node.name
                ))
            })?;
            let output_dtypes = committed_node.output_dtypes.as_deref().ok_or_else(|| {
                invalid(format!(
                    "committed CPU shape-metadata node {:?} lost its static dtype proof",
                    committed_node.name
                ))
            })?;
            if profiled_node.output_elements == 0
                || profiled_node.output_elements > max_output_elements
                || profiled_node.output_dtypes != output_dtypes
            {
                return Err(placement(format!(
                    "CPU shape-metadata runtime proof drift for {:?}: runtime elements={} dtypes={:?}, static max_elements={} dtypes={:?}",
                    committed_node.name,
                    profiled_node.output_elements,
                    profiled_node.output_dtypes,
                    max_output_elements,
                    output_dtypes
                )));
            }
        }
    }
    Ok(())
}

fn validate_node_count(stage: &str, length: usize, expected: u64) -> Result<()> {
    let length = u64::try_from(length)
        .map_err(|_| invalid(format!("{stage} node inventory length exceeds u64")))?;
    if length != expected {
        return Err(invalid(format!(
            "{stage} node inventory has {length} entries but total_graph_nodes={expected}"
        )));
    }
    Ok(())
}

fn validate_final_graph_placement_sha256(evidence: &OnnxCudaExecutionEvidence) -> Result<()> {
    let mut parts = Vec::new();
    for node in &evidence.final_graph_placement.nodes {
        parts.extend([
            node.provider.as_bytes(),
            node.name.as_bytes(),
            node.domain.as_bytes(),
            node.operator.as_bytes(),
        ]);
    }
    let expected = hash_length_delimited(&parts)?;
    if evidence.final_graph_placement_sha256 != expected {
        return Err(invalid(format!(
            "final graph placement SHA-256 does not bind the exact sorted provider/name/domain/operator fields: expected {expected}, observed {}",
            evidence.final_graph_placement_sha256
        )));
    }
    Ok(())
}

fn validate_cpu_metadata_proof_sha256(evidence: &OnnxCudaExecutionEvidence) -> Result<()> {
    let mut owned_parts = Vec::new();
    for node in &evidence.final_graph_placement.nodes {
        if node.role != OnnxPlacementNodeRole::CpuShapeMetadata {
            continue;
        }
        let max_output_elements = node.max_output_elements.ok_or_else(|| {
            invalid(format!(
                "CPU metadata proof hash cannot be reconstructed because node {:?} omits max_output_elements",
                node.name
            ))
        })?;
        let output_dtypes = node.output_dtypes.as_deref().ok_or_else(|| {
            invalid(format!(
                "CPU metadata proof hash cannot be reconstructed because node {:?} omits output_dtypes",
                node.name
            ))
        })?;
        owned_parts.push(node.name.as_bytes().to_vec());
        owned_parts.push(max_output_elements.to_be_bytes().to_vec());
        owned_parts.push(output_dtypes.as_bytes().to_vec());
    }
    let parts = owned_parts.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let expected = hash_length_delimited(&parts)?;
    if evidence.cpu_metadata_proof_sha256 != expected {
        return Err(invalid(format!(
            "CPU metadata proof SHA-256 does not bind the exact sorted node/bound/dtype fields: expected {expected}, observed {}",
            evidence.cpu_metadata_proof_sha256
        )));
    }
    Ok(())
}

fn provider_summary(cuda: u64, cpu_metadata: u64) -> String {
    if cpu_metadata == 0 {
        format!("{CUDA_PROVIDER}:{cuda}")
    } else {
        format!("{CPU_PROVIDER}:{cpu_metadata},{CUDA_PROVIDER}:{cuda}")
    }
}

fn increment_count(count: &mut u64, message: &'static str) -> Result<()> {
    *count = (*count).checked_add(1).ok_or_else(|| invalid(message))?;
    Ok(())
}

fn is_memcpy_operator(operator: &str) -> bool {
    matches!(operator, "Memcpy" | "MemcpyFromHost" | "MemcpyToHost")
}

fn runtime_dtype_bits(dtype: &str) -> Option<u64> {
    match dtype {
        "bool" | "int8" | "uint8" | "Float8E4M3FN" | "Float8E4M3FNUZ" | "Float8E5M2"
        | "Float8E5M2FNUZ" | "Float8E8M0" => Some(8),
        "int16" | "uint16" | "float16" | "bfloat16" => Some(16),
        "int32" | "uint32" | "float" => Some(32),
        "int64" | "uint64" | "double" | "complex64" => Some(64),
        "complex128" => Some(128),
        "Float4E2M1x2" | "Int4x2" | "UInt4x2" => Some(4),
        "Int2x4" | "UInt2x4" => Some(2),
        _ => None,
    }
}

fn is_metadata_dtype(dtype: &str) -> bool {
    matches!(
        dtype,
        "bool" | "uint8" | "int8" | "uint16" | "int16" | "int32" | "int64" | "uint32" | "uint64"
    )
}

fn validate_opset_inventory(evidence: &OnnxCudaExecutionEvidence) -> Result<BTreeSet<String>> {
    if evidence.opset_inventory.is_empty()
        || evidence.opset_inventory.trim() != evidence.opset_inventory
    {
        return Err(invalid(format!(
            "opset inventory is empty or noncanonical: {:?}",
            evidence.opset_inventory
        )));
    }
    let mut parsed = BTreeMap::<String, i64>::new();
    for entry in evidence.opset_inventory.split(',') {
        let (domain, raw_version) = entry.rsplit_once(':').ok_or_else(|| {
            invalid(format!(
                "opset inventory entry lacks domain:version form: {entry:?}"
            ))
        })?;
        if domain.is_empty()
            || domain.trim() != domain
            || domain.contains(':')
            || domain.contains(';')
            || domain.contains('[')
            || domain.contains(']')
            || (raw_version.len() > 1 && raw_version.starts_with('0'))
            || raw_version.is_empty()
            || !raw_version.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(invalid(format!(
                "opset inventory entry is not canonical and unambiguous: {entry:?}"
            )));
        }
        let version = raw_version.parse::<i64>().map_err(|error| {
            invalid(format!(
                "opset inventory version exceeds positive i64 in {entry:?}: {error}"
            ))
        })?;
        if version <= 0 {
            return Err(invalid(format!(
                "opset inventory version must be positive in {entry:?}"
            )));
        }
        let stored_domain = if domain == "ai.onnx" {
            String::new()
        } else {
            domain.to_string()
        };
        if parsed.insert(stored_domain, version).is_some() {
            return Err(invalid(format!(
                "opset inventory repeats canonical domain {domain:?}"
            )));
        }
    }
    if !parsed.contains_key("") {
        return Err(invalid(
            "opset inventory omits the required ai.onnx standard domain",
        ));
    }
    let canonical = parsed
        .iter()
        .map(|(domain, version)| {
            format!(
                "{}:{version}",
                if domain.is_empty() { "ai.onnx" } else { domain }
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    if evidence.opset_inventory != canonical {
        return Err(invalid(format!(
            "opset inventory is not in deterministic canonical-domain order: expected {canonical:?}, observed {:?}",
            evidence.opset_inventory
        )));
    }
    let mut hash_parts = Vec::new();
    for (domain, version) in &parsed {
        hash_parts.push(domain.as_bytes().to_vec());
        hash_parts.push(version.to_be_bytes().to_vec());
    }
    let references = hash_parts.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let expected_hash = hash_length_delimited(&references)?;
    validate_sha256("opset inventory", &evidence.opset_sha256)?;
    if evidence.opset_sha256 != expected_hash {
        return Err(invalid(format!(
            "opset inventory SHA-256 does not bind the canonical domain/version fields: expected {expected_hash}, observed {}",
            evidence.opset_sha256
        )));
    }
    Ok(parsed
        .keys()
        .map(|domain| {
            if domain.is_empty() {
                "ai.onnx".to_string()
            } else {
                domain.clone()
            }
        })
        .collect())
}

fn validate_absolute_path(label: &str, raw: &str) -> Result<()> {
    let path = Path::new(raw);
    let normalized = path.components().collect::<PathBuf>();
    if raw.is_empty()
        || raw.trim() != raw
        || !path.is_absolute()
        || normalized.as_os_str() != path.as_os_str()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(invalid(format!(
            "{label} path must be a nonblank absolute normalized path without dot segments, observed {raw:?}"
        )));
    }
    Ok(())
}

fn validate_artifact_bytes(
    label: &str,
    raw_path: &str,
    expected_bytes: u64,
    expected_sha256: &str,
    kind_directory: &str,
    extension: &str,
    maximum_bytes: u64,
) -> Result<Vec<u8>> {
    let path = Path::new(raw_path);
    if expected_bytes == 0 || expected_bytes > maximum_bytes {
        return Err(invalid(format!(
            "durable {label} receipt reports {expected_bytes} bytes outside the required 1..={maximum_bytes} range"
        )));
    }
    validate_cas_path(label, path, expected_sha256, kind_directory, extension)?;
    let model_parent = path.ancestors().nth(6).ok_or_else(|| {
        invalid(format!(
            "durable {label} path {} has no model parent above its content-addressed suffix",
            path.display()
        ))
    })?;
    let model_root =
        std::sync::Arc::new(calyx_onnx_runtime::open_immutable_directory(model_parent)?);
    let store_root = std::sync::Arc::new(calyx_onnx_runtime::open_immutable_child_directory(
        &model_root,
        STORE_DIRECTORY.as_ref(),
    )?);
    let blobs_root = std::sync::Arc::new(calyx_onnx_runtime::open_immutable_child_directory(
        &store_root,
        "blobs".as_ref(),
    )?);
    let sha_root = std::sync::Arc::new(calyx_onnx_runtime::open_immutable_child_directory(
        &blobs_root,
        "sha256".as_ref(),
    )?);
    let kind_root = std::sync::Arc::new(calyx_onnx_runtime::open_immutable_child_directory(
        &sha_root,
        kind_directory.as_ref(),
    )?);
    let prefix_root = std::sync::Arc::new(calyx_onnx_runtime::open_immutable_child_directory(
        &kind_root,
        expected_sha256[..2].as_ref(),
    )?);
    let exact_path = prefix_root
        .final_path()
        .join(format!("{expected_sha256}.{extension}"));
    let snapshot = calyx_onnx_runtime::snapshot_immutable_file(
        &exact_path,
        Some(prefix_root.as_ref()),
        maximum_bytes,
    )?;
    let observed_bytes = u64::try_from(snapshot.bytes.len())
        .map_err(|_| invalid(format!("durable {label} readback length exceeds u64")))?;
    let observed_sha256 = format!("{:x}", Sha256::digest(&snapshot.bytes));
    if snapshot.final_path != path
        || observed_bytes != expected_bytes
        || observed_sha256 != expected_sha256
    {
        return Err(invalid(format!(
            "durable {label} readback mismatch: expected path={} bytes={expected_bytes} sha256={expected_sha256}, observed path={} bytes={observed_bytes} sha256={observed_sha256}",
            path.display(),
            snapshot.final_path.display()
        )));
    }
    Ok(snapshot.bytes)
}

fn validate_cas_path(
    label: &str,
    path: &Path,
    sha256: &str,
    kind_directory: &str,
    extension: &str,
) -> Result<()> {
    let expected_file_name = format!("{sha256}.{extension}");
    let expected_prefix = &sha256[..2];
    let prefix_directory = path.parent();
    let kind = prefix_directory.and_then(Path::parent);
    let sha_directory = kind.and_then(Path::parent);
    let blobs_directory = sha_directory.and_then(Path::parent);
    let store_directory = blobs_directory.and_then(Path::parent);
    let exact = path.file_name().and_then(|name| name.to_str())
        == Some(expected_file_name.as_str())
        && prefix_directory
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            == Some(expected_prefix)
        && kind
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            == Some(kind_directory)
        && sha_directory
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            == Some("sha256")
        && blobs_directory
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            == Some("blobs")
        && store_directory
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            == Some(STORE_DIRECTORY);
    if !exact {
        return Err(invalid(format!(
            "durable {label} path {} is not the exact content-addressed suffix {STORE_DIRECTORY}/blobs/sha256/{kind_directory}/{expected_prefix}/{expected_file_name}",
            path.display()
        )));
    }
    Ok(())
}

fn validate_artifact_semantics(
    evidence: &OnnxCudaExecutionEvidence,
    optimized_graph_bytes: &[u8],
    profile_bytes: &[u8],
) -> Result<()> {
    let optimized = inspect_optimized_graph(
        Path::new(&evidence.optimized_graph_path),
        optimized_graph_bytes,
    )?;
    if optimized.classifier_version != evidence.classifier_version
        || optimized.opset_inventory != evidence.opset_inventory
        || optimized.opset_sha256 != evidence.opset_sha256
        || optimized.optimized_graph_path != evidence.optimized_graph_path
        || optimized.optimized_graph_bytes != evidence.optimized_graph_bytes
        || optimized.optimized_graph_sha256 != evidence.optimized_graph_sha256
        || optimized.total_graph_nodes != evidence.final_graph_placement.total_graph_nodes
    {
        return Err(invalid(format!(
            "durable optimized ModelProto semantic receipt differs from structured evidence: graph_sha={} graph_nodes={} evidence_sha={} evidence_nodes={}",
            optimized.optimized_graph_sha256,
            optimized.total_graph_nodes,
            evidence.optimized_graph_sha256,
            evidence.final_graph_placement.total_graph_nodes
        )));
    }
    let trace = std::str::from_utf8(profile_bytes).map_err(|error| {
        invalid(format!(
            "durable first-inference profile {} is not UTF-8: {error}",
            evidence.profile_path
        ))
    })?;
    let profile = reconcile_profile_with_optimized_graph(
        "durable structured execution evidence",
        trace,
        &optimized,
    )?;
    let derived_profile = OnnxFirstInferencePlacementEvidence {
        total_graph_nodes: profile.total_nodes,
        cuda_compute_nodes: profile.cuda_compute_nodes,
        cpu_metadata_nodes: profile.cpu_metadata_nodes,
        unclassified_cpu_nodes: 0,
        inter_provider_memcpy_nodes: 0,
        providers: profile.per_provider.clone(),
        nodes: profile
            .nodes
            .iter()
            .map(|node| OnnxProfiledNodeEvidence {
                name: node.name.clone(),
                domain: node.domain.clone(),
                operator: node.operator.clone(),
                provider: node.provider.clone(),
                role: if node.provider == CUDA_PROVIDER {
                    OnnxPlacementNodeRole::CudaCompute
                } else {
                    OnnxPlacementNodeRole::CpuShapeMetadata
                },
                node_index: node.node_index,
                output_size: node.output_size,
                output_elements: node.output_elements,
                output_dtypes: node.output_dtypes.clone(),
            })
            .collect(),
    };
    if derived_profile != evidence.first_inference_profile {
        return Err(placement(
            "durable first-inference profile does not rederive the exact structured profile receipt",
        ));
    }

    let assignment = reconstruct_partition_assignment(evidence)?;
    validate_partition_receipt(&assignment, "durable structured execution evidence", true)?;
    let contract = classify_profiled_cuda_placement(
        &assignment,
        &optimized,
        optimized_graph_bytes,
        &profile,
        &evidence.profile_sha256,
    )?;
    validate_rederived_contract(evidence, &contract, &profile.per_provider)
}

fn reconstruct_partition_assignment(
    evidence: &OnnxCudaExecutionEvidence,
) -> Result<CommittedGraphAssignment> {
    let nodes = evidence
        .api24_partition
        .nodes
        .iter()
        .map(|node| AssignedNode {
            subgraph_index: node.subgraph_index,
            node_index_in_subgraph: node.node_index_in_subgraph,
            provider: node.provider.clone(),
            name: node.name.clone(),
            domain: node.domain.clone(),
            operator: node.operator.clone(),
        })
        .collect::<Vec<_>>();
    let mut provider_nodes = BTreeMap::<String, Vec<String>>::new();
    for node in &nodes {
        provider_nodes
            .entry(node.provider.clone())
            .or_default()
            .push(node.inventory_entry());
    }
    let per_provider_nodes = provider_nodes
        .into_iter()
        .map(|(provider, nodes)| format!("{provider}:[{}]", nodes.join(",")))
        .collect::<Vec<_>>()
        .join(";");
    Ok(CommittedGraphAssignment {
        schema: API24_PARTITION_RECEIPT_SCHEMA,
        subgraph_count: evidence.api24_partition.subgraph_count,
        total_nodes: evidence.api24_partition.total_nodes,
        cpu_nodes: evidence.api24_partition.cpu_nodes,
        cuda_nodes: evidence.api24_partition.cuda_nodes,
        partition_sha256: evidence.api24_partition_sha256.clone(),
        per_provider: evidence.api24_partition.providers.clone(),
        per_provider_operators: evidence.api24_partition.assigned_operators.clone(),
        per_provider_nodes,
        nodes,
    })
}

fn validate_rederived_contract(
    evidence: &OnnxCudaExecutionEvidence,
    contract: &CudaPlacementContract,
    providers: &str,
) -> Result<()> {
    if contract.classifier_version != evidence.classifier_version
        || contract.opset_inventory != evidence.opset_inventory
        || contract.opset_sha256 != evidence.opset_sha256
        || contract.optimized_graph_path != evidence.optimized_graph_path
        || contract.optimized_graph_bytes != evidence.optimized_graph_bytes
        || contract.optimized_graph_sha256 != evidence.optimized_graph_sha256
        || contract.api24_partition_sha256 != evidence.api24_partition_sha256
        || contract.final_graph_placement_sha256 != evidence.final_graph_placement_sha256
        || contract.cpu_metadata_proof_sha256 != evidence.cpu_metadata_proof_sha256
        || contract.profile_sha256 != evidence.profile_sha256
        || contract.contract_sha256 != evidence.placement_contract_sha256
    {
        return Err(placement(
            "rederived graph/profile classifier contract differs from the structured evidence hashes or identities",
        ));
    }
    let mut nodes = Vec::new();
    for node in &contract.cuda_compute_nodes {
        nodes.push(OnnxFinalGraphNodeEvidence {
            name: node.name.clone(),
            domain: node.domain.clone(),
            operator: node.operator.clone(),
            provider: node.provider.clone(),
            role: OnnxPlacementNodeRole::CudaCompute,
            max_output_elements: None,
            output_dtypes: None,
        });
    }
    for node in &contract.cpu_metadata_nodes {
        let proof = contract
            .cpu_metadata_proofs
            .get(&node.name)
            .ok_or_else(|| {
                invalid(format!(
                    "rederived CPU metadata node {:?} has no static proof",
                    node.name
                ))
            })?;
        nodes.push(OnnxFinalGraphNodeEvidence {
            name: node.name.clone(),
            domain: node.domain.clone(),
            operator: node.operator.clone(),
            provider: node.provider.clone(),
            role: OnnxPlacementNodeRole::CpuShapeMetadata,
            max_output_elements: Some(proof.max_output_elements),
            output_dtypes: Some(proof.output_dtypes.clone()),
        });
    }
    nodes.sort_by(|left, right| left.name.cmp(&right.name));
    let assigned_operators = final_provider_operator_summary(&nodes);
    let derived = OnnxFinalGraphPlacementEvidence {
        total_graph_nodes: contract.total_graph_nodes(),
        cuda_compute_nodes: contract.cuda_compute_node_count(),
        cpu_metadata_nodes: contract.cpu_metadata_node_count(),
        unclassified_cpu_nodes: 0,
        inter_provider_memcpy_nodes: 0,
        providers: providers.to_string(),
        assigned_operators,
        nodes,
    };
    if derived != evidence.final_graph_placement {
        return Err(placement(
            "rederived optimized-graph placement and CPU metadata proofs differ from the structured final-graph receipt",
        ));
    }
    Ok(())
}

fn final_provider_operator_summary(nodes: &[OnnxFinalGraphNodeEvidence]) -> String {
    let mut providers = BTreeMap::<&str, BTreeSet<String>>::new();
    for node in nodes {
        let qualified = if node.domain.is_empty() {
            node.operator.clone()
        } else {
            format!("{}::{}", node.domain, node.operator)
        };
        providers
            .entry(node.provider.as_str())
            .or_default()
            .insert(qualified);
    }
    providers
        .into_iter()
        .map(|(provider, operators)| {
            format!(
                "{provider}:[{}]",
                operators.into_iter().collect::<Vec<_>>().join(",")
            )
        })
        .collect::<Vec<_>>()
        .join(";")
}

fn validate_sha256(label: &str, value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(format!(
            "{label} SHA-256 must be exactly 64 lowercase hexadecimal characters, observed {value:?}"
        )));
    }
    Ok(())
}

fn hash_length_delimited(parts: &[&[u8]]) -> Result<String> {
    let mut hash = Sha256::new();
    for part in parts {
        let length = u64::try_from(part.len())
            .map_err(|_| invalid("attestation hash field length exceeds u64"))?;
        hash.update(length.to_be_bytes());
        hash.update(part);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn invalid(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: "CALYX_ONNX_EXECUTION_ATTESTATION_INVALID",
        message: message.into(),
        remediation: "use the Calyx-owned ONNX session path that binds the immutable optimized graph, canonical opsets, exact API-24 assignment, static CPU-metadata proof, retained stream/device identity, and first-real-inference profile into the current structured receipt; legacy, ambiguous, or incomplete evidence is never accepted",
    }
}

fn placement(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: "CALYX_ONNX_EXECUTION_PLACEMENT_MISMATCH",
        message: message.into(),
        remediation: "use a CUDA-compatible graph whose substantive compute is exactly on CUDAExecutionProvider, whose only CPU nodes are statically proven bounded integral/bool shape metadata, and whose committed/profile inventories contain zero unknown or inter-provider transfer nodes; terminally discard mismatched sessions rather than retrying on CPU",
    }
}
