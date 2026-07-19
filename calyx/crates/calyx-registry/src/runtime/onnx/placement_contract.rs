//! Fail-closed CUDA compute versus CPU shape-metadata placement contract.
//!
//! ONNX Runtime intentionally keeps `Shape` outputs and their small integral
//! manipulation chains in CPU memory. That is not activation compute fallback,
//! but provider counts or operator allowlists cannot prove the distinction:
//! `Gather`, `Slice`, and arithmetic can process either metadata or content.
//! This module therefore binds API-24 assignment records to the exact optimized
//! graph and authorizes CPU work only when graph dataflow proves a closed,
//! bounded, integral/bool metadata subgraph whose values can escape solely
//! through schema-defined metadata inputs.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use calyx_core::{CalyxError, Result};
use onnx_rs::ast::{
    AttributeType, DataLocation, DataType, Graph, Model, Node, OpType, TensorProto,
};
use sha2::{Digest, Sha256};

use super::cpu_fallback_audit::{AssignedNode, CommittedGraphAssignment};

pub(super) const CUDA_PLACEMENT_CLASSIFIER_VERSION: &str = "calyx.onnx.cuda_shape_metadata.v1";

const CUDA_PROVIDER: &str = "CUDAExecutionProvider";
const CPU_PROVIDER: &str = "CPUExecutionProvider";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CudaPlacementContract {
    pub(super) classifier_version: &'static str,
    pub(super) opset_inventory: String,
    pub(super) opset_sha256: String,
    pub(super) optimized_graph_path: String,
    pub(super) optimized_graph_bytes: u64,
    pub(super) optimized_graph_sha256: String,
    pub(super) assignment_sha256: String,
    pub(super) cpu_metadata_proof_sha256: String,
    pub(super) contract_sha256: String,
    pub(super) total_graph_nodes: u64,
    cuda_compute_node_count: u64,
    cpu_metadata_node_count: u64,
    pub(super) cuda_compute_nodes: Vec<AssignedNode>,
    pub(super) cpu_metadata_nodes: Vec<AssignedNode>,
    pub(super) cpu_metadata_proofs: BTreeMap<String, CpuMetadataNodeProof>,
    pub(super) cuda_node_inventory: String,
    pub(super) cpu_metadata_node_inventory: String,
    pub(super) cpu_metadata_proof_inventory: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CpuMetadataNodeProof {
    pub(super) max_output_elements: u64,
    pub(super) output_dtypes: String,
}

impl CudaPlacementContract {
    pub(super) fn total_graph_nodes(&self) -> u64 {
        self.total_graph_nodes
    }

    pub(super) fn cuda_compute_node_count(&self) -> u64 {
        self.cuda_compute_node_count
    }

    pub(super) fn cpu_metadata_node_count(&self) -> u64 {
        self.cpu_metadata_node_count
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MetadataTensor {
    dtype: DataType,
    max_elements: u64,
}

/// Unique path supplied to ORT before commit. ORT writes the final optimized
/// ONNX graph exactly once; callers snapshot/hash it before publishing the
/// session.
pub(super) fn optimized_graph_file_path(label: &str) -> Result<PathBuf> {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let label_hash = format!("{:x}", Sha256::digest(label.as_bytes()));
    loop {
        let seq = SEQ
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| {
                placement_error(
                    "CALYX_ONNX_OPTIMIZED_GRAPH_PATH_EXHAUSTED",
                    "optimized-graph path sequence exhausted u64",
                    "restart the process and preserve the path-allocation diagnostics",
                )
            })?;
        let directory = std::env::temp_dir().join(format!(
            "calyx_onnx_optimized_{}_{seq}_{}",
            std::process::id(),
            &label_hash[..16]
        ));
        match std::fs::create_dir(&directory) {
            Ok(()) => return Ok(directory.join("optimized.onnx")),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(placement_error(
                    "CALYX_ONNX_OPTIMIZED_GRAPH_DIRECTORY_CREATE",
                    format!(
                        "exclusive optimized-graph directory creation failed at {}: {error}",
                        directory.display()
                    ),
                    "repair the process temporary-directory permissions and retry in a new process",
                ));
            }
        }
    }
}

pub(super) fn inspect_cuda_placement(
    assignment: &CommittedGraphAssignment,
    optimized_graph_path: &Path,
    optimized_graph_bytes: &[u8],
) -> Result<CudaPlacementContract> {
    if optimized_graph_bytes.is_empty() {
        return Err(placement_error(
            "CALYX_ONNX_OPTIMIZED_GRAPH_EMPTY",
            format!(
                "optimized ONNX graph {} is empty",
                optimized_graph_path.display()
            ),
            "preserve the failed session and runtime logs, repair optimized-model serialization, and retry in a new process",
        ));
    }
    if assignment.total_nodes == 0
        || assignment.nodes.is_empty()
        || assignment.total_nodes
            != u64::try_from(assignment.nodes.len()).map_err(|_| {
                placement_error(
                    "CALYX_ONNX_GRAPH_ASSIGNMENT_COUNT_MISMATCH",
                    "API-24 assigned-node inventory exceeds u64",
                    "repair the exact graph-assignment reader before admitting any CUDA session",
                )
            })?
    {
        return Err(placement_error(
            "CALYX_ONNX_GRAPH_ASSIGNMENT_COUNT_MISMATCH",
            format!(
                "API-24 assignment count total={} inventory={}",
                assignment.total_nodes,
                assignment.nodes.len()
            ),
            "preserve the assignment receipt and repair node-level API-24 readback before retrying",
        ));
    }
    let counted_cpu = u64::try_from(
        assignment
            .nodes
            .iter()
            .filter(|node| node.provider == CPU_PROVIDER)
            .count(),
    )
    .map_err(|_| {
        placement_error(
            "CALYX_ONNX_GRAPH_ASSIGNMENT_COUNT_OVERFLOW",
            "CPU node inventory exceeds u64",
            "repair the exact API-24 assignment reader before admitting the session",
        )
    })?;
    let counted_cuda = u64::try_from(
        assignment
            .nodes
            .iter()
            .filter(|node| node.provider == CUDA_PROVIDER)
            .count(),
    )
    .map_err(|_| {
        placement_error(
            "CALYX_ONNX_GRAPH_ASSIGNMENT_COUNT_OVERFLOW",
            "CUDA node inventory exceeds u64",
            "repair the exact API-24 assignment reader before admitting the session",
        )
    })?;
    if assignment.cpu_nodes != counted_cpu || assignment.cuda_nodes != counted_cuda {
        return Err(placement_error(
            "CALYX_ONNX_GRAPH_ASSIGNMENT_COUNT_MISMATCH",
            format!(
                "API-24 provider counts report cuda={} cpu={}, exact node inventory reports cuda={counted_cuda} cpu={counted_cpu}",
                assignment.cuda_nodes, assignment.cpu_nodes
            ),
            "preserve the exact API-24 receipt and repair provider-count reconciliation before retrying",
        ));
    }

    let model = onnx_rs::parse(optimized_graph_bytes).map_err(|error| {
        placement_error(
            "CALYX_ONNX_OPTIMIZED_GRAPH_PARSE",
            format!(
                "parse optimized ONNX graph {} failed: {error}",
                optimized_graph_path.display()
            ),
            "preserve the exact optimized bytes and repair the ONNX graph parser before retrying",
        )
    })?;
    if !model.training_info.is_empty() || !model.functions.is_empty() {
        return Err(placement_error(
            "CALYX_ONNX_PLACEMENT_UNPROVEN_LOCAL_GRAPH",
            format!(
                "optimized ONNX graph {} contains training_info or local functions outside the placement classifier",
                optimized_graph_path.display()
            ),
            "commission an inference-only graph without local/training graphs, or extend the classifier to recurse and prove every scoped node before retrying",
        ));
    }
    let opsets = canonical_opsets(&model)?;
    let standard_opset = *opsets.get("").ok_or_else(|| {
        placement_error(
            "CALYX_ONNX_STANDARD_OPSET_MISSING",
            "optimized ONNX model has no standard-domain opset import",
            "export a standards-conforming ONNX model with one positive default-domain opset import",
        )
    })?;
    let opset_inventory = opsets
        .iter()
        .map(|(domain, version)| {
            format!(
                "{}:{version}",
                if domain.is_empty() { "ai.onnx" } else { domain }
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let mut opset_part_bytes = Vec::new();
    for (domain, version) in &opsets {
        opset_part_bytes.push(domain.as_bytes().to_vec());
        opset_part_bytes.push(version.to_be_bytes().to_vec());
    }
    let opset_parts = opset_part_bytes
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    let opset_sha256 = hash_length_delimited(&opset_parts)?;
    let graph = model.graph.as_ref().ok_or_else(|| {
        placement_error(
            "CALYX_ONNX_OPTIMIZED_GRAPH_MISSING",
            format!(
                "optimized ONNX model {} has no main GraphProto",
                optimized_graph_path.display()
            ),
            "repair optimized-model serialization and retry in a new process",
        )
    })?;
    reject_external_tensor_data(graph)?;

    let mut graph_nodes = BTreeMap::<String, &Node<'_>>::new();
    let mut nested_graphs = false;
    collect_graph_nodes(graph, &mut graph_nodes, &mut nested_graphs)?;
    if graph_nodes.is_empty() {
        return Err(placement_error(
            "CALYX_ONNX_OPTIMIZED_GRAPH_EMPTY",
            format!(
                "optimized ONNX graph {} contains no executable nodes",
                optimized_graph_path.display()
            ),
            "use a model whose committed CUDA session retains at least one executable compute node",
        ));
    }

    if nested_graphs {
        return Err(placement_error(
            "CALYX_ONNX_PLACEMENT_CONTROL_FLOW_UNPROVEN",
            "optimized CUDA graph contains nested/control-flow graph scopes outside placement-classifier v1",
            "commission a control-flow-free graph, or extend the classifier to prove every scoped branch, loop, assignment, and profile multiplicity before retrying",
        ));
    }
    for node in graph_nodes.values() {
        if !node.overload.is_empty() {
            return Err(placement_error(
                "CALYX_ONNX_NODE_OVERLOAD_UNPROVEN",
                format!(
                    "optimized graph node {:?} ({}) declares overload {:?}",
                    node.name,
                    qualified_graph_operator(node),
                    node.overload
                ),
                "commission a graph without function overloads, or extend the classifier to bind the exact overload schema before retrying",
            ));
        }
        let domain = canonical_domain(node.domain);
        if !opsets.contains_key(domain) {
            return Err(placement_error(
                "CALYX_ONNX_NODE_OPSET_MISSING",
                format!(
                    "optimized graph node {:?} ({}) has no matching opset import for domain {:?}",
                    node.name,
                    qualified_graph_operator(node),
                    domain
                ),
                "export a standards-conforming ONNX graph whose every node domain has one positive opset import",
            ));
        }
    }

    let mut assigned_by_name = BTreeMap::<String, &AssignedNode>::new();
    for assigned in &assignment.nodes {
        if assigned.provider != CUDA_PROVIDER && assigned.provider != CPU_PROVIDER {
            return Err(placement_error(
                "CALYX_ONNX_UNKNOWN_EXECUTION_PROVIDER",
                format!(
                    "node {:?} is assigned to unsupported provider {:?}",
                    assigned.name, assigned.provider
                ),
                "configure exactly CUDAExecutionProvider with ORT's implicit CPU metadata provider; unknown providers are never admitted",
            ));
        }
        if assigned_by_name
            .insert(assigned.name.clone(), assigned)
            .is_some()
        {
            return Err(placement_error(
                "CALYX_ONNX_GRAPH_ASSIGNMENT_DUPLICATE_NODE",
                format!(
                    "API-24 assignment contains duplicate node name {:?}",
                    assigned.name
                ),
                "normalize the model to globally unique nonblank node names before commissioning",
            ));
        }
        let graph_node = graph_nodes.get(&assigned.name).ok_or_else(|| {
            placement_error(
                "CALYX_ONNX_GRAPH_ASSIGNMENT_UNMAPPED_NODE",
                format!(
                    "API-24 assigned node {:?} ({}) is absent from optimized graph {}",
                    assigned.name,
                    assigned.qualified_operator(),
                    optimized_graph_path.display()
                ),
                "preserve the assignment and optimized bytes, then repair the one-to-one node mapping before retrying",
            )
        })?;
        if graph_node.op_type.as_str() != assigned.operator
            || !domains_equivalent(graph_node.domain, &assigned.domain)
        {
            return Err(placement_error(
                "CALYX_ONNX_GRAPH_ASSIGNMENT_OPERATOR_DRIFT",
                format!(
                    "assigned node {:?} reports {} but optimized graph reports {}",
                    assigned.name,
                    assigned.qualified_operator(),
                    qualified_graph_operator(graph_node)
                ),
                "preserve both receipts and repair the assignment-to-optimized-graph mapping before retrying",
            ));
        }
    }

    for (name, node) in &graph_nodes {
        if is_memcpy_operator(node.op_type.as_str()) {
            return Err(placement_error(
                "CALYX_ONNX_INTER_PROVIDER_MEMCPY",
                format!(
                    "optimized CUDA graph contains forbidden transfer node {name:?} ({})",
                    qualified_graph_operator(node)
                ),
                "use a graph whose activation/weight compute stays on CUDA; CPU shape metadata must remain host metadata and introduce zero graph-internal Memcpy nodes",
            ));
        }
        if !assigned_by_name.contains_key(name) {
            return Err(placement_error(
                "CALYX_ONNX_OPTIMIZED_GRAPH_UNASSIGNED_NODE",
                format!(
                    "optimized graph node {name:?} ({}) has no API-24 provider assignment",
                    qualified_graph_operator(node)
                ),
                "repair assignment recording or normalize the optimized graph so every executable node maps one-to-one before admission",
            ));
        }
    }
    if graph_nodes.len() != assigned_by_name.len() {
        return Err(placement_error(
            "CALYX_ONNX_GRAPH_ASSIGNMENT_COUNT_MISMATCH",
            format!(
                "optimized graph has {} nodes but API-24 assignment has {}",
                graph_nodes.len(),
                assigned_by_name.len()
            ),
            "preserve both inventories and repair their exact one-to-one mapping",
        ));
    }

    let mut cuda_nodes = Vec::new();
    let mut cpu_nodes = Vec::new();
    for node in &assignment.nodes {
        match node.provider.as_str() {
            CUDA_PROVIDER => cuda_nodes.push(node.clone()),
            CPU_PROVIDER => cpu_nodes.push(node.clone()),
            provider => {
                return Err(placement_error(
                    "CALYX_ONNX_UNKNOWN_EXECUTION_PROVIDER",
                    format!(
                        "node {:?} changed to unsupported provider {provider:?} during categorical partitioning",
                        node.name
                    ),
                    "preserve the assignment receipt and repair provider-identity handling before retrying",
                ));
            }
        }
    }
    if cuda_nodes.is_empty() {
        return Err(placement_error(
            "CALYX_ONNX_CUDA_COMPUTE_MISSING",
            format!(
                "optimized graph has no node assigned to {CUDA_PROVIDER}; providers={}",
                assignment.per_provider
            ),
            "select the explicit CPU policy only when CPU execution is intended and separately authorized; a CUDA session must execute real compute on CUDA",
        ));
    }
    let cpu_metadata_proofs = if cpu_nodes.is_empty() {
        BTreeMap::new()
    } else {
        classify_cpu_metadata(graph, &assigned_by_name, &cpu_nodes, standard_opset)?
    };

    cuda_nodes.sort_by(|left, right| left.name.cmp(&right.name));
    cpu_nodes.sort_by(|left, right| left.name.cmp(&right.name));
    let cuda_inventory = node_inventory(&cuda_nodes);
    let cpu_inventory = node_inventory(&cpu_nodes);
    let cpu_proof_inventory = cpu_metadata_proofs
        .iter()
        .map(|(name, proof)| {
            format!(
                "{name}=max_elements:{};dtypes:{}",
                proof.max_output_elements, proof.output_dtypes
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let mut cpu_proof_part_bytes = Vec::new();
    for (name, proof) in &cpu_metadata_proofs {
        cpu_proof_part_bytes.push(name.as_bytes().to_vec());
        cpu_proof_part_bytes.push(proof.max_output_elements.to_be_bytes().to_vec());
        cpu_proof_part_bytes.push(proof.output_dtypes.as_bytes().to_vec());
    }
    let cpu_proof_parts = cpu_proof_part_bytes
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    let cpu_metadata_proof_sha256 = hash_length_delimited(&cpu_proof_parts)?;
    let optimized_sha256 = format!("{:x}", Sha256::digest(optimized_graph_bytes));
    let mut assignment_parts = Vec::new();
    for node in &assignment.nodes {
        assignment_parts.extend([
            node.provider.as_bytes(),
            node.name.as_bytes(),
            node.domain.as_bytes(),
            node.operator.as_bytes(),
        ]);
    }
    let assignment_sha256 = hash_length_delimited(&assignment_parts)?;
    let contract_sha256 = hash_length_delimited(&[
        CUDA_PLACEMENT_CLASSIFIER_VERSION.as_bytes(),
        opset_sha256.as_bytes(),
        optimized_sha256.as_bytes(),
        assignment_sha256.as_bytes(),
        cpu_metadata_proof_sha256.as_bytes(),
    ])?;
    let optimized_graph_path = optimized_graph_path.to_str().ok_or_else(|| {
        placement_error(
            "CALYX_ONNX_OPTIMIZED_GRAPH_PATH_INVALID",
            format!(
                "optimized graph path {} is not valid UTF-8",
                optimized_graph_path.display()
            ),
            "use a canonical UTF-8 Windows temporary directory and retry",
        )
    })?;
    Ok(CudaPlacementContract {
        classifier_version: CUDA_PLACEMENT_CLASSIFIER_VERSION,
        opset_inventory,
        opset_sha256,
        optimized_graph_path: optimized_graph_path.to_string(),
        optimized_graph_bytes: u64::try_from(optimized_graph_bytes.len()).map_err(|_| {
            placement_error(
                "CALYX_ONNX_OPTIMIZED_GRAPH_SIZE_OVERFLOW",
                "optimized graph byte length exceeds u64",
                "commission an optimized graph within the native process address space",
            )
        })?,
        optimized_graph_sha256: optimized_sha256,
        assignment_sha256,
        cpu_metadata_proof_sha256,
        contract_sha256,
        total_graph_nodes: assignment.total_nodes,
        cuda_compute_node_count: assignment.cuda_nodes,
        cpu_metadata_node_count: assignment.cpu_nodes,
        cuda_compute_nodes: cuda_nodes,
        cpu_metadata_nodes: cpu_nodes,
        cpu_metadata_proofs,
        cuda_node_inventory: cuda_inventory,
        cpu_metadata_node_inventory: cpu_inventory,
        cpu_metadata_proof_inventory: cpu_proof_inventory,
    })
}

fn collect_graph_nodes<'a>(
    graph: &'a Graph<'a>,
    nodes: &mut BTreeMap<String, &'a Node<'a>>,
    nested_graphs: &mut bool,
) -> Result<()> {
    for (index, node) in graph.node.iter().enumerate() {
        if node.name.trim().is_empty() || node.name.trim() != node.name {
            return Err(placement_error(
                "CALYX_ONNX_OPTIMIZED_GRAPH_NODE_NAME_INVALID",
                format!(
                    "optimized graph {:?} node index {index} has an empty or noncanonical name",
                    graph.name
                ),
                "normalize the ONNX model to globally unique nonblank node names before commissioning",
            ));
        }
        if nodes.insert(node.name.to_string(), node).is_some() {
            return Err(placement_error(
                "CALYX_ONNX_OPTIMIZED_GRAPH_DUPLICATE_NODE",
                format!(
                    "optimized ONNX graph contains duplicate node name {:?}",
                    node.name
                ),
                "normalize every graph scope to globally unique node names before commissioning",
            ));
        }
        for attribute in &node.attribute {
            if let Some(nested) = attribute.g.as_deref() {
                *nested_graphs = true;
                collect_graph_nodes(nested, nodes, nested_graphs)?;
            }
            for nested in &attribute.graphs {
                *nested_graphs = true;
                collect_graph_nodes(nested, nodes, nested_graphs)?;
            }
        }
    }
    Ok(())
}

fn canonical_opsets(model: &Model<'_>) -> Result<BTreeMap<String, i64>> {
    let mut opsets = BTreeMap::new();
    for import in &model.opset_import {
        if import.domain.trim() != import.domain || import.version <= 0 {
            return Err(placement_error(
                "CALYX_ONNX_OPSET_IMPORT_INVALID",
                format!(
                    "optimized ONNX model has noncanonical opset import domain={:?} version={}",
                    import.domain, import.version
                ),
                "export one positive, canonical opset import for every node domain",
            ));
        }
        let domain = canonical_domain(import.domain).to_string();
        if opsets.insert(domain.clone(), import.version).is_some() {
            return Err(placement_error(
                "CALYX_ONNX_OPSET_IMPORT_DUPLICATE",
                format!(
                    "optimized ONNX model has duplicate opset import for domain {:?}",
                    if domain.is_empty() {
                        "ai.onnx"
                    } else {
                        domain.as_str()
                    }
                ),
                "export exactly one opset import per canonical domain; empty and ai.onnx are the same standard domain",
            ));
        }
    }
    Ok(opsets)
}

fn canonical_domain(domain: &str) -> &str {
    if domain.is_empty() || domain == "ai.onnx" {
        ""
    } else {
        domain
    }
}

fn reject_external_tensor_data(graph: &Graph<'_>) -> Result<()> {
    for tensor in &graph.initializer {
        reject_external_tensor(tensor, "initializer")?;
    }
    for sparse in &graph.sparse_initializer {
        if let Some(values) = &sparse.values {
            reject_external_tensor(values, "sparse initializer values")?;
        }
        if let Some(indices) = &sparse.indices {
            reject_external_tensor(indices, "sparse initializer indices")?;
        }
    }
    for node in &graph.node {
        for attribute in &node.attribute {
            if let Some(tensor) = &attribute.t {
                reject_external_tensor(tensor, "node attribute tensor")?;
            }
            for tensor in &attribute.tensors {
                reject_external_tensor(tensor, "node attribute tensor list")?;
            }
            if let Some(sparse) = &attribute.sparse_tensor {
                if let Some(values) = &sparse.values {
                    reject_external_tensor(values, "node sparse attribute values")?;
                }
                if let Some(indices) = &sparse.indices {
                    reject_external_tensor(indices, "node sparse attribute indices")?;
                }
            }
            for sparse in &attribute.sparse_tensors {
                if let Some(values) = &sparse.values {
                    reject_external_tensor(values, "node sparse attribute values")?;
                }
                if let Some(indices) = &sparse.indices {
                    reject_external_tensor(indices, "node sparse attribute indices")?;
                }
            }
        }
    }
    Ok(())
}

fn reject_external_tensor(tensor: &TensorProto<'_>, location: &str) -> Result<()> {
    if tensor.data_location() == DataLocation::External || !tensor.external_data().is_empty() {
        return Err(placement_error(
            "CALYX_ONNX_OPTIMIZED_GRAPH_EXTERNAL_DATA_UNBOUND",
            format!(
                "optimized graph {location} {:?} references external tensor data not covered by the single immutable graph snapshot",
                tensor.name()
            ),
            "serialize the optimized graph with inline tensor data, or extend the placement contract to snapshot and hash every external sidecar before admission",
        ));
    }
    Ok(())
}

fn classify_cpu_metadata(
    graph: &Graph<'_>,
    assigned_by_name: &BTreeMap<String, &AssignedNode>,
    cpu_nodes: &[AssignedNode],
    standard_opset: i64,
) -> Result<BTreeMap<String, CpuMetadataNodeProof>> {
    let cpu_names = cpu_nodes
        .iter()
        .map(|node| node.name.as_str())
        .collect::<BTreeSet<_>>();
    let graph_outputs = graph
        .output
        .iter()
        .map(|value| value.name)
        .collect::<BTreeSet<_>>();
    let nodes_by_name = graph
        .node
        .iter()
        .map(|node| (node.name, node))
        .collect::<BTreeMap<_, _>>();
    let mut consumers = BTreeMap::<&str, Vec<(&Node<'_>, usize)>>::new();
    let mut producers = BTreeMap::<&str, &Node<'_>>::new();
    let initializer_names = graph
        .initializer
        .iter()
        .map(TensorProto::name)
        .collect::<BTreeSet<_>>();
    for node in &graph.node {
        for (input_index, input) in node.input.iter().enumerate() {
            if !input.is_empty() {
                consumers
                    .entry(input)
                    .or_default()
                    .push((node, input_index));
            }
        }
        for output in &node.output {
            if output.is_empty() {
                return Err(placement_error(
                    "CALYX_ONNX_METADATA_EMPTY_OUTPUT",
                    format!("node {:?} contains an empty output name", node.name),
                    "normalize optional outputs away or extend the classifier with an explicit operator contract before retrying",
                ));
            }
            if initializer_names.contains(output) {
                return Err(placement_error(
                    "CALYX_ONNX_OPTIMIZED_GRAPH_DUPLICATE_TENSOR",
                    format!(
                        "node {:?} output {output:?} collides with an initializer",
                        node.name
                    ),
                    "repair the optimized graph value namespace before provider placement admission",
                ));
            }
            if producers.insert(output, node).is_some() {
                return Err(placement_error(
                    "CALYX_ONNX_OPTIMIZED_GRAPH_DUPLICATE_TENSOR",
                    format!("optimized graph contains multiple producers for tensor {output:?}"),
                    "repair the optimized graph before provider placement admission",
                ));
            }
        }
    }

    let declared_types = declared_tensor_types(graph)?;
    let declared_ranks = declared_tensor_ranks(graph)?;
    let mut metadata = initializer_metadata(graph)?;
    let mut authorized = BTreeSet::<String>::new();

    let mut progress = true;
    while progress {
        progress = false;
        for cpu in cpu_nodes {
            if authorized.contains(&cpu.name) {
                continue;
            }
            let node = nodes_by_name.get(cpu.name.as_str()).ok_or_else(|| {
                placement_error(
                    "CALYX_ONNX_GRAPH_ASSIGNMENT_UNMAPPED_NODE",
                    format!(
                        "CPU-assigned node {:?} is absent from the main graph",
                        cpu.name
                    ),
                    "preserve the graph and assignment inventories and repair their mapping",
                )
            })?;
            let Some(outputs) = infer_metadata_outputs(node, &metadata, &declared_ranks)? else {
                continue;
            };
            if outputs.len() != node.output.len() {
                return Err(placement_error(
                    "CALYX_ONNX_METADATA_OUTPUT_COUNT_MISMATCH",
                    format!(
                        "metadata inference for node {:?} produced {} facts for {} outputs",
                        node.name,
                        outputs.len(),
                        node.output.len()
                    ),
                    "repair the operator-specific metadata inference contract before retrying",
                ));
            }
            for (name, inferred) in node.output.iter().zip(outputs) {
                if let Some(declared) = declared_types.get(name)
                    && *declared != inferred.dtype
                {
                    return Err(placement_error(
                        "CALYX_ONNX_METADATA_TYPE_MISMATCH",
                        format!(
                            "CPU metadata node {:?} output {name:?} inferred {:?} but optimized graph declares {:?}",
                            node.name, inferred.dtype, declared
                        ),
                        "preserve the optimized graph and repair type inference before retrying",
                    ));
                }
                metadata.insert(name, inferred);
            }
            authorized.insert(cpu.name.clone());
            progress = true;
        }
    }

    let unclassified = cpu_names
        .iter()
        .filter(|name| !authorized.contains(**name))
        .copied()
        .collect::<Vec<_>>();
    if !unclassified.is_empty() {
        let details = unclassified
            .iter()
            .map(|name| {
                let node = nodes_by_name[name];
                format!("{name}={}", qualified_graph_operator(node))
            })
            .collect::<Vec<_>>()
            .join(",");
        return Err(placement_error(
            "CALYX_ONNX_CPU_COMPUTE_UNCLASSIFIED",
            format!(
                "CPU-assigned nodes are not proven bounded integral/bool shape metadata: {details}"
            ),
            "use a CUDA-capable model for substantive compute; extend the metadata classifier only with schema/dataflow proof, never an operator-name fallback",
        ));
    }

    let mut proofs = BTreeMap::new();
    for cpu in cpu_nodes {
        let node = nodes_by_name[cpu.name.as_str()];
        let mut max_output_elements = 0u64;
        let mut output_dtypes = BTreeSet::new();
        for output in &node.output {
            let fact = metadata.get(output).ok_or_else(|| {
                placement_error(
                    "CALYX_ONNX_METADATA_FACT_MISSING",
                    format!(
                        "authorized CPU metadata node {:?} has no fact for output {output:?}",
                        node.name
                    ),
                    "repair metadata propagation before admitting the session",
                )
            })?;
            if !is_metadata_dtype(fact.dtype) || fact.max_elements == 0 {
                return Err(placement_error(
                    "CALYX_ONNX_METADATA_OUTPUT_UNBOUNDED",
                    format!(
                        "CPU metadata output {output:?} has dtype {:?} max_elements={}",
                        fact.dtype, fact.max_elements
                    ),
                    "restrict CPU shape metadata to a finite nonempty integral/bool tensor",
                ));
            }
            max_output_elements = max_output_elements
                .checked_add(fact.max_elements)
                .ok_or_else(|| {
                    placement_error(
                        "CALYX_ONNX_METADATA_BOUND_OVERFLOW",
                        format!(
                            "CPU metadata node {:?} aggregate output bound exceeds u64",
                            node.name
                        ),
                        "commission a bounded shape-metadata graph",
                    )
                })?;
            output_dtypes.insert(metadata_dtype_name(fact.dtype));
            if graph_outputs.contains(output) {
                return Err(placement_error(
                    "CALYX_ONNX_CPU_METADATA_GRAPH_OUTPUT_ESCAPE",
                    format!(
                        "CPU metadata tensor {output:?} from node {:?} is a model output",
                        node.name
                    ),
                    "model outputs must be substantive CUDA results; remove the CPU output or commission an explicit CPU model",
                ));
            }
            let output_consumers = consumers.get(*output).ok_or_else(|| {
                placement_error(
                    "CALYX_ONNX_CPU_METADATA_DEAD_OUTPUT",
                    format!(
                        "CPU metadata tensor {output:?} from node {:?} has no consumer",
                        node.name
                    ),
                    "remove the dead node or produce a normalized optimized graph before retrying",
                )
            })?;
            for (consumer, input_index) in output_consumers {
                let assigned = assigned_by_name.get(consumer.name).ok_or_else(|| {
                    placement_error(
                        "CALYX_ONNX_OPTIMIZED_GRAPH_UNASSIGNED_NODE",
                        format!(
                            "consumer {:?} of CPU metadata tensor {output:?} has no provider assignment",
                            consumer.name
                        ),
                        "repair assignment recording before placement admission",
                    )
                })?;
                if assigned.provider == CPU_PROVIDER {
                    if !authorized.contains(consumer.name) {
                        return Err(placement_error(
                            "CALYX_ONNX_CPU_METADATA_UNCLASSIFIED_CONSUMER",
                            format!(
                                "CPU metadata tensor {output:?} reaches unclassified CPU node {:?}",
                                consumer.name
                            ),
                            "repair the metadata subgraph so every CPU consumer is independently proven",
                        ));
                    }
                } else if assigned.provider == CUDA_PROVIDER {
                    if !cuda_metadata_input(consumer, *input_index, standard_opset, *fact) {
                        return Err(placement_error(
                            "CALYX_ONNX_CPU_METADATA_CONTENT_ESCAPE",
                            format!(
                                "CPU metadata tensor {output:?} reaches CUDA node {:?} ({}) at substantive input index {input_index}",
                                consumer.name,
                                qualified_graph_operator(consumer)
                            ),
                            "CPU metadata may feed only schema-defined shape/axes/size inputs; move content computation to CUDA or reject the model",
                        ));
                    }
                } else {
                    return Err(placement_error(
                        "CALYX_ONNX_UNKNOWN_EXECUTION_PROVIDER",
                        format!(
                            "consumer {:?} of CPU metadata tensor {output:?} uses provider {:?}",
                            consumer.name, assigned.provider
                        ),
                        "configure only the categorical CUDA plus classified CPU-metadata contract",
                    ));
                }
            }
        }
        proofs.insert(
            cpu.name.clone(),
            CpuMetadataNodeProof {
                max_output_elements,
                output_dtypes: output_dtypes.into_iter().collect::<Vec<_>>().join(","),
            },
        );
    }
    Ok(proofs)
}

fn infer_metadata_outputs(
    node: &Node<'_>,
    metadata: &BTreeMap<&str, MetadataTensor>,
    declared_ranks: &BTreeMap<&str, usize>,
) -> Result<Option<Vec<MetadataTensor>>> {
    let standard_domain = node.domain.is_empty() || node.domain == "ai.onnx";
    if !standard_domain {
        return Ok(None);
    }
    let output_count = node.output.len();
    if output_count == 0 {
        return Ok(None);
    }
    let checked_repeat = |fact: MetadataTensor| Ok(vec![fact; output_count]);
    match &node.op_type {
        OpType::Shape => {
            if node.input.len() != 1 {
                return Ok(None);
            }
            let rank = declared_ranks.get(node.input[0]).copied().ok_or_else(|| {
                placement_error(
                    "CALYX_ONNX_METADATA_RANK_UNPROVEN",
                    format!(
                        "Shape node {:?} input {:?} has no declared rank",
                        node.name, node.input[0]
                    ),
                    "export fixed-rank tensor type information in the optimized graph before retrying",
                )
            })?;
            let (start, end) = shape_slice(node, rank)?;
            let elements = end.checked_sub(start).ok_or_else(|| {
                placement_error(
                    "CALYX_ONNX_METADATA_BOUND_OVERFLOW",
                    format!("Shape node {:?} has invalid normalized slice", node.name),
                    "repair the Shape start/end attributes before retrying",
                )
            })?;
            checked_repeat(MetadataTensor {
                dtype: DataType::Int64,
                max_elements: nonzero_u64(elements, node, "Shape")?,
            })
            .map(Some)
        }
        OpType::Size => {
            if node.input.len() != 1 {
                return Ok(None);
            }
            checked_repeat(MetadataTensor {
                dtype: DataType::Int64,
                max_elements: 1,
            })
            .map(Some)
        }
        OpType::Constant => {
            if node.input.iter().any(|input| !input.is_empty()) {
                return Ok(None);
            }
            let fact = constant_metadata(node)?;
            match fact {
                Some(fact) => checked_repeat(fact).map(Some),
                None => Ok(None),
            }
        }
        OpType::Identity
        | OpType::Reshape
        | OpType::Transpose
        | OpType::Flatten
        | OpType::Squeeze
        | OpType::Unsqueeze => {
            let Some(input) = first_metadata_input(node, metadata) else {
                return Ok(None);
            };
            if !all_remaining_inputs_metadata(node, metadata, 1) {
                return Ok(None);
            }
            checked_repeat(input).map(Some)
        }
        OpType::Slice => {
            let Some(input) = first_metadata_input(node, metadata) else {
                return Ok(None);
            };
            if !all_remaining_inputs_metadata(node, metadata, 1) {
                return Ok(None);
            }
            checked_repeat(input).map(Some)
        }
        OpType::Gather | OpType::GatherElements | OpType::GatherND => {
            if node.input.len() != 2 {
                return Ok(None);
            }
            let Some(data) = metadata.get(node.input[0]).copied() else {
                return Ok(None);
            };
            let Some(indices) = metadata.get(node.input[1]).copied() else {
                return Ok(None);
            };
            let max_elements = data
                .max_elements
                .checked_mul(indices.max_elements)
                .ok_or_else(|| {
                    placement_error(
                        "CALYX_ONNX_METADATA_BOUND_OVERFLOW",
                        format!("metadata Gather node {:?} bound exceeds u64", node.name),
                        "commission a bounded shape-metadata graph",
                    )
                })?;
            checked_repeat(MetadataTensor {
                dtype: data.dtype,
                max_elements,
            })
            .map(Some)
        }
        OpType::Concat => {
            let Some(inputs) = metadata_inputs(node, metadata) else {
                return Ok(None);
            };
            let dtype = common_dtype(&inputs)?;
            let max_elements = inputs.iter().try_fold(0u64, |sum, fact| {
                sum.checked_add(fact.max_elements).ok_or_else(|| {
                    placement_error(
                        "CALYX_ONNX_METADATA_BOUND_OVERFLOW",
                        format!("metadata Concat node {:?} bound exceeds u64", node.name),
                        "commission a bounded shape-metadata graph",
                    )
                })
            })?;
            checked_repeat(MetadataTensor {
                dtype,
                max_elements,
            })
            .map(Some)
        }
        OpType::Split => {
            let Some(input) = first_metadata_input(node, metadata) else {
                return Ok(None);
            };
            if !all_remaining_inputs_metadata(node, metadata, 1) {
                return Ok(None);
            }
            checked_repeat(input).map(Some)
        }
        OpType::Add
        | OpType::Sub
        | OpType::Mul
        | OpType::Div
        | OpType::Neg
        | OpType::Abs
        | OpType::Pow
        | OpType::Mod
        | OpType::BitShift
        | OpType::BitwiseAnd
        | OpType::BitwiseOr
        | OpType::BitwiseXor
        | OpType::BitwiseNot
        | OpType::Min
        | OpType::Max
        | OpType::Sum => {
            let Some(inputs) = metadata_inputs(node, metadata) else {
                return Ok(None);
            };
            let dtype = common_dtype(&inputs)?;
            let max_elements = broadcast_element_bound(node, &inputs)?;
            checked_repeat(MetadataTensor {
                dtype,
                max_elements: nonzero_bound(max_elements, node)?,
            })
            .map(Some)
        }
        OpType::ReduceMax | OpType::ReduceMin | OpType::ReduceSum | OpType::ReduceProd => {
            let Some(input) = first_metadata_input(node, metadata) else {
                return Ok(None);
            };
            if !all_remaining_inputs_metadata(node, metadata, 1) {
                return Ok(None);
            }
            checked_repeat(input).map(Some)
        }
        OpType::Equal
        | OpType::Greater
        | OpType::GreaterOrEqual
        | OpType::Less
        | OpType::LessOrEqual
        | OpType::Not
        | OpType::And
        | OpType::Or
        | OpType::Xor => {
            let Some(inputs) = metadata_inputs(node, metadata) else {
                return Ok(None);
            };
            let max_elements = broadcast_element_bound(node, &inputs)?;
            checked_repeat(MetadataTensor {
                dtype: DataType::Bool,
                max_elements: nonzero_bound(max_elements, node)?,
            })
            .map(Some)
        }
        OpType::Where => {
            if node.input.len() != 3 {
                return Ok(None);
            }
            let Some(condition) = metadata.get(node.input[0]).copied() else {
                return Ok(None);
            };
            let Some(left) = metadata.get(node.input[1]).copied() else {
                return Ok(None);
            };
            let Some(right) = metadata.get(node.input[2]).copied() else {
                return Ok(None);
            };
            if condition.dtype != DataType::Bool || left.dtype != right.dtype {
                return Ok(None);
            }
            checked_repeat(MetadataTensor {
                dtype: left.dtype,
                max_elements: broadcast_element_bound(node, &[condition, left, right])?,
            })
            .map(Some)
        }
        OpType::Cast => {
            let Some(input) = first_metadata_input(node, metadata) else {
                return Ok(None);
            };
            if node.input.len() != 1 {
                return Ok(None);
            }
            let Some(to) = unique_int_attribute(node, "to")? else {
                return Ok(None);
            };
            let dtype = i32::try_from(to)
                .ok()
                .and_then(|value| DataType::try_from(value).ok())
                .filter(|dtype| is_metadata_dtype(*dtype));
            let Some(dtype) = dtype else {
                return Ok(None);
            };
            checked_repeat(MetadataTensor {
                dtype,
                max_elements: input.max_elements,
            })
            .map(Some)
        }
        OpType::CastLike => {
            if node.input.len() != 2 {
                return Ok(None);
            }
            let Some(input) = metadata.get(node.input[0]).copied() else {
                return Ok(None);
            };
            let Some(target) = metadata.get(node.input[1]).copied() else {
                return Ok(None);
            };
            checked_repeat(MetadataTensor {
                dtype: target.dtype,
                max_elements: input.max_elements,
            })
            .map(Some)
        }
        // A metadata-looking dtype is not enough to authorize an unknown
        // operator. Returning `None` makes the categorical gate name the
        // exact unclassified CPU node.
        _ => Ok(None),
    }
}

fn initializer_metadata<'a>(graph: &'a Graph<'a>) -> Result<BTreeMap<&'a str, MetadataTensor>> {
    let mut metadata = BTreeMap::new();
    let mut initializer_names = BTreeSet::new();
    for tensor in &graph.initializer {
        if tensor.name().trim().is_empty() || tensor.name().trim() != tensor.name() {
            return Err(placement_error(
                "CALYX_ONNX_METADATA_INITIALIZER_NAME_INVALID",
                format!(
                    "optimized graph contains an empty or noncanonical initializer name {:?}",
                    tensor.name()
                ),
                "normalize every initializer to a unique nonblank name",
            ));
        }
        if !initializer_names.insert(tensor.name()) {
            return Err(placement_error(
                "CALYX_ONNX_METADATA_INITIALIZER_DUPLICATE",
                format!(
                    "optimized graph contains duplicate initializer name {:?}",
                    tensor.name()
                ),
                "normalize every initializer to a unique name",
            ));
        }
        if !is_metadata_dtype(tensor.data_type()) {
            continue;
        }
        let elements = tensor.dims().iter().try_fold(1u64, |product, dimension| {
            let dimension = u64::try_from(*dimension).map_err(|_| {
                placement_error(
                    "CALYX_ONNX_METADATA_INITIALIZER_SHAPE_INVALID",
                    format!(
                        "integral/bool initializer {:?} has negative dimension {dimension}",
                        tensor.name()
                    ),
                    "repair the optimized ONNX initializer shape",
                )
            })?;
            product.checked_mul(dimension).ok_or_else(|| {
                placement_error(
                    "CALYX_ONNX_METADATA_BOUND_OVERFLOW",
                    format!(
                        "integral/bool initializer {:?} element count exceeds u64",
                        tensor.name()
                    ),
                    "commission a bounded ONNX graph",
                )
            })
        })?;
        metadata.insert(
            tensor.name(),
            MetadataTensor {
                dtype: tensor.data_type(),
                max_elements: nonzero_bound_for_label(
                    elements,
                    format!("initializer {:?}", tensor.name()),
                )?,
            },
        );
    }
    Ok(metadata)
}

fn declared_tensor_types<'a>(graph: &'a Graph<'a>) -> Result<BTreeMap<&'a str, DataType>> {
    let mut types = BTreeMap::new();
    for value in graph
        .input
        .iter()
        .chain(&graph.output)
        .chain(&graph.value_info)
    {
        if let Some(dtype) = value.tensor_elem_type()
            && let Some(existing) = types.insert(value.name, dtype)
            && existing != dtype
        {
            return Err(placement_error(
                "CALYX_ONNX_OPTIMIZED_GRAPH_TYPE_CONFLICT",
                format!(
                    "optimized graph contains conflicting types for tensor {:?}: {:?} versus {:?}",
                    value.name, existing, dtype
                ),
                "repair optimized-model type inference before retrying",
            ));
        }
    }
    for tensor in &graph.initializer {
        if let Some(existing) = types.insert(tensor.name(), tensor.data_type())
            && existing != tensor.data_type()
        {
            return Err(placement_error(
                "CALYX_ONNX_OPTIMIZED_GRAPH_TYPE_CONFLICT",
                format!(
                    "initializer {:?} type {:?} conflicts with declared {:?}",
                    tensor.name(),
                    tensor.data_type(),
                    existing
                ),
                "repair optimized-model type inference before retrying",
            ));
        }
    }
    Ok(types)
}

fn declared_tensor_ranks<'a>(graph: &'a Graph<'a>) -> Result<BTreeMap<&'a str, usize>> {
    let mut ranks = BTreeMap::new();
    for value in graph
        .input
        .iter()
        .chain(&graph.output)
        .chain(&graph.value_info)
    {
        if let Some(rank) = value.tensor_shape().map(|shape| shape.rank())
            && let Some(existing) = ranks.insert(value.name, rank)
            && existing != rank
        {
            return Err(placement_error(
                "CALYX_ONNX_OPTIMIZED_GRAPH_RANK_CONFLICT",
                format!(
                    "optimized graph contains conflicting ranks for tensor {:?}: {} versus {}",
                    value.name, existing, rank
                ),
                "repair optimized-model shape inference before retrying",
            ));
        }
    }
    for tensor in &graph.initializer {
        let rank = tensor.dims().len();
        if let Some(existing) = ranks.insert(tensor.name(), rank)
            && existing != rank
        {
            return Err(placement_error(
                "CALYX_ONNX_OPTIMIZED_GRAPH_RANK_CONFLICT",
                format!(
                    "initializer {:?} rank {} conflicts with declared {}",
                    tensor.name(),
                    rank,
                    existing
                ),
                "repair optimized-model shape inference before retrying",
            ));
        }
    }
    Ok(ranks)
}

fn constant_metadata(node: &Node<'_>) -> Result<Option<MetadataTensor>> {
    let mut found = None;
    for attribute in &node.attribute {
        let candidate = match (attribute.name, attribute.r#type) {
            ("value", AttributeType::Tensor) => match attribute.t.as_ref() {
                Some(tensor) if is_metadata_dtype(tensor.data_type()) => {
                    let max_elements =
                        tensor
                            .dims()
                            .iter()
                            .try_fold(1u64, |product, dimension| {
                                let dimension = u64::try_from(*dimension).map_err(|_| {
                                    placement_error(
                                        "CALYX_ONNX_METADATA_CONSTANT_SHAPE_INVALID",
                                        format!(
                                            "Constant node {:?} has negative tensor dimension {dimension}",
                                            node.name
                                        ),
                                        "repair the integral/bool Constant tensor shape",
                                    )
                                })?;
                                product.checked_mul(dimension).ok_or_else(|| {
                                    placement_error(
                                        "CALYX_ONNX_METADATA_BOUND_OVERFLOW",
                                        format!(
                                            "Constant node {:?} tensor element count exceeds u64",
                                            node.name
                                        ),
                                        "commission a bounded shape-metadata graph",
                                    )
                                })
                            })?;
                    Some(MetadataTensor {
                        dtype: tensor.data_type(),
                        max_elements: nonzero_bound(max_elements, node)?,
                    })
                }
                Some(_) => None,
                None => {
                    return Err(placement_error(
                        "CALYX_ONNX_METADATA_CONSTANT_VALUE_MISSING",
                        format!(
                            "Constant node {:?} declares a Tensor value attribute without a tensor",
                            node.name
                        ),
                        "repair the malformed Constant attribute before retrying",
                    ));
                }
            },
            ("value_int", AttributeType::Int) => Some(MetadataTensor {
                dtype: DataType::Int64,
                max_elements: 1,
            }),
            ("value_ints", AttributeType::Ints) => Some(MetadataTensor {
                dtype: DataType::Int64,
                max_elements: nonzero_u64(attribute.ints.len(), node, "Constant value_ints")?,
            }),
            _ => None,
        };
        if let Some(candidate) = candidate {
            if found.replace(candidate).is_some() {
                return Err(placement_error(
                    "CALYX_ONNX_METADATA_CONSTANT_AMBIGUOUS",
                    format!(
                        "Constant node {:?} has multiple integral/bool value attributes",
                        node.name
                    ),
                    "normalize the Constant node to one value attribute before retrying",
                ));
            }
        }
    }
    Ok(found)
}

fn metadata_inputs(
    node: &Node<'_>,
    metadata: &BTreeMap<&str, MetadataTensor>,
) -> Option<Vec<MetadataTensor>> {
    let inputs = node
        .input
        .iter()
        .filter(|input| !input.is_empty())
        .map(|input| metadata.get(input).copied())
        .collect::<Option<Vec<_>>>()?;
    (!inputs.is_empty()).then_some(inputs)
}

fn first_metadata_input(
    node: &Node<'_>,
    metadata: &BTreeMap<&str, MetadataTensor>,
) -> Option<MetadataTensor> {
    node.input
        .first()
        .filter(|input| !input.is_empty())
        .and_then(|input| metadata.get(input).copied())
}

fn all_remaining_inputs_metadata(
    node: &Node<'_>,
    metadata: &BTreeMap<&str, MetadataTensor>,
    start: usize,
) -> bool {
    node.input
        .iter()
        .skip(start)
        .filter(|input| !input.is_empty())
        .all(|input| metadata.contains_key(input))
}

fn common_dtype(inputs: &[MetadataTensor]) -> Result<DataType> {
    let dtype = inputs.first().map(|fact| fact.dtype).ok_or_else(|| {
        placement_error(
            "CALYX_ONNX_METADATA_INPUT_MISSING",
            "metadata operator has no input facts",
            "repair metadata propagation before retrying",
        )
    })?;
    if inputs.iter().any(|fact| fact.dtype != dtype) {
        return Err(placement_error(
            "CALYX_ONNX_METADATA_TYPE_MISMATCH",
            format!(
                "metadata operator combines incompatible dtypes: {:?}",
                inputs.iter().map(|fact| fact.dtype).collect::<Vec<_>>()
            ),
            "normalize the shape-metadata dtypes before retrying",
        ));
    }
    Ok(dtype)
}

fn broadcast_element_bound(node: &Node<'_>, inputs: &[MetadataTensor]) -> Result<u64> {
    if inputs.is_empty() {
        return Err(placement_error(
            "CALYX_ONNX_METADATA_INPUT_MISSING",
            format!("metadata node {:?} has no inputs to bound", node.name),
            "repair metadata propagation before retrying",
        ));
    }
    inputs.iter().try_fold(1u64, |bound, input| {
        bound.checked_mul(input.max_elements).ok_or_else(|| {
            placement_error(
                "CALYX_ONNX_METADATA_BOUND_OVERFLOW",
                format!(
                    "metadata node {:?} conservative broadcast bound exceeds u64",
                    node.name
                ),
                "commission a bounded shape-metadata graph or add exact declared-shape broadcast proof",
            )
        })
    })
}

fn shape_slice(node: &Node<'_>, rank: usize) -> Result<(usize, usize)> {
    let rank_i64 = i64::try_from(rank).map_err(|_| {
        placement_error(
            "CALYX_ONNX_METADATA_RANK_OVERFLOW",
            format!("Shape node {:?} input rank exceeds i64", node.name),
            "commission a tensor rank representable by ONNX",
        )
    })?;
    let start = unique_int_attribute(node, "start")?.unwrap_or(0);
    let end = unique_int_attribute(node, "end")?.unwrap_or(rank_i64);
    let normalize = |value: i64| {
        if value < 0 {
            rank_i64.checked_add(value)
        } else {
            Some(value)
        }
        .filter(|value| (0..=rank_i64).contains(value))
    };
    let start = normalize(start).ok_or_else(|| {
        placement_error(
            "CALYX_ONNX_METADATA_SHAPE_SLICE_INVALID",
            format!("Shape node {:?} start is outside rank {rank}", node.name),
            "repair the Shape start attribute",
        )
    })?;
    let end = normalize(end).ok_or_else(|| {
        placement_error(
            "CALYX_ONNX_METADATA_SHAPE_SLICE_INVALID",
            format!("Shape node {:?} end is outside rank {rank}", node.name),
            "repair the Shape end attribute",
        )
    })?;
    if start > end {
        return Err(placement_error(
            "CALYX_ONNX_METADATA_SHAPE_SLICE_INVALID",
            format!(
                "Shape node {:?} normalized start {start} exceeds end {end}",
                node.name
            ),
            "repair the Shape slice attributes",
        ));
    }
    Ok((
        usize::try_from(start).map_err(|_| {
            placement_error(
                "CALYX_ONNX_METADATA_RANK_OVERFLOW",
                format!("Shape node {:?} normalized start exceeds usize", node.name),
                "commission a tensor rank representable by the native process",
            )
        })?,
        usize::try_from(end).map_err(|_| {
            placement_error(
                "CALYX_ONNX_METADATA_RANK_OVERFLOW",
                format!("Shape node {:?} normalized end exceeds usize", node.name),
                "commission a tensor rank representable by the native process",
            )
        })?,
    ))
}

fn unique_int_attribute(node: &Node<'_>, name: &str) -> Result<Option<i64>> {
    let mut found = None;
    for attribute in node
        .attribute
        .iter()
        .filter(|attribute| attribute.name == name)
    {
        if attribute.r#type != AttributeType::Int {
            return Err(placement_error(
                "CALYX_ONNX_METADATA_ATTRIBUTE_TYPE_INVALID",
                format!(
                    "metadata node {:?} attribute {name:?} has type {:?}, expected Int",
                    node.name, attribute.r#type
                ),
                "repair the operator attribute type before retrying",
            ));
        }
        if found.replace(attribute.i).is_some() {
            return Err(placement_error(
                "CALYX_ONNX_METADATA_ATTRIBUTE_DUPLICATE",
                format!(
                    "metadata node {:?} contains duplicate attribute {name:?}",
                    node.name
                ),
                "normalize the operator to one canonical attribute before retrying",
            ));
        }
    }
    Ok(found)
}

fn cuda_metadata_input(
    node: &Node<'_>,
    input_index: usize,
    standard_opset: i64,
    fact: MetadataTensor,
) -> bool {
    if canonical_domain(node.domain) != "" {
        return false;
    }
    let role = match node.op_type.as_str() {
        "Reshape" if standard_opset >= 5 => input_index == 1,
        "Tile" if standard_opset >= 6 => input_index == 1,
        "Expand" if standard_opset >= 8 => input_index == 1,
        "OneHot" if standard_opset >= 9 => input_index == 1,
        "Slice" if standard_opset >= 10 => (1..=4).contains(&input_index),
        "TopK" if standard_opset >= 10 => input_index == 1,
        "CumSum" if standard_opset >= 11 => input_index == 1,
        "Resize" if standard_opset >= 11 => input_index == 3,
        "Pad" if standard_opset >= 18 => input_index == 1 || input_index == 3,
        "Pad" if standard_opset >= 11 => input_index == 1,
        "Split" | "Squeeze" | "Unsqueeze" if standard_opset >= 13 => input_index == 1,
        "Trilu" if standard_opset >= 14 => input_index == 1,
        "ReduceMax" | "ReduceMin" | "ReduceMean" | "ReduceSum" | "ReduceProd" | "ReduceL1"
        | "ReduceL2" | "ReduceLogSum" | "ReduceLogSumExp" | "ReduceSumSquare"
            if standard_opset >= 18 =>
        {
            input_index == 1
        }
        "ConstantOfShape" if standard_opset >= 9 => input_index == 0,
        "Shape" | "Size" if standard_opset >= 1 => input_index == 0,
        _ => false,
    };
    if !role {
        return false;
    }
    match node.op_type.as_str() {
        "Shape" | "Size" => is_metadata_dtype(fact.dtype),
        "CumSum" => {
            matches!(fact.dtype, DataType::Int32 | DataType::Int64) && fact.max_elements == 1
        }
        "TopK" | "OneHot" | "Trilu" => fact.dtype == DataType::Int64 && fact.max_elements == 1,
        _ => fact.dtype == DataType::Int64,
    }
}

fn is_metadata_dtype(dtype: DataType) -> bool {
    matches!(
        dtype,
        DataType::Bool
            | DataType::Uint8
            | DataType::Int8
            | DataType::Uint16
            | DataType::Int16
            | DataType::Int32
            | DataType::Int64
            | DataType::Uint32
            | DataType::Uint64
    )
}

fn metadata_dtype_name(dtype: DataType) -> &'static str {
    match dtype {
        DataType::Bool => "bool",
        DataType::Uint8 => "uint8",
        DataType::Int8 => "int8",
        DataType::Uint16 => "uint16",
        DataType::Int16 => "int16",
        DataType::Int32 => "int32",
        DataType::Int64 => "int64",
        DataType::Uint32 => "uint32",
        DataType::Uint64 => "uint64",
        _ => "unclassified",
    }
}

fn is_memcpy_operator(operator: &str) -> bool {
    matches!(operator, "Memcpy" | "MemcpyFromHost" | "MemcpyToHost")
}

fn qualified_graph_operator(node: &Node<'_>) -> String {
    if node.domain.is_empty() {
        node.op_type.as_str().to_string()
    } else {
        format!("{}::{}", node.domain, node.op_type.as_str())
    }
}

fn domains_equivalent(left: &str, right: &str) -> bool {
    left == right
        || ((left.is_empty() || left == "ai.onnx") && (right.is_empty() || right == "ai.onnx"))
}

fn node_inventory(nodes: &[AssignedNode]) -> String {
    nodes
        .iter()
        .map(|node| node.inventory_entry())
        .collect::<Vec<_>>()
        .join(",")
}

fn hash_length_delimited(parts: &[&[u8]]) -> Result<String> {
    let mut hash = Sha256::new();
    for part in parts {
        let length = u64::try_from(part.len()).map_err(|_| {
            placement_error(
                "CALYX_ONNX_PLACEMENT_HASH_LENGTH_OVERFLOW",
                "placement-contract hash part exceeds u64 bytes",
                "commission a graph whose attestation fields fit the native u64 wire contract",
            )
        })?;
        hash.update(length.to_be_bytes());
        hash.update(part);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn nonzero_u64(value: usize, node: &Node<'_>, operator: &str) -> Result<u64> {
    let value = u64::try_from(value).map_err(|_| {
        placement_error(
            "CALYX_ONNX_METADATA_BOUND_OVERFLOW",
            format!("{operator} node {:?} bound exceeds u64", node.name),
            "commission a bounded shape-metadata graph",
        )
    })?;
    nonzero_bound(value, node)
}

fn nonzero_bound(value: u64, node: &Node<'_>) -> Result<u64> {
    if value == 0 {
        return Err(placement_error(
            "CALYX_ONNX_METADATA_OUTPUT_EMPTY",
            format!(
                "metadata node {:?} has a zero-element output bound",
                node.name
            ),
            "remove empty metadata computation or define a nonempty shape contract",
        ));
    }
    Ok(value)
}

fn nonzero_bound_for_label(value: u64, label: String) -> Result<u64> {
    if value == 0 {
        return Err(placement_error(
            "CALYX_ONNX_METADATA_OUTPUT_EMPTY",
            format!("{label} has a zero-element metadata tensor"),
            "remove empty metadata computation or define a nonempty shape contract",
        ));
    }
    Ok(value)
}

fn placement_error(
    code: &'static str,
    message: impl Into<String>,
    remediation: &'static str,
) -> CalyxError {
    CalyxError {
        code,
        message: message.into(),
        remediation,
    }
}
