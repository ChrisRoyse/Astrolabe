//! Structural attestation for commissioned ONNX INT8 graphs.
//!
//! The attestor parses source and quantizer-output protobuf bytes, validates
//! supported quantization paths and external tensor storage, and binds the
//! observed semantics into a deterministic manifest identity. Manifest reads
//! recompute the same identity from the persisted bytes and fail closed on any
//! drift.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::{Component, Path, PathBuf};

use calyx_core::{CalyxError, Result};
use onnx_rs::ast::{DataLocation, DataType, Graph, Node, OpType, TensorProto, TypeValue};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};

use super::manifest::{LensForgeFile, LensForgeManifest};

const ATTESTATION_INVALID: &str = "CALYX_ONNX_INT8_ATTESTATION_INVALID";
const ATTESTATION_FORMAT: &str = "calyx-onnx-int8-attestation-v1";
const HASH_BUFFER_BYTES: usize = 1024 * 1024;
const MAX_SCALE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_SCALE_EXPRESSION_DEPTH: usize = 16;
const MAX_QUANTIZED_VALUE_TRACE_DEPTH: usize = 64;
const MAX_WEIGHT_ORIGIN_TRACE_DEPTH: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// Frozen converter and Python package identities used for quantization.
pub struct OnnxInt8Toolchain {
    pub converter: String,
    pub converter_version: String,
    pub optimum_onnx_version: String,
    pub converter_executable_sha256: String,
    pub python_version: String,
    pub python_executable_sha256: String,
    pub onnx_version: String,
    pub onnxruntime_version: String,
    pub quant_target: String,
    pub frozen_options: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// One deterministic name/count entry in a graph inventory.
pub struct OnnxInventoryCount {
    pub name: String,
    pub count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// A graph input or output tensor's declared element type and shape.
pub struct OnnxTensorBoundary {
    pub name: String,
    pub elem_type: String,
    pub shape: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// One tensor's exact byte range inside an ONNX external-data file.
pub struct OnnxExternalTensorSlice {
    pub tensor: String,
    pub offset: u64,
    pub length: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared_sha1: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// Content identity and tensor ranges for one external-data file.
pub struct OnnxExternalDataFile {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
    pub slices: Vec<OnnxExternalTensorSlice>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// Reproducible content and semantic inventory for one ONNX graph.
pub struct OnnxGraphIdentity {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
    pub ir_version: i64,
    pub producer_name: String,
    pub producer_version: String,
    pub opsets: Vec<String>,
    pub operators: Vec<OnnxInventoryCount>,
    pub initializer_dtypes: Vec<OnnxInventoryCount>,
    pub inputs: Vec<OnnxTensorBoundary>,
    pub outputs: Vec<OnnxTensorBoundary>,
    pub external_data: Vec<OnnxExternalDataFile>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// Validated quantized compute, parameter, and floating-boundary inventory.
pub struct OnnxQuantizationInventory {
    pub form: String,
    pub source_eligible_compute_nodes: u64,
    pub quantized_compute_nodes: u64,
    pub qoperator_compute_nodes: u64,
    pub qdq_compute_nodes: u64,
    pub matmul_integer_nodes: u64,
    pub conv_integer_nodes: u64,
    pub qlinear_matmul_nodes: u64,
    pub qlinear_conv_nodes: u64,
    pub dynamic_quantize_linear_nodes: u64,
    pub quantize_linear_nodes: u64,
    pub dequantize_linear_nodes: u64,
    pub integer_weight_tensors: Vec<String>,
    pub scale_tensors: Vec<String>,
    pub zero_point_tensors: Vec<String>,
    pub intentional_float_boundaries: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// Complete source/output/toolchain semantic attestation stored in a manifest.
pub struct OnnxInt8Attestation {
    pub format: String,
    pub source: OnnxGraphIdentity,
    pub output: OnnxGraphIdentity,
    pub toolchain: OnnxInt8Toolchain,
    pub quantization: OnnxQuantizationInventory,
    pub attestation_sha256: String,
}

struct GraphAnalysis {
    identity: OnnxGraphIdentity,
    eligible_compute_nodes: u64,
    qoperator_compute_nodes: u64,
    qdq_compute_nodes: u64,
    matmul_integer_nodes: u64,
    conv_integer_nodes: u64,
    qlinear_matmul_nodes: u64,
    qlinear_conv_nodes: u64,
    dynamic_quantize_linear_nodes: u64,
    quantize_linear_nodes: u64,
    dequantize_linear_nodes: u64,
    integer_weight_tensors: BTreeSet<String>,
    scale_tensors: BTreeSet<String>,
    zero_point_tensors: BTreeSet<String>,
    float_boundaries: Vec<String>,
    residual_float_nodes: Vec<String>,
}

enum FrozenWeightOrigin {
    FloatInitializer { tensor: String, dtype: DataType },
    QuantizedInitializer { tensor: String },
    UnsupportedInitializer { tensor: String, dtype: DataType },
    Dynamic,
}

#[derive(Clone)]
struct ExternalAccess {
    path: PathBuf,
    offset: u64,
    length: u64,
}

struct ExternalResolution {
    files: Vec<OnnxExternalDataFile>,
    tensors: BTreeMap<String, ExternalAccess>,
}

struct GraphContext<'a> {
    graph: &'a Graph<'a>,
    initializers: BTreeMap<&'a str, &'a TensorProto<'a>>,
    producers: BTreeMap<&'a str, usize>,
    consumers: BTreeMap<&'a str, Vec<usize>>,
    external: BTreeMap<String, ExternalAccess>,
}

/// Attests a distinct FP32 source and supported ONNX INT8 quantizer output.
pub fn attest_onnx_int8(
    base_dir: &Path,
    source_path: &Path,
    output_path: &Path,
    toolchain: OnnxInt8Toolchain,
) -> Result<OnnxInt8Attestation> {
    validate_toolchain(&toolchain)?;
    let source_canonical = canonical_file_within(base_dir, source_path, "source graph")?;
    let output_canonical = canonical_file_within(base_dir, output_path, "quantized graph")?;
    if source_canonical == output_canonical {
        return Err(invalid(format!(
            "source graph {} and quantized graph {} resolve to the same file",
            source_path.display(),
            output_path.display()
        )));
    }

    let source = analyze_graph(base_dir, &source_canonical, false)?;
    if source.eligible_compute_nodes == 0 {
        return Err(invalid(format!(
            "source graph {} has no supported constant-weight FP32 MatMul/Gemm/Conv node to quantize",
            source_path.display()
        )));
    }
    if source.qoperator_compute_nodes != 0
        || source.qdq_compute_nodes != 0
        || source.dynamic_quantize_linear_nodes != 0
        || source.quantize_linear_nodes != 0
        || source.dequantize_linear_nodes != 0
    {
        return Err(invalid(format!(
            "source graph {} already contains quantized operators; commissioning requires the distinct pre-quantization FP32 graph",
            source_path.display()
        )));
    }

    let output = analyze_graph(base_dir, &output_canonical, true)?;
    if source.identity.sha256 == output.identity.sha256 {
        return Err(invalid(format!(
            "quantizer output {} is byte-identical to FP32 source {} (sha256={})",
            output_path.display(),
            source_path.display(),
            output.identity.sha256
        )));
    }
    let quantized_compute_nodes = output
        .qoperator_compute_nodes
        .checked_add(output.qdq_compute_nodes)
        .ok_or_else(|| invalid("quantized compute-node count overflow"))?;
    if quantized_compute_nodes == 0 {
        return Err(invalid(format!(
            "quantizer output {} contains no validated QOperator, MatMulInteger/ConvInteger, or QDQ compute path",
            output_path.display()
        )));
    }
    if quantized_compute_nodes < source.eligible_compute_nodes {
        return Err(invalid(format!(
            "quantizer output {} validates only {} quantized compute nodes for {} eligible source compute nodes",
            output_path.display(),
            quantized_compute_nodes,
            source.eligible_compute_nodes
        )));
    }
    if output.identity.inputs != source.identity.inputs
        || output.identity.outputs != source.identity.outputs
    {
        return Err(invalid(format!(
            "quantizer output {} changed the source graph input/output boundary: source_inputs={:?} output_inputs={:?} source_outputs={:?} output_outputs={:?}",
            output_path.display(),
            source.identity.inputs,
            output.identity.inputs,
            source.identity.outputs,
            output.identity.outputs
        )));
    }
    if !output.residual_float_nodes.is_empty() {
        return Err(invalid(format!(
            "quantizer output {} retains eligible constant-weight floating compute nodes: {}",
            output_path.display(),
            output.residual_float_nodes.join(", ")
        )));
    }

    let form = match (output.qoperator_compute_nodes, output.qdq_compute_nodes) {
        (qoperator, 0) if qoperator > 0 => "qoperator",
        (0, qdq) if qdq > 0 => "qdq",
        _ => "hybrid",
    };
    let quantization = OnnxQuantizationInventory {
        form: form.to_string(),
        source_eligible_compute_nodes: source.eligible_compute_nodes,
        quantized_compute_nodes,
        qoperator_compute_nodes: output.qoperator_compute_nodes,
        qdq_compute_nodes: output.qdq_compute_nodes,
        matmul_integer_nodes: output.matmul_integer_nodes,
        conv_integer_nodes: output.conv_integer_nodes,
        qlinear_matmul_nodes: output.qlinear_matmul_nodes,
        qlinear_conv_nodes: output.qlinear_conv_nodes,
        dynamic_quantize_linear_nodes: output.dynamic_quantize_linear_nodes,
        quantize_linear_nodes: output.quantize_linear_nodes,
        dequantize_linear_nodes: output.dequantize_linear_nodes,
        integer_weight_tensors: output.integer_weight_tensors.into_iter().collect(),
        scale_tensors: output.scale_tensors.into_iter().collect(),
        zero_point_tensors: output.zero_point_tensors.into_iter().collect(),
        intentional_float_boundaries: output.float_boundaries,
    };
    let mut attestation = OnnxInt8Attestation {
        format: ATTESTATION_FORMAT.to_string(),
        source: source.identity,
        output: output.identity,
        toolchain,
        quantization,
        attestation_sha256: String::new(),
    };
    attestation.attestation_sha256 = attestation_identity(&attestation)?;
    Ok(attestation)
}

/// Recomputes and exact-compares the ONNX INT8 attestation in a manifest.
pub fn verify_manifest_onnx_int8_attestation(
    manifest: &LensForgeManifest,
    base_dir: &Path,
) -> Result<()> {
    if manifest.runtime != "onnx-int8" {
        if manifest.onnx_int8_attestation.is_some() {
            return Err(invalid(format!(
                "runtime {} carries an inert onnx_int8_attestation",
                manifest.runtime
            )));
        }
        return Ok(());
    }
    if !manifest.dtype.eq_ignore_ascii_case("int8") {
        return Err(invalid(format!(
            "onnx-int8 manifest declares dtype {}; expected int8",
            manifest.dtype
        )));
    }
    let declared = manifest.onnx_int8_attestation.as_ref().ok_or_else(|| {
        invalid("onnx-int8 manifest is missing its mandatory semantic attestation")
    })?;
    if declared.format != ATTESTATION_FORMAT {
        return Err(invalid(format!(
            "unsupported ONNX INT8 attestation format {}",
            declared.format
        )));
    }
    let source_path = base_dir.join(path_from_attestation(&declared.source.path)?);
    let output_path = base_dir.join(path_from_attestation(&declared.output.path)?);
    let observed = attest_onnx_int8(
        base_dir,
        &source_path,
        &output_path,
        declared.toolchain.clone(),
    )?;
    if &observed != declared {
        return Err(CalyxError::lens_frozen_violation(format!(
            "onnx-int8 semantic attestation drift: declared={} observed={} source={} output={}",
            declared.attestation_sha256,
            observed.attestation_sha256,
            declared.source.path,
            declared.output.path
        )));
    }
    verify_manifest_external_files(manifest, base_dir, &observed)?;
    Ok(())
}

/// Reads a manifest and returns its recomputed, verified ONNX INT8 attestation.
pub fn onnx_int8_attestation_from_manifest_path(
    manifest_path: impl AsRef<Path>,
) -> Result<Option<OnnxInt8Attestation>> {
    let manifest_path = manifest_path.as_ref();
    let bytes = fs::read(manifest_path).map_err(|error| {
        invalid(format!(
            "read ONNX INT8 manifest {} failed: {error}",
            manifest_path.display()
        ))
    })?;
    let manifest: LensForgeManifest = serde_json::from_slice(&bytes).map_err(|error| {
        invalid(format!(
            "parse ONNX INT8 manifest {} failed: {error}",
            manifest_path.display()
        ))
    })?;
    let base = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    verify_manifest_onnx_int8_attestation(&manifest, base)?;
    Ok(manifest.onnx_int8_attestation)
}

fn analyze_graph(base_dir: &Path, graph_path: &Path, scan_extras: bool) -> Result<GraphAnalysis> {
    let bytes = fs::read(graph_path).map_err(|error| {
        invalid(format!(
            "read ONNX graph {} failed: {error}",
            graph_path.display()
        ))
    })?;
    if bytes.is_empty() {
        return Err(invalid(format!(
            "ONNX graph {} is empty",
            graph_path.display()
        )));
    }
    let model = onnx_rs::parse(&bytes).map_err(|error| {
        invalid(format!(
            "parse ONNX protobuf {} failed: {error}",
            graph_path.display()
        ))
    })?;
    if !model.training_info.is_empty() || !model.functions.is_empty() {
        return Err(invalid(format!(
            "ONNX graph {} contains training_info or local functions outside the frozen INT8 attestor contract",
            graph_path.display()
        )));
    }
    let graph = model.graph.as_ref().ok_or_else(|| {
        invalid(format!(
            "ONNX model {} contains no GraphProto",
            graph_path.display()
        ))
    })?;
    if !graph.sparse_initializer.is_empty() {
        return Err(invalid(format!(
            "ONNX graph {} contains sparse initializers outside the frozen INT8 attestor contract",
            graph_path.display()
        )));
    }
    for (index, node) in graph.node.iter().enumerate() {
        if node
            .attribute
            .iter()
            .any(|attribute| attribute.g.is_some() || !attribute.graphs.is_empty())
        {
            return Err(invalid(format!(
                "node {} contains a nested graph outside the frozen INT8 attestor contract",
                node_label(node, index)
            )));
        }
    }

    let external = resolve_external_data(base_dir, graph_path, graph)?;
    if scan_extras {
        reject_unreferenced_external_data(base_dir, graph_path, &external.files)?;
    }
    let initializers = graph
        .initializer
        .iter()
        .map(|tensor| (tensor.name(), tensor))
        .collect::<BTreeMap<_, _>>();
    if initializers.len() != graph.initializer.len() {
        return Err(invalid(format!(
            "ONNX graph {} contains duplicate initializer names",
            graph_path.display()
        )));
    }
    let mut producers = BTreeMap::new();
    let mut consumers = BTreeMap::<&str, Vec<usize>>::new();
    for (index, node) in graph.node.iter().enumerate() {
        for input in &node.input {
            if !input.is_empty() {
                consumers.entry(input).or_default().push(index);
            }
        }
        for output in &node.output {
            if output.is_empty() {
                continue;
            }
            if producers.insert(*output, index).is_some() {
                return Err(invalid(format!(
                    "ONNX graph {} has multiple producers for tensor {output}",
                    graph_path.display()
                )));
            }
        }
    }
    let context = GraphContext {
        graph,
        initializers,
        producers,
        consumers,
        external: external.tensors,
    };
    let mut analysis = empty_analysis(graph_identity(
        base_dir,
        graph_path,
        &bytes,
        &model,
        graph,
        external.files,
    )?);

    for (index, node) in graph.node.iter().enumerate() {
        match node.op_type {
            OpType::DynamicQuantizeLinear => {
                require_standard_domain(node, index)?;
                if node.input.len() != 1 || node.output.len() < 3 {
                    return Err(invalid(format!(
                        "node {} has invalid DynamicQuantizeLinear arity inputs={} outputs={}",
                        node_label(node, index),
                        node.input.len(),
                        node.output.len()
                    )));
                }
                analysis.dynamic_quantize_linear_nodes += 1;
            }
            OpType::QuantizeLinear => {
                require_standard_domain(node, index)?;
                validate_quantize_linear(&context, node, index, &mut analysis)?;
                analysis.quantize_linear_nodes += 1;
            }
            OpType::DequantizeLinear => {
                require_standard_domain(node, index)?;
                validate_dequantize_linear(&context, node, index, &mut analysis)?;
                analysis.dequantize_linear_nodes += 1;
            }
            _ => {}
        }
    }

    for (index, node) in graph.node.iter().enumerate() {
        match node.op_type {
            OpType::MatMulInteger => {
                require_standard_domain(node, index)?;
                validate_integer_compute(&context, node, index, &mut analysis)?;
                analysis.matmul_integer_nodes += 1;
                analysis.qoperator_compute_nodes += 1;
            }
            OpType::ConvInteger => {
                require_standard_domain(node, index)?;
                validate_integer_compute(&context, node, index, &mut analysis)?;
                analysis.conv_integer_nodes += 1;
                analysis.qoperator_compute_nodes += 1;
            }
            OpType::QLinearMatMul => {
                require_standard_domain(node, index)?;
                validate_qlinear_compute(&context, node, index, &mut analysis)?;
                analysis.qlinear_matmul_nodes += 1;
                analysis.qoperator_compute_nodes += 1;
            }
            OpType::QLinearConv => {
                require_standard_domain(node, index)?;
                validate_qlinear_compute(&context, node, index, &mut analysis)?;
                analysis.qlinear_conv_nodes += 1;
                analysis.qoperator_compute_nodes += 1;
            }
            OpType::MatMul | OpType::Gemm | OpType::Conv => {
                classify_float_compute(&context, node, index, &mut analysis)?;
            }
            _ => {}
        }
    }
    analysis.float_boundaries.sort();
    analysis.residual_float_nodes.sort();
    Ok(analysis)
}

fn validate_quantize_linear(
    context: &GraphContext<'_>,
    node: &Node<'_>,
    index: usize,
    analysis: &mut GraphAnalysis,
) -> Result<()> {
    if node.input.len() < 3 || node.output.is_empty() {
        return Err(invalid(format!(
            "node {} must provide input, scale, zero_point, and output",
            node_label(node, index)
        )));
    }
    validate_scale(context, node.input[1], node, index)?;
    analysis.scale_tensors.insert(node.input[1].to_string());
    let dtype = validate_integer_tensor(context, node.input[2], node, index)?;
    analysis
        .zero_point_tensors
        .insert(node.input[2].to_string());
    if !matches!(dtype, DataType::Int8 | DataType::Uint8) {
        return Err(invalid(format!(
            "node {} zero point {} has unsupported type {}",
            node_label(node, index),
            node.input[2],
            dtype_name(dtype)
        )));
    }
    Ok(())
}

fn validate_dequantize_linear(
    context: &GraphContext<'_>,
    node: &Node<'_>,
    index: usize,
    analysis: &mut GraphAnalysis,
) -> Result<()> {
    if node.input.len() < 3 || node.output.is_empty() {
        return Err(invalid(format!(
            "node {} must provide integer input, scale, zero_point, and output",
            node_label(node, index)
        )));
    }
    let value_dtype = validate_quantized_value(context, node.input[0], node, index)?;
    validate_scale(context, node.input[1], node, index)?;
    let zero_dtype = validate_integer_tensor(context, node.input[2], node, index)?;
    if value_dtype != zero_dtype {
        return Err(invalid(format!(
            "node {} integer input {} type {} does not match zero point {} type {}",
            node_label(node, index),
            node.input[0],
            dtype_name(value_dtype),
            node.input[2],
            dtype_name(zero_dtype)
        )));
    }
    analysis.scale_tensors.insert(node.input[1].to_string());
    analysis
        .zero_point_tensors
        .insert(node.input[2].to_string());
    Ok(())
}

fn validate_integer_compute(
    context: &GraphContext<'_>,
    node: &Node<'_>,
    index: usize,
    analysis: &mut GraphAnalysis,
) -> Result<()> {
    if node.input.len() < 2 {
        return Err(invalid(format!(
            "node {} requires activation and weight inputs",
            node_label(node, index)
        )));
    }
    let activation_dtype = validate_quantized_value(context, node.input[0], node, index)?;
    let weight_dtype = validate_quantized_value(context, node.input[1], node, index)?;
    if context.initializers.contains_key(node.input[1]) {
        analysis
            .integer_weight_tensors
            .insert(node.input[1].to_string());
    }
    if let Some(zero) = node.input.get(2).filter(|value| !value.is_empty()) {
        let dtype = validate_quantized_value(context, zero, node, index)?;
        if dtype != activation_dtype {
            return Err(invalid(format!(
                "node {} activation zero point {} type {} != activation type {}",
                node_label(node, index),
                zero,
                dtype_name(dtype),
                dtype_name(activation_dtype)
            )));
        }
        analysis.zero_point_tensors.insert((*zero).to_string());
    }
    if let Some(zero) = node.input.get(3).filter(|value| !value.is_empty()) {
        let dtype = validate_quantized_value(context, zero, node, index)?;
        if dtype != weight_dtype {
            return Err(invalid(format!(
                "node {} weight zero point {} type {} != weight {} type {}",
                node_label(node, index),
                zero,
                dtype_name(dtype),
                node.input[1],
                dtype_name(weight_dtype)
            )));
        }
        analysis.zero_point_tensors.insert((*zero).to_string());
    }
    validate_integer_reconstruction_scales(context, node, index, analysis)?;
    Ok(())
}

fn validate_qlinear_compute(
    context: &GraphContext<'_>,
    node: &Node<'_>,
    index: usize,
    analysis: &mut GraphAnalysis,
) -> Result<()> {
    if node.input.len() < 8 {
        return Err(invalid(format!(
            "node {} requires A/a_scale/a_zero/B/b_scale/b_zero/y_scale/y_zero inputs",
            node_label(node, index)
        )));
    }
    let activation_dtype = validate_quantized_value(context, node.input[0], node, index)?;
    let weight_dtype = validate_integer_tensor(context, node.input[3], node, index)?;
    for scale_index in [1_usize, 4, 6] {
        validate_scale(context, node.input[scale_index], node, index)?;
        analysis
            .scale_tensors
            .insert(node.input[scale_index].to_string());
    }
    for (zero_index, expected) in [(2_usize, activation_dtype), (5, weight_dtype)] {
        let dtype = validate_integer_tensor(context, node.input[zero_index], node, index)?;
        if dtype != expected {
            return Err(invalid(format!(
                "node {} zero point {} type {} != paired tensor type {}",
                node_label(node, index),
                node.input[zero_index],
                dtype_name(dtype),
                dtype_name(expected)
            )));
        }
        analysis
            .zero_point_tensors
            .insert(node.input[zero_index].to_string());
    }
    let output_zero_dtype = validate_integer_tensor(context, node.input[7], node, index)?;
    if !matches!(output_zero_dtype, DataType::Int8 | DataType::Uint8) {
        return Err(invalid(format!(
            "node {} output zero point {} has unsupported type {}",
            node_label(node, index),
            node.input[7],
            dtype_name(output_zero_dtype)
        )));
    }
    analysis
        .zero_point_tensors
        .insert(node.input[7].to_string());
    analysis
        .integer_weight_tensors
        .insert(node.input[3].to_string());
    Ok(())
}

fn classify_float_compute(
    context: &GraphContext<'_>,
    node: &Node<'_>,
    index: usize,
    analysis: &mut GraphAnalysis,
) -> Result<()> {
    let Some(weight_name) = node.input.get(1).filter(|value| !value.is_empty()) else {
        analysis.float_boundaries.push(format!(
            "{}: missing constant weight input",
            node_label(node, index)
        ));
        return Ok(());
    };
    let mut visiting = BTreeSet::new();
    match trace_frozen_weight_origin(context, weight_name, node, index, 0, &mut visiting)? {
        FrozenWeightOrigin::FloatInitializer { tensor, dtype } => {
            analysis.eligible_compute_nodes += 1;
            analysis.residual_float_nodes.push(format!(
                "{} weight={} dtype={}",
                node_label(node, index),
                tensor,
                dtype_name(dtype)
            ));
            Ok(())
        }
        FrozenWeightOrigin::QuantizedInitializer { tensor } => {
            analysis.integer_weight_tensors.insert(tensor);
            analysis.qdq_compute_nodes += 1;
            Ok(())
        }
        FrozenWeightOrigin::UnsupportedInitializer { tensor, dtype } => Err(invalid(format!(
            "node {} consumes constant weight {} with unsupported type {}; quantized regular operators must consume a validated DequantizeLinear output",
            node_label(node, index),
            tensor,
            dtype_name(dtype)
        ))),
        FrozenWeightOrigin::Dynamic => {
            analysis.float_boundaries.push(format!(
                "{}: non-constant/activation-derived weight boundary {}",
                node_label(node, index),
                weight_name
            ));
            Ok(())
        }
    }
}

fn trace_frozen_weight_origin(
    context: &GraphContext<'_>,
    value: &str,
    compute: &Node<'_>,
    compute_index: usize,
    depth: usize,
    visiting: &mut BTreeSet<String>,
) -> Result<FrozenWeightOrigin> {
    if depth > MAX_WEIGHT_ORIGIN_TRACE_DEPTH {
        return Err(invalid(format!(
            "node {} weight {} exceeds the {}-edge provenance bound",
            node_label(compute, compute_index),
            value,
            MAX_WEIGHT_ORIGIN_TRACE_DEPTH
        )));
    }
    if !visiting.insert(value.to_string()) {
        return Err(invalid(format!(
            "node {} weight {} contains a producer cycle",
            node_label(compute, compute_index),
            value
        )));
    }
    if let Some(initializer) = context.initializers.get(value) {
        let origin = if is_float_dtype(initializer.data_type()) {
            FrozenWeightOrigin::FloatInitializer {
                tensor: value.to_string(),
                dtype: initializer.data_type(),
            }
        } else {
            FrozenWeightOrigin::UnsupportedInitializer {
                tensor: value.to_string(),
                dtype: initializer.data_type(),
            }
        };
        visiting.remove(value);
        return Ok(origin);
    }
    let Some(producer_index) = context.producers.get(value).copied() else {
        visiting.remove(value);
        return Ok(FrozenWeightOrigin::Dynamic);
    };
    let producer = &context.graph.node[producer_index];
    let origin = match producer.op_type {
        OpType::DequantizeLinear => {
            require_standard_domain(producer, producer_index)?;
            let quantized_weight = producer
                .input
                .first()
                .copied()
                .filter(|input| !input.is_empty())
                .ok_or_else(|| {
                    invalid(format!(
                        "weight dequantizer {} has no integer input",
                        node_label(producer, producer_index)
                    ))
                })?;
            let mut quantized_visiting = BTreeSet::new();
            let (dtype, initializer) = trace_quantized_origin(
                context,
                quantized_weight,
                producer,
                producer_index,
                0,
                &mut quantized_visiting,
            )?;
            if !matches!(dtype, DataType::Int8 | DataType::Uint8) {
                return Err(invalid(format!(
                    "weight dequantizer {} input {} has type {}, expected int8/uint8",
                    node_label(producer, producer_index),
                    quantized_weight,
                    dtype_name(dtype)
                )));
            }
            let initializer = initializer.ok_or_else(|| {
                invalid(format!(
                    "node {} weight boundary {} dequantizes nonconstant value {}",
                    node_label(compute, compute_index),
                    value,
                    quantized_weight
                ))
            })?;
            let tensor = context
                .initializers
                .get(initializer.as_str())
                .ok_or_else(|| invalid(format!("lost quantized initializer {initializer}")))?;
            if !context.external.contains_key(initializer.as_str()) {
                validate_embedded_payload(tensor, producer, producer_index)?;
            }
            FrozenWeightOrigin::QuantizedInitializer {
                tensor: initializer,
            }
        }
        OpType::Identity
        | OpType::Reshape
        | OpType::Transpose
        | OpType::Flatten
        | OpType::Squeeze
        | OpType::Unsqueeze
        | OpType::Expand
        | OpType::Tile
        | OpType::Pad
        | OpType::Slice
        | OpType::Split
        | OpType::DepthToSpace
        | OpType::SpaceToDepth
        | OpType::ReverseSequence
        | OpType::Gather
        | OpType::GatherElements
        | OpType::GatherND
        | OpType::Compress => {
            require_standard_domain(producer, producer_index)?;
            let data = producer
                .input
                .first()
                .copied()
                .filter(|input| !input.is_empty())
                .ok_or_else(|| {
                    invalid(format!(
                        "weight-preserving node {} has no data input",
                        node_label(producer, producer_index)
                    ))
                })?;
            trace_frozen_weight_origin(context, data, compute, compute_index, depth + 1, visiting)?
        }
        _ => FrozenWeightOrigin::Dynamic,
    };
    visiting.remove(value);
    Ok(origin)
}

fn validate_scale(
    context: &GraphContext<'_>,
    tensor_name: &str,
    node: &Node<'_>,
    index: usize,
) -> Result<()> {
    let tensor = context.initializers.get(tensor_name).ok_or_else(|| {
        invalid(format!(
            "node {} scale {} is not a constant initializer",
            node_label(node, index),
            tensor_name
        ))
    })?;
    if tensor.data_type() != DataType::Float {
        return Err(invalid(format!(
            "node {} scale {} has unsupported type {}; frozen contract requires float32 scales",
            node_label(node, index),
            tensor_name,
            dtype_name(tensor.data_type())
        )));
    }
    let values = if let Some(access) = context.external.get(tensor_name) {
        if access.length > MAX_SCALE_BYTES {
            return Err(invalid(format!(
                "node {} scale {} external slice is {} bytes, over {} byte attestation bound",
                node_label(node, index),
                tensor_name,
                access.length,
                MAX_SCALE_BYTES
            )));
        }
        let raw = read_slice(access)?;
        if !raw.len().is_multiple_of(4) {
            return Err(invalid(format!(
                "node {} scale {} external payload length {} is not float32-aligned",
                node_label(node, index),
                tensor_name,
                raw.len()
            )));
        }
        raw.chunks_exact(4)
            .map(|chunk| f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect::<Vec<_>>()
    } else {
        validate_embedded_payload(tensor, node, index)?;
        tensor
            .as_f32()
            .ok_or_else(|| {
                invalid(format!(
                    "node {} scale {} has no readable float32 payload",
                    node_label(node, index),
                    tensor_name
                ))
            })?
            .into_owned()
    };
    if values.is_empty() {
        return Err(invalid(format!(
            "node {} scale {} is empty",
            node_label(node, index),
            tensor_name
        )));
    }
    for (value_index, value) in values.iter().enumerate() {
        if !value.is_finite() || *value <= 0.0 {
            return Err(invalid(format!(
                "node {} scale {} value[{value_index}]={value} is not finite and positive",
                node_label(node, index),
                tensor_name
            )));
        }
    }
    Ok(())
}

fn validate_integer_tensor(
    context: &GraphContext<'_>,
    tensor_name: &str,
    node: &Node<'_>,
    index: usize,
) -> Result<DataType> {
    let tensor = context.initializers.get(tensor_name).ok_or_else(|| {
        invalid(format!(
            "node {} integer tensor {} is not a constant initializer",
            node_label(node, index),
            tensor_name
        ))
    })?;
    let dtype = tensor.data_type();
    if !matches!(dtype, DataType::Int8 | DataType::Uint8) {
        return Err(invalid(format!(
            "node {} tensor {} has type {}, expected int8/uint8",
            node_label(node, index),
            tensor_name,
            dtype_name(dtype)
        )));
    }
    if !context.external.contains_key(tensor_name) {
        validate_embedded_payload(tensor, node, index)?;
    }
    Ok(dtype)
}

fn validate_quantized_value(
    context: &GraphContext<'_>,
    tensor_name: &str,
    node: &Node<'_>,
    index: usize,
) -> Result<DataType> {
    let mut visiting = BTreeSet::new();
    let (dtype, initializer) =
        trace_quantized_origin(context, tensor_name, node, index, 0, &mut visiting)?;
    if !matches!(dtype, DataType::Int8 | DataType::Uint8) {
        return Err(invalid(format!(
            "node {} quantized value {} has type {}, expected int8/uint8",
            node_label(node, index),
            tensor_name,
            dtype_name(dtype)
        )));
    }
    if let Some(initializer) = initializer
        && let Some(tensor) = context.initializers.get(initializer.as_str())
        && !context.external.contains_key(initializer.as_str())
    {
        validate_embedded_payload(tensor, node, index)?;
    }
    Ok(dtype)
}

fn trace_quantized_origin(
    context: &GraphContext<'_>,
    value: &str,
    consumer: &Node<'_>,
    consumer_index: usize,
    depth: usize,
    visiting: &mut BTreeSet<String>,
) -> Result<(DataType, Option<String>)> {
    if depth > MAX_QUANTIZED_VALUE_TRACE_DEPTH {
        return Err(invalid(format!(
            "node {} quantized value {} exceeds the {}-edge provenance bound",
            node_label(consumer, consumer_index),
            value,
            MAX_QUANTIZED_VALUE_TRACE_DEPTH
        )));
    }
    if !visiting.insert(value.to_string()) {
        return Err(invalid(format!(
            "node {} quantized value {} contains a producer cycle",
            node_label(consumer, consumer_index),
            value
        )));
    }
    if let Some(initializer) = context.initializers.get(value) {
        return Ok((initializer.data_type(), Some(value.to_string())));
    }
    if let Some(dtype) = graph_input_dtype(context, value) {
        return Ok((dtype, None));
    }

    let producer_index = *context.producers.get(value).ok_or_else(|| {
        invalid(format!(
            "node {} quantized value {} has no initializer, typed graph input, or producer",
            node_label(consumer, consumer_index),
            value
        ))
    })?;
    let producer = &context.graph.node[producer_index];
    let output_index = producer
        .output
        .iter()
        .position(|output| *output == value)
        .ok_or_else(|| {
            invalid(format!(
                "producer map for quantized value {} does not match node {}",
                value,
                node_label(producer, producer_index)
            ))
        })?;
    match producer.op_type {
        OpType::DynamicQuantizeLinear => {
            require_standard_domain(producer, producer_index)?;
            match output_index {
                0 | 2 => Ok((DataType::Uint8, None)),
                _ => Err(invalid(format!(
                    "node {} quantized value {} resolves to non-integer DynamicQuantizeLinear output {}",
                    node_label(consumer, consumer_index),
                    value,
                    output_index
                ))),
            }
        }
        OpType::QuantizeLinear => {
            require_standard_domain(producer, producer_index)?;
            if output_index != 0 {
                return Err(invalid(format!(
                    "node {} quantized value {} resolves to unexpected QuantizeLinear output {}",
                    node_label(consumer, consumer_index),
                    value,
                    output_index
                )));
            }
            let zero_point = producer.input.get(2).copied().ok_or_else(|| {
                invalid(format!(
                    "node {} has no frozen zero-point input",
                    node_label(producer, producer_index)
                ))
            })?;
            let zero_point = context.initializers.get(zero_point).ok_or_else(|| {
                invalid(format!(
                    "node {} zero point {} is not a constant initializer",
                    node_label(producer, producer_index),
                    zero_point
                ))
            })?;
            Ok((zero_point.data_type(), None))
        }
        OpType::QLinearMatMul | OpType::QLinearConv => {
            require_standard_domain(producer, producer_index)?;
            if output_index != 0 {
                return Err(invalid(format!(
                    "node {} quantized value {} resolves to unexpected {} output {}",
                    node_label(consumer, consumer_index),
                    value,
                    producer.op_type.as_str(),
                    output_index
                )));
            }
            let zero_point = producer.input.get(7).copied().ok_or_else(|| {
                invalid(format!(
                    "node {} has no frozen output zero-point input",
                    node_label(producer, producer_index)
                ))
            })?;
            let zero_point = context.initializers.get(zero_point).ok_or_else(|| {
                invalid(format!(
                    "node {} output zero point {} is not a constant initializer",
                    node_label(producer, producer_index),
                    zero_point
                ))
            })?;
            Ok((zero_point.data_type(), None))
        }
        OpType::Identity
        | OpType::Reshape
        | OpType::Transpose
        | OpType::Flatten
        | OpType::Squeeze
        | OpType::Unsqueeze
        | OpType::Expand
        | OpType::Tile
        | OpType::Pad
        | OpType::Slice
        | OpType::Split
        | OpType::DepthToSpace
        | OpType::SpaceToDepth
        | OpType::ReverseSequence
        | OpType::Gather
        | OpType::GatherElements
        | OpType::GatherND
        | OpType::Compress => {
            require_standard_domain(producer, producer_index)?;
            let data = producer
                .input
                .first()
                .copied()
                .filter(|input| !input.is_empty())
                .ok_or_else(|| {
                    invalid(format!(
                        "type-preserving node {} has no data input",
                        node_label(producer, producer_index)
                    ))
                })?;
            trace_quantized_origin(context, data, consumer, consumer_index, depth + 1, visiting)
        }
        _ => Err(invalid(format!(
            "node {} quantized value {} is produced by non-attested operator {} at {}",
            node_label(consumer, consumer_index),
            value,
            producer.op_type.as_str(),
            node_label(producer, producer_index)
        ))),
    }
}

fn graph_input_dtype(context: &GraphContext<'_>, value: &str) -> Option<DataType> {
    context
        .graph
        .input
        .iter()
        .find(|input| input.name == value)
        .and_then(|input| input.r#type.as_ref())
        .and_then(|r#type| r#type.value.as_ref())
        .and_then(|value| match value {
            TypeValue::Tensor(tensor) => Some(tensor.elem_type),
            _ => None,
        })
}

fn validate_integer_reconstruction_scales(
    context: &GraphContext<'_>,
    node: &Node<'_>,
    index: usize,
    analysis: &mut GraphAnalysis,
) -> Result<()> {
    let output = node
        .output
        .first()
        .copied()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            invalid(format!(
                "node {} has no integer accumulation output",
                node_label(node, index)
            ))
        })?;
    let mut frontier = vec![(output, 0_usize)];
    let mut visited = BTreeSet::new();
    let mut scales = BTreeSet::new();
    while let Some((value, depth)) = frontier.pop() {
        if depth > 4 || !visited.insert(value) {
            continue;
        }
        let Some(consumers) = context.consumers.get(value) else {
            continue;
        };
        for consumer_index in consumers {
            let consumer = &context.graph.node[*consumer_index];
            match consumer.op_type {
                OpType::Cast if consumer.input.first().copied() == Some(value) => {
                    for next in &consumer.output {
                        if !next.is_empty() {
                            frontier.push((next, depth + 1));
                        }
                    }
                }
                OpType::Mul => {
                    let others = consumer
                        .input
                        .iter()
                        .copied()
                        .filter(|input| *input != value && !input.is_empty())
                        .collect::<Vec<_>>();
                    if others.len() != 1 {
                        continue;
                    }
                    let scale = others[0];
                    let mut scale_expression = BTreeSet::new();
                    collect_reconstruction_scales(
                        context,
                        scale,
                        consumer,
                        *consumer_index,
                        0,
                        &mut scale_expression,
                        &mut scales,
                    )?;
                    for next in &consumer.output {
                        if !next.is_empty() {
                            frontier.push((next, depth + 1));
                        }
                    }
                }
                _ => {}
            }
        }
    }
    if scales.len() < 2 {
        return Err(invalid(format!(
            "node {} integer accumulation {} has only {} validated reconstruction scale(s) {:?}; expected one per quantized operand",
            node_label(node, index),
            output,
            scales.len(),
            scales
        )));
    }
    analysis.scale_tensors.extend(scales);
    Ok(())
}

fn collect_reconstruction_scales(
    context: &GraphContext<'_>,
    value: &str,
    consumer: &Node<'_>,
    consumer_index: usize,
    depth: usize,
    visiting: &mut BTreeSet<String>,
    scales: &mut BTreeSet<String>,
) -> Result<()> {
    if depth > MAX_SCALE_EXPRESSION_DEPTH {
        return Err(invalid(format!(
            "node {} reconstruction scale {} exceeds the {}-edge expression bound",
            node_label(consumer, consumer_index),
            value,
            MAX_SCALE_EXPRESSION_DEPTH
        )));
    }
    if !visiting.insert(value.to_string()) {
        return Err(invalid(format!(
            "node {} reconstruction scale {} contains a producer cycle",
            node_label(consumer, consumer_index),
            value
        )));
    }
    if context.initializers.contains_key(value) {
        validate_scale(context, value, consumer, consumer_index)?;
        scales.insert(value.to_string());
        visiting.remove(value);
        return Ok(());
    }
    if is_dynamic_scale_output(context, value) {
        scales.insert(value.to_string());
        visiting.remove(value);
        return Ok(());
    }

    let producer_index = *context.producers.get(value).ok_or_else(|| {
        invalid(format!(
            "node {} reconstruction scale {} has no validated initializer or producer",
            node_label(consumer, consumer_index),
            value
        ))
    })?;
    let producer = &context.graph.node[producer_index];
    require_standard_domain(producer, producer_index)?;
    match producer.op_type {
        OpType::Mul => {
            let inputs = producer
                .input
                .iter()
                .copied()
                .filter(|input| !input.is_empty())
                .collect::<Vec<_>>();
            if inputs.len() != 2 {
                return Err(invalid(format!(
                    "scale-composition node {} has {} nonblank inputs; expected exactly 2",
                    node_label(producer, producer_index),
                    inputs.len()
                )));
            }
            for input in inputs {
                collect_reconstruction_scales(
                    context,
                    input,
                    consumer,
                    consumer_index,
                    depth + 1,
                    visiting,
                    scales,
                )?;
            }
            visiting.remove(value);
            Ok(())
        }
        OpType::Identity
        | OpType::Reshape
        | OpType::Squeeze
        | OpType::Unsqueeze
        | OpType::Expand => {
            let input = producer
                .input
                .first()
                .copied()
                .filter(|input| !input.is_empty())
                .ok_or_else(|| {
                    invalid(format!(
                        "scale-preserving node {} has no data input",
                        node_label(producer, producer_index)
                    ))
                })?;
            let result = collect_reconstruction_scales(
                context,
                input,
                consumer,
                consumer_index,
                depth + 1,
                visiting,
                scales,
            );
            visiting.remove(value);
            result
        }
        _ => Err(invalid(format!(
            "node {} reconstruction scale {} is produced by non-attested operator {} at {}",
            node_label(consumer, consumer_index),
            value,
            producer.op_type.as_str(),
            node_label(producer, producer_index)
        ))),
    }
}

fn is_dynamic_scale_output(context: &GraphContext<'_>, value: &str) -> bool {
    let Some(producer_index) = context.producers.get(value) else {
        return false;
    };
    let producer = &context.graph.node[*producer_index];
    producer.op_type == OpType::DynamicQuantizeLinear
        && producer.output.get(1).copied() == Some(value)
}

fn validate_embedded_payload(
    tensor: &TensorProto<'_>,
    node: &Node<'_>,
    index: usize,
) -> Result<()> {
    let expected = tensor_byte_len(tensor)?;
    if let Some(raw) = tensor.as_raw() {
        if raw.len() as u64 != expected {
            return Err(invalid(format!(
                "node {} tensor {} raw payload is {} bytes, expected {} from dtype/shape",
                node_label(node, index),
                tensor.name(),
                raw.len(),
                expected
            )));
        }
        return Ok(());
    }
    match tensor.data_type() {
        DataType::Int8 | DataType::Uint8 => {
            let values = tensor.as_i32().ok_or_else(|| {
                invalid(format!(
                    "node {} tensor {} type {} has neither raw/external bytes nor TensorProto int32_data",
                    node_label(node, index),
                    tensor.name(),
                    dtype_name(tensor.data_type())
                ))
            })?;
            if values.len() as u64 != expected {
                return Err(invalid(format!(
                    "node {} tensor {} typed payload has {} elements, expected {} from shape {:?}",
                    node_label(node, index),
                    tensor.name(),
                    values.len(),
                    expected,
                    tensor.dims()
                )));
            }
            let is_int8 = tensor.data_type() == DataType::Int8;
            let valid = values.iter().all(|value| {
                if is_int8 {
                    i8::try_from(*value).is_ok()
                } else {
                    u8::try_from(*value).is_ok()
                }
            });
            if !valid {
                let invalid_value = values
                    .iter()
                    .find(|value| {
                        if is_int8 {
                            i8::try_from(**value).is_err()
                        } else {
                            u8::try_from(**value).is_err()
                        }
                    })
                    .copied()
                    .unwrap_or_default();
                return Err(invalid(format!(
                    "node {} tensor {} typed payload value {} is outside {} range",
                    node_label(node, index),
                    tensor.name(),
                    invalid_value,
                    dtype_name(tensor.data_type())
                )));
            }
            return Ok(());
        }
        DataType::Float => {
            let count = tensor.as_f32().map_or(0, |values| values.len() as u64);
            if count.checked_mul(4) == Some(expected) {
                return Ok(());
            }
        }
        DataType::Double => {
            let count = tensor.as_f64().map_or(0, |values| values.len() as u64);
            if count.checked_mul(8) == Some(expected) {
                return Ok(());
            }
        }
        _ => {}
    }
    Err(invalid(format!(
        "node {} tensor {} type {} has no exact raw/external payload for semantic attestation",
        node_label(node, index),
        tensor.name(),
        dtype_name(tensor.data_type())
    )))
}

fn resolve_external_data(
    base_dir: &Path,
    graph_path: &Path,
    graph: &Graph<'_>,
) -> Result<ExternalResolution> {
    let graph_dir = graph_path.parent().unwrap_or_else(|| Path::new("."));
    let graph_dir_canonical = fs::canonicalize(graph_dir).map_err(|error| {
        invalid(format!(
            "canonicalize ONNX graph directory {} failed: {error}",
            graph_dir.display()
        ))
    })?;
    let mut file_records: BTreeMap<String, OnnxExternalDataFile> = BTreeMap::new();
    let mut accesses = BTreeMap::new();
    let mut canonical_by_location = BTreeMap::new();
    for tensor in &graph.initializer {
        let entries = tensor.external_data();
        if tensor.data_location() != DataLocation::External && entries.is_empty() {
            continue;
        }
        if tensor.data_location() != DataLocation::External || entries.is_empty() {
            return Err(invalid(format!(
                "tensor {} has inconsistent data_location/external_data metadata",
                tensor.name()
            )));
        }
        if tensor.as_raw().is_some() {
            return Err(invalid(format!(
                "external tensor {} also carries embedded raw_data",
                tensor.name()
            )));
        }
        let mut values = BTreeMap::new();
        for entry in entries {
            if !matches!(entry.key, "location" | "offset" | "length" | "checksum") {
                return Err(invalid(format!(
                    "tensor {} external_data contains unsupported key {}",
                    tensor.name(),
                    entry.key
                )));
            }
            if values.insert(entry.key, entry.value).is_some() {
                return Err(invalid(format!(
                    "tensor {} external_data repeats key {}",
                    tensor.name(),
                    entry.key
                )));
            }
        }
        let location = values.get("location").copied().ok_or_else(|| {
            invalid(format!(
                "tensor {} external_data is missing location",
                tensor.name()
            ))
        })?;
        let relative = path_from_attestation(location)?;
        let requested = graph_dir.join(&relative);
        let metadata = fs::symlink_metadata(&requested).map_err(|error| {
            invalid(format!(
                "tensor {} external data {} is missing or unreadable: {error}",
                tensor.name(),
                requested.display()
            ))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(invalid(format!(
                "tensor {} external data {} must be a regular non-symlink file",
                tensor.name(),
                requested.display()
            )));
        }
        let canonical = fs::canonicalize(&requested).map_err(|error| {
            invalid(format!(
                "canonicalize tensor {} external data {} failed: {error}",
                tensor.name(),
                requested.display()
            ))
        })?;
        if !canonical.starts_with(&graph_dir_canonical) {
            return Err(invalid(format!(
                "tensor {} external data {} escapes graph directory {}",
                tensor.name(),
                canonical.display(),
                graph_dir_canonical.display()
            )));
        }
        let file_bytes = metadata.len();
        let offset = parse_external_u64(tensor.name(), "offset", values.get("offset").copied(), 0)?;
        let expected = tensor_byte_len(tensor)?;
        let length = parse_external_u64(
            tensor.name(),
            "length",
            values.get("length").copied(),
            file_bytes.checked_sub(offset).ok_or_else(|| {
                invalid(format!(
                    "tensor {} external offset {} exceeds file length {}",
                    tensor.name(),
                    offset,
                    file_bytes
                ))
            })?,
        )?;
        let end = offset.checked_add(length).ok_or_else(|| {
            invalid(format!(
                "tensor {} external offset+length overflow",
                tensor.name()
            ))
        })?;
        if end > file_bytes {
            return Err(invalid(format!(
                "tensor {} external slice offset={} length={} exceeds {} bytes in {}",
                tensor.name(),
                offset,
                length,
                file_bytes,
                requested.display()
            )));
        }
        if length != expected {
            return Err(invalid(format!(
                "tensor {} external slice length {} != {} bytes required by dtype {} and dims {:?}",
                tensor.name(),
                length,
                expected,
                dtype_name(tensor.data_type()),
                tensor.dims()
            )));
        }
        let declared_sha1 = values
            .get("checksum")
            .map(|value| value.to_ascii_lowercase());
        if let Some(checksum) = &declared_sha1 {
            if checksum.len() != 40 || !checksum.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(invalid(format!(
                    "tensor {} external checksum {} is not a 40-character SHA-1 digest",
                    tensor.name(),
                    checksum
                )));
            }
            let observed = hash_slice::<Sha1>(&canonical, offset, length)?;
            if !observed.eq_ignore_ascii_case(checksum) {
                return Err(invalid(format!(
                    "tensor {} external checksum mismatch for {}: declared={} observed={}",
                    tensor.name(),
                    requested.display(),
                    checksum,
                    observed
                )));
            }
        }
        let relative_to_base = relative_path_string(base_dir, &canonical)?;
        canonical_by_location.insert(relative_to_base.clone(), canonical.clone());
        accesses.insert(
            tensor.name().to_string(),
            ExternalAccess {
                path: canonical.clone(),
                offset,
                length,
            },
        );
        let record = file_records
            .entry(relative_to_base.clone())
            .or_insert_with(|| OnnxExternalDataFile {
                path: relative_to_base,
                bytes: file_bytes,
                sha256: String::new(),
                slices: Vec::new(),
            });
        record.slices.push(OnnxExternalTensorSlice {
            tensor: tensor.name().to_string(),
            offset,
            length,
            declared_sha1,
        });
    }
    for (location, record) in &mut file_records {
        let canonical = canonical_by_location
            .get(location)
            .ok_or_else(|| invalid(format!("lost canonical external-data path for {location}")))?;
        let (bytes, sha256) = hash_file::<Sha256>(canonical)?;
        if bytes != record.bytes {
            return Err(invalid(format!(
                "external data {} changed length during attestation: {} -> {}",
                canonical.display(),
                record.bytes,
                bytes
            )));
        }
        record.sha256 = sha256;
        record
            .slices
            .sort_by_key(|slice| (slice.offset, slice.length, slice.tensor.clone()));
        for pair in record.slices.windows(2) {
            let left_end = pair[0]
                .offset
                .checked_add(pair[0].length)
                .ok_or_else(|| invalid("external tensor range overflow"))?;
            if left_end > pair[1].offset {
                return Err(invalid(format!(
                    "external data {} has overlapping tensor slices {} and {}",
                    canonical.display(),
                    pair[0].tensor,
                    pair[1].tensor
                )));
            }
        }
    }
    Ok(ExternalResolution {
        files: file_records.into_values().collect(),
        tensors: accesses,
    })
}

fn graph_identity(
    base_dir: &Path,
    graph_path: &Path,
    bytes: &[u8],
    model: &onnx_rs::Model<'_>,
    graph: &Graph<'_>,
    external_data: Vec<OnnxExternalDataFile>,
) -> Result<OnnxGraphIdentity> {
    let mut operators = BTreeMap::<String, u64>::new();
    for node in &graph.node {
        *operators
            .entry(node.op_type.as_str().to_string())
            .or_default() += 1;
    }
    let mut initializer_dtypes = BTreeMap::<String, u64>::new();
    for tensor in &graph.initializer {
        *initializer_dtypes
            .entry(dtype_name(tensor.data_type()).to_string())
            .or_default() += 1;
    }
    let mut opsets = model
        .opset_import
        .iter()
        .map(|opset| format!("{}:{}", opset.domain, opset.version))
        .collect::<Vec<_>>();
    opsets.sort();
    Ok(OnnxGraphIdentity {
        path: relative_path_string(base_dir, graph_path)?,
        bytes: bytes.len() as u64,
        sha256: format!("{:x}", Sha256::digest(bytes)),
        ir_version: model.ir_version,
        producer_name: model.producer_name.to_string(),
        producer_version: model.producer_version.to_string(),
        opsets,
        operators: inventory(operators),
        initializer_dtypes: inventory(initializer_dtypes),
        inputs: boundaries(&graph.input),
        outputs: boundaries(&graph.output),
        external_data,
    })
}

fn boundaries(values: &[onnx_rs::ast::ValueInfo<'_>]) -> Vec<OnnxTensorBoundary> {
    let mut out = values
        .iter()
        .map(|value| {
            let (elem_type, shape) = value
                .r#type
                .as_ref()
                .and_then(|r#type| r#type.value.as_ref())
                .and_then(|value| match value {
                    TypeValue::Tensor(tensor) => Some((
                        dtype_name(tensor.elem_type).to_string(),
                        tensor
                            .shape
                            .as_ref()
                            .map(|shape| {
                                shape
                                    .dim
                                    .iter()
                                    .map(|dim| format!("{:?}", dim.value))
                                    .collect::<Vec<_>>()
                            })
                            .unwrap_or_default(),
                    )),
                    _ => None,
                })
                .unwrap_or_else(|| ("unknown_or_non_tensor".to_string(), Vec::new()));
            OnnxTensorBoundary {
                name: value.name.to_string(),
                elem_type,
                shape,
            }
        })
        .collect::<Vec<_>>();
    out.sort_by(|left, right| left.name.cmp(&right.name));
    out
}

fn empty_analysis(identity: OnnxGraphIdentity) -> GraphAnalysis {
    GraphAnalysis {
        identity,
        eligible_compute_nodes: 0,
        qoperator_compute_nodes: 0,
        qdq_compute_nodes: 0,
        matmul_integer_nodes: 0,
        conv_integer_nodes: 0,
        qlinear_matmul_nodes: 0,
        qlinear_conv_nodes: 0,
        dynamic_quantize_linear_nodes: 0,
        quantize_linear_nodes: 0,
        dequantize_linear_nodes: 0,
        integer_weight_tensors: BTreeSet::new(),
        scale_tensors: BTreeSet::new(),
        zero_point_tensors: BTreeSet::new(),
        float_boundaries: Vec::new(),
        residual_float_nodes: Vec::new(),
    }
}

fn verify_manifest_external_files(
    manifest: &LensForgeManifest,
    base_dir: &Path,
    attestation: &OnnxInt8Attestation,
) -> Result<()> {
    let model = manifest
        .files
        .iter()
        .find(|file| file.role == "model")
        .ok_or_else(|| invalid("onnx-int8 manifest has no model artifact"))?;
    let model_canonical = canonical_manifest_file(base_dir, model)?;
    let output_canonical =
        fs::canonicalize(base_dir.join(path_from_attestation(&attestation.output.path)?))
            .map_err(|error| invalid(format!("canonicalize attested output failed: {error}")))?;
    if model_canonical != output_canonical {
        return Err(invalid(format!(
            "manifest model {} does not match attested quantizer output {}",
            model.path.display(),
            attestation.output.path
        )));
    }
    if model.bytes != attestation.output.bytes
        || !model
            .sha256
            .eq_ignore_ascii_case(&attestation.output.sha256)
    {
        return Err(invalid(format!(
            "manifest model {} identity bytes={} sha256={} != attested bytes={} sha256={}",
            model.path.display(),
            model.bytes,
            model.sha256,
            attestation.output.bytes,
            attestation.output.sha256
        )));
    }
    let expected = attestation
        .output
        .external_data
        .iter()
        .map(|file| file.path.as_str())
        .collect::<BTreeSet<_>>();
    let declared = manifest
        .files
        .iter()
        .filter(|file| file.role.starts_with("model_external_data:"))
        .collect::<Vec<_>>();
    if declared.len() != expected.len() {
        return Err(invalid(format!(
            "manifest declares {} model external-data artifacts but graph attests {}",
            declared.len(),
            expected.len()
        )));
    }
    for external in &attestation.output.external_data {
        let external_canonical = fs::canonicalize(
            base_dir.join(path_from_attestation(&external.path)?),
        )
        .map_err(|error| {
            invalid(format!(
                "canonicalize attested external data {} failed: {error}",
                external.path
            ))
        })?;
        let file = declared
            .iter()
            .find(|file| {
                canonical_manifest_file(base_dir, file).is_ok_and(|path| path == external_canonical)
            })
            .ok_or_else(|| {
                invalid(format!(
                    "attested external data {} is not a manifest artifact",
                    external.path
                ))
            })?;
        if file.bytes != external.bytes || !file.sha256.eq_ignore_ascii_case(&external.sha256) {
            return Err(invalid(format!(
                "manifest external data {} identity bytes={} sha256={} != attested bytes={} sha256={}",
                file.path.display(),
                file.bytes,
                file.sha256,
                external.bytes,
                external.sha256
            )));
        }
    }
    for file in declared {
        let relative = relative_path_string(base_dir, &canonical_manifest_file(base_dir, file)?)?;
        if !expected.contains(relative.as_str()) {
            return Err(invalid(format!(
                "manifest carries unreferenced model external-data artifact {}",
                file.path.display()
            )));
        }
    }
    Ok(())
}

fn reject_unreferenced_external_data(
    base_dir: &Path,
    graph_path: &Path,
    referenced: &[OnnxExternalDataFile],
) -> Result<()> {
    let graph_canonical = fs::canonicalize(graph_path).map_err(|error| {
        invalid(format!(
            "canonicalize quantized graph {} failed: {error}",
            graph_path.display()
        ))
    })?;
    let graph_dir = graph_path.parent().unwrap_or_else(|| Path::new("."));
    let referenced = referenced
        .iter()
        .map(|file| fs::canonicalize(base_dir.join(file.path.replace('/', "\\"))))
        .collect::<std::result::Result<BTreeSet<_>, _>>()
        .map_err(|error| invalid(format!("canonicalize external data failed: {error}")))?;
    for path in regular_files_recursive(graph_dir)? {
        let canonical = fs::canonicalize(&path)
            .map_err(|error| invalid(format!("canonicalize {} failed: {error}", path.display())))?;
        if canonical == graph_canonical || referenced.contains(&canonical) {
            continue;
        }
        let lower_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        let lower_extension = path
            .extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if lower_extension == "onnx"
            || lower_extension == "data"
            || lower_extension == "bin"
            || lower_name.ends_with(".onnx_data")
        {
            return Err(invalid(format!(
                "quantized graph directory contains unreferenced data artifact {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn regular_files_recursive(root: &Path) -> Result<Vec<PathBuf>> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).map_err(|error| {
            invalid(format!(
                "enumerate quantized graph directory {} failed: {error}",
                directory.display()
            ))
        })? {
            let entry =
                entry.map_err(|error| invalid(format!("read directory entry failed: {error}")))?;
            let path = entry.path();
            let kind = entry.file_type().map_err(|error| {
                invalid(format!("read file type {} failed: {error}", path.display()))
            })?;
            if kind.is_symlink() {
                return Err(invalid(format!(
                    "quantized graph directory contains unsupported symlink/reparse entry {}",
                    path.display()
                )));
            }
            if kind.is_dir() {
                pending.push(path);
            } else if kind.is_file() {
                files.push(path);
            }
        }
    }
    files.sort();
    Ok(files)
}

fn validate_toolchain(toolchain: &OnnxInt8Toolchain) -> Result<()> {
    for (name, value) in [
        ("converter", toolchain.converter.as_str()),
        ("converter_version", toolchain.converter_version.as_str()),
        (
            "optimum_onnx_version",
            toolchain.optimum_onnx_version.as_str(),
        ),
        (
            "converter_executable_sha256",
            toolchain.converter_executable_sha256.as_str(),
        ),
        ("python_version", toolchain.python_version.as_str()),
        (
            "python_executable_sha256",
            toolchain.python_executable_sha256.as_str(),
        ),
        ("onnx_version", toolchain.onnx_version.as_str()),
        (
            "onnxruntime_version",
            toolchain.onnxruntime_version.as_str(),
        ),
        ("quant_target", toolchain.quant_target.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(invalid(format!("ONNX INT8 toolchain {name} is blank")));
        }
    }
    for (name, hash) in [
        (
            "converter_executable_sha256",
            toolchain.converter_executable_sha256.trim(),
        ),
        (
            "python_executable_sha256",
            toolchain.python_executable_sha256.trim(),
        ),
    ] {
        if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(invalid(format!(
                "{name} {hash} is not a 64-character SHA-256 digest"
            )));
        }
    }
    if toolchain.frozen_options.is_empty()
        || toolchain
            .frozen_options
            .iter()
            .any(|(key, value)| key.trim().is_empty() || value.trim().is_empty())
    {
        return Err(invalid(
            "ONNX INT8 toolchain frozen_options must contain nonblank option/value pairs",
        ));
    }
    if toolchain.converter != "optimum-cli" {
        return Err(invalid(format!(
            "ONNX INT8 converter {} is unsupported; expected optimum-cli",
            toolchain.converter
        )));
    }
    if !matches!(
        toolchain.quant_target.as_str(),
        "arm64" | "avx2" | "avx512" | "avx512_vnni" | "tensorrt"
    ) {
        return Err(invalid(format!(
            "ONNX INT8 quant_target {} is unsupported",
            toolchain.quant_target
        )));
    }
    for (key, expected) in [
        ("command", "optimum-cli onnxruntime quantize"),
        ("export_task", "feature-extraction"),
        ("export_library", "transformers"),
        ("quantizer_output", "onnx-int8/model_quantized.onnx"),
        ("source_graph", "onnx-export/model.onnx"),
    ] {
        if toolchain.frozen_options.get(key).map(String::as_str) != Some(expected) {
            return Err(invalid(format!(
                "ONNX INT8 frozen option {key} is {:?}; expected {expected:?}",
                toolchain.frozen_options.get(key)
            )));
        }
    }
    Ok(())
}

fn require_standard_domain(node: &Node<'_>, index: usize) -> Result<()> {
    if node.domain.is_empty() || node.domain == "ai.onnx" {
        return Ok(());
    }
    Err(invalid(format!(
        "node {} uses quantized operator domain {}; only the standard ONNX domain is attested",
        node_label(node, index),
        node.domain
    )))
}

fn canonical_file_within(base_dir: &Path, path: &Path, role: &str) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        invalid(format!(
            "{role} {} is missing or unreadable: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(invalid(format!(
            "{role} {} must be a regular non-symlink file",
            path.display()
        )));
    }
    let base = fs::canonicalize(base_dir).map_err(|error| {
        invalid(format!(
            "canonicalize attestation base {} failed: {error}",
            base_dir.display()
        ))
    })?;
    let canonical = fs::canonicalize(path).map_err(|error| {
        invalid(format!(
            "canonicalize {role} {} failed: {error}",
            path.display()
        ))
    })?;
    if !canonical.starts_with(&base) {
        return Err(invalid(format!(
            "{role} {} escapes attestation base {}",
            canonical.display(),
            base.display()
        )));
    }
    Ok(canonical)
}

fn canonical_manifest_file(base_dir: &Path, file: &LensForgeFile) -> Result<PathBuf> {
    let relative = path_from_attestation(&file.path.to_string_lossy())?;
    canonical_file_within(
        base_dir,
        &base_dir.join(relative),
        &format!("manifest role {}", file.role),
    )
}

fn relative_path_string(base_dir: &Path, path: &Path) -> Result<String> {
    let base = fs::canonicalize(base_dir).map_err(|error| {
        invalid(format!(
            "canonicalize attestation base {} failed: {error}",
            base_dir.display()
        ))
    })?;
    let canonical = fs::canonicalize(path)
        .map_err(|error| invalid(format!("canonicalize {} failed: {error}", path.display())))?;
    let relative = canonical.strip_prefix(&base).map_err(|_| {
        invalid(format!(
            "path {} escapes attestation base {}",
            canonical.display(),
            base.display()
        ))
    })?;
    if relative.as_os_str().is_empty() {
        return Err(invalid("attested path cannot equal its base directory"));
    }
    Ok(relative.to_string_lossy().replace('\\', "/"))
}

fn path_from_attestation(raw: &str) -> Result<PathBuf> {
    if raw.trim().is_empty() || raw.contains('\0') {
        return Err(invalid(format!("invalid blank/NUL path {raw:?}")));
    }
    let path = Path::new(raw);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(invalid(format!(
            "attested path {raw:?} must be a relative normal-component path without traversal"
        )));
    }
    Ok(path.to_path_buf())
}

fn tensor_byte_len(tensor: &TensorProto<'_>) -> Result<u64> {
    let elements = tensor.dims().iter().try_fold(1_u64, |acc, dim| {
        let dim = u64::try_from(*dim).map_err(|_| {
            invalid(format!(
                "tensor {} has negative dimension {dim}",
                tensor.name()
            ))
        })?;
        acc.checked_mul(dim).ok_or_else(|| {
            invalid(format!(
                "tensor {} element count overflows u64",
                tensor.name()
            ))
        })
    })?;
    let width = dtype_width(tensor.data_type()).ok_or_else(|| {
        invalid(format!(
            "tensor {} uses unsupported byte width type {}",
            tensor.name(),
            dtype_name(tensor.data_type())
        ))
    })?;
    elements.checked_mul(width).ok_or_else(|| {
        invalid(format!(
            "tensor {} byte length overflows u64",
            tensor.name()
        ))
    })
}

fn dtype_width(dtype: DataType) -> Option<u64> {
    match dtype {
        DataType::Bool | DataType::Int8 | DataType::Uint8 => Some(1),
        DataType::Int16 | DataType::Uint16 | DataType::Float16 | DataType::Bfloat16 => Some(2),
        DataType::Float | DataType::Int32 | DataType::Uint32 => Some(4),
        DataType::Double | DataType::Int64 | DataType::Uint64 => Some(8),
        _ => None,
    }
}

fn dtype_name(dtype: DataType) -> &'static str {
    match dtype {
        DataType::Undefined => "undefined",
        DataType::Float => "float32",
        DataType::Uint8 => "uint8",
        DataType::Int8 => "int8",
        DataType::Uint16 => "uint16",
        DataType::Int16 => "int16",
        DataType::Int32 => "int32",
        DataType::Int64 => "int64",
        DataType::String => "string",
        DataType::Bool => "bool",
        DataType::Float16 => "float16",
        DataType::Double => "float64",
        DataType::Uint32 => "uint32",
        DataType::Uint64 => "uint64",
        DataType::Complex64 => "complex64",
        DataType::Complex128 => "complex128",
        DataType::Bfloat16 => "bfloat16",
        DataType::Float8e4m3fn => "float8e4m3fn",
        DataType::Float8e4m3fnuz => "float8e4m3fnuz",
        DataType::Float8e5m2 => "float8e5m2",
        DataType::Float8e5m2fnuz => "float8e5m2fnuz",
        DataType::Uint4 => "uint4",
        DataType::Int4 => "int4",
        DataType::Float4e2m1 => "float4e2m1",
    }
}

fn is_float_dtype(dtype: DataType) -> bool {
    matches!(
        dtype,
        DataType::Float | DataType::Float16 | DataType::Double | DataType::Bfloat16
    )
}

fn parse_external_u64(tensor: &str, key: &str, raw: Option<&str>, default: u64) -> Result<u64> {
    let Some(raw) = raw else {
        return Ok(default);
    };
    if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid(format!(
            "tensor {tensor} external {key} {raw:?} is not an unsigned decimal integer"
        )));
    }
    raw.parse::<u64>().map_err(|error| {
        invalid(format!(
            "tensor {tensor} external {key} {raw:?} is invalid: {error}"
        ))
    })
}

fn read_slice(access: &ExternalAccess) -> Result<Vec<u8>> {
    let length = usize::try_from(access.length).map_err(|_| {
        invalid(format!(
            "external slice {} length {} exceeds addressable memory",
            access.path.display(),
            access.length
        ))
    })?;
    let mut file = File::open(&access.path).map_err(|error| {
        invalid(format!(
            "open external data {} failed: {error}",
            access.path.display()
        ))
    })?;
    file.seek(SeekFrom::Start(access.offset)).map_err(|error| {
        invalid(format!(
            "seek external data {} to {} failed: {error}",
            access.path.display(),
            access.offset
        ))
    })?;
    let mut bytes = vec![0_u8; length];
    file.read_exact(&mut bytes).map_err(|error| {
        invalid(format!(
            "read external data {} offset={} length={} failed: {error}",
            access.path.display(),
            access.offset,
            access.length
        ))
    })?;
    Ok(bytes)
}

fn hash_file<D>(path: &Path) -> Result<(u64, String)>
where
    D: Digest + Default,
{
    let file = File::open(path).map_err(|error| {
        invalid(format!(
            "open {} for hashing failed: {error}",
            path.display()
        ))
    })?;
    let mut reader = BufReader::new(file);
    let mut digest = D::default();
    let mut buffer = vec![0_u8; HASH_BUFFER_BYTES];
    let mut bytes = 0_u64;
    loop {
        let read = reader.read(&mut buffer).map_err(|error| {
            invalid(format!(
                "read {} for hashing failed: {error}",
                path.display()
            ))
        })?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
        bytes = bytes
            .checked_add(read as u64)
            .ok_or_else(|| invalid(format!("hash byte count overflow for {}", path.display())))?;
    }
    Ok((bytes, lower_hex(digest.finalize())))
}

fn hash_slice<D>(path: &Path, offset: u64, length: u64) -> Result<String>
where
    D: Digest + Default,
{
    let mut file = File::open(path).map_err(|error| {
        invalid(format!(
            "open {} for slice hashing failed: {error}",
            path.display()
        ))
    })?;
    file.seek(SeekFrom::Start(offset)).map_err(|error| {
        invalid(format!(
            "seek {} to {offset} failed: {error}",
            path.display()
        ))
    })?;
    let mut reader = file.take(length);
    let mut digest = D::default();
    let mut buffer = vec![0_u8; HASH_BUFFER_BYTES];
    let mut observed = 0_u64;
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| invalid(format!("read {} slice failed: {error}", path.display())))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
        observed += read as u64;
    }
    if observed != length {
        return Err(invalid(format!(
            "slice hash {} observed {} bytes, expected {}",
            path.display(),
            observed,
            length
        )));
    }
    Ok(lower_hex(digest.finalize()))
}

fn lower_hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn inventory(values: BTreeMap<String, u64>) -> Vec<OnnxInventoryCount> {
    values
        .into_iter()
        .map(|(name, count)| OnnxInventoryCount { name, count })
        .collect()
}

fn node_label(node: &Node<'_>, index: usize) -> String {
    if node.name.trim().is_empty() {
        format!("{}[{index}]", node.op_type.as_str())
    } else {
        format!("{}({})", node.name, node.op_type.as_str())
    }
}

fn attestation_identity(attestation: &OnnxInt8Attestation) -> Result<String> {
    let mut canonical = attestation.clone();
    canonical.attestation_sha256.clear();
    let bytes = serde_json::to_vec(&canonical).map_err(|error| {
        invalid(format!(
            "serialize canonical ONNX INT8 attestation failed: {error}"
        ))
    })?;
    let mut digest = Sha256::new();
    digest.update(b"calyx-onnx-int8-attestation-identity-v1");
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
    Ok(format!("{:x}", digest.finalize()))
}

fn invalid(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: ATTESTATION_INVALID,
        message: message.into(),
        remediation: "preserve the source/output/toolchain bytes and recommission with the pinned quantizer; never publish or relabel an unattested graph",
    }
}
