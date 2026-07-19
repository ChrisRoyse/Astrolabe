//! ONNX Runtime I/O binding + provider telemetry for warm lens inference
//! (#1011).
//!
//! For GPU-policy sessions the run path uses `IoBinding`: inputs are bound
//! (host→device transfer happens at bind time on the CUDA EP) and every
//! output is bound to CUDA pinned host memory, so the device→host copy lands
//! in page-locked memory instead of pageable arena buffers. CPU-policy
//! sessions run direct. There is no fallback in either direction: a GPU
//! session that cannot bind or run fails with a structured error.
//!
//! Environment knobs (all logged at session readiness):
//! - `CALYX_CUDA_DEVICE` — process-global CUDA Runtime-visible ordinal (default
//!   0; compatibility selectors must agree, and an out-of-range ordinal fails provider
//!   registration at session build because the CUDA dispatch is
//!   `error_on_failure`).
//! - `CALYX_ONNX_IO_BINDING=0` — explicitly disable I/O binding for GPU
//!   sessions (diagnostic; logged, never silent).
//! - `CALYX_ONNX_REQUIRE_STATIC_BINDING=1` — refuse any run whose
//!   (batch, seq) shape differs from the first bound shape instead of
//!   rebinding. This is the CUDA-graph-capture precondition; a dynamic batch
//!   under this mode is a structured error, not a fallback.
//! - `CALYX_ONNX_CUDA_GRAPHS=1` — enable ORT CUDA Graph capture/replay for
//!   GPU-policy sessions. This requires I/O binding, and assigns a stable
//!   `gpu_graph_id` per observed `(batch, seq)` shape. Invalid values or an
//!   incompatible run plan fail closed. Graph mode disables the default arena
//!   shrink run option; an explicit non-`off` arena-shrink policy is refused.
//! - `CALYX_ONNX_GREEN_CONTEXT_SMS=<n>` — opt a GPU-policy session into a CUDA
//!   green-context user stream with an SM slice of at least `n` SMs and balanced
//!   work queues. Invalid values, CPU-policy sessions, unsupported builds, or
//!   `CALYX_ONNX_CUDA_GRAPHS=1` fail closed.
//! - `CALYX_ONNX_DISABLE_CPU_EP_FALLBACK=1` — set the ORT session config only
//!   for CPU-explicit sessions. CUDA sessions reject this switch because ORT
//!   applies it to intentional host shape metadata as well as compute; CUDA
//!   content fallback is instead refused by the exact placement contract.
//!
//! Device-arena controls (#1143 — BFC arena growth across dynamic shapes):
//! - `CALYX_ONNX_GPU_MEM_LIMIT_MIB` — hard cap (MiB) on the CUDA BFC arena;
//!   exhaustion becomes a structured error at a defined budget instead of
//!   eating the device from co-tenants.
//! - `CALYX_ONNX_ARENA_SHRINK` — `off` | `new-shape` (default) | `always`:
//!   when to request `memory.enable_memory_arena_shrinkage` for the run.
//! - `CALYX_ONNX_MAX_DISTINCT_SHAPES` — fail-loud cap (default 64) on the
//!   distinct (batch, seq) shapes a GPU session may run; batch/seq bucketing
//!   keeps real workloads far below it, so reaching it means a caller
//!   regressed into unbounded shape diversity.
//! Provider placement is not configurable telemetry. Every committed session
//! is inspected through ORT API 24 and the final optimized graph. CUDA sessions
//! must prove all substantive compute on CUDA, only classified bounded shape
//! metadata on CPU, zero inter-provider transfer nodes, and the same exact
//! identities in the first real synchronized-forward profile.

use std::collections::{BTreeMap, BTreeSet};

use calyx_core::{
    CalyxError, OnnxApi24PartitionNodeEvidence, OnnxApi24PartitionReceiptEvidence,
    OnnxCudaExecutionEvidence, OnnxCudaExecutionEvidenceKind, OnnxFinalGraphNodeEvidence,
    OnnxFinalGraphPlacementEvidence, OnnxFirstInferencePlacementEvidence, OnnxPlacementNodeRole,
    OnnxProfiledNodeEvidence, Result, RuntimeExecutionAttestation,
};
use ort::memory::{AllocationDevice, AllocatorType, MemoryInfo, MemoryType};
use ort::session::{RunOptions, Session, SessionInputValue, SessionOutputs};
use ort::value::{Tensor, ValueType};

use super::arena::{
    ARENA_SHRINKAGE_RUN_KEY, ArenaShrinkPolicy, MAX_DISTINCT_SHAPES_ENV, configured_arena_shrink,
    configured_gpu_mem_limit, configured_max_distinct_shapes,
};
use super::cpu_fallback_audit::{CommittedGraphAssignment, reconcile_profile_with_optimized_graph};
use super::cuda_graphs::{CUDA_GRAPHS_ENV, CudaGraphRunConfig, CudaGraphRunRequest};
use super::placement_contract::{OptimizedGraphReceipt, classify_profiled_cuda_placement};
use super::session::{
    IO_BINDING_ENV, ManagedOnnxSession, ManagedOnnxSessionId, REQUIRE_STATIC_BINDING_ENV,
    configured_cuda_graphs, cpu_ep_fallback_session_config_enabled, env_flag,
};
use super::{OnnxProviderPolicy, config_invalid};

/// Per-runtime run plan: which device, whether I/O binding is active, and the
/// static-shape contract state.
#[derive(Debug)]
pub(super) struct OnnxRunPlan {
    label: String,
    runtime: &'static str,
    io_binding: bool,
    gpu_policy: bool,
    device_id: i32,
    execution_device: String,
    stream_receipt: Option<String>,
    session_id: ManagedOnnxSessionId,
    assignment: CommittedGraphAssignment,
    optimized_graph_receipt: Option<OptimizedGraphReceipt>,
    execution_state: ExecutionState,
    require_static: bool,
    cuda_graphs: CudaGraphRunConfig,
    arena_shrink: ArenaShrinkPolicy,
    max_distinct_shapes: usize,
    bound_shape: Option<(usize, usize)>,
    seen_shapes: BTreeSet<(usize, usize)>,
}

#[derive(Debug)]
enum ExecutionState {
    Pending,
    Attested(RuntimeExecutionAttestation),
    Failed(CalyxError),
}

pub(super) struct MaterializedF32Output {
    pub(super) shape: Vec<i64>,
    pub(super) values: Vec<f32>,
}

fn validate_committed_assignment(
    policy: OnnxProviderPolicy,
    label: &str,
    execution_device: &str,
    assignment: &CommittedGraphAssignment,
    optimized_graph_receipt: Option<&OptimizedGraphReceipt>,
) -> Result<()> {
    if assignment.total_nodes == 0 {
        return Err(CalyxError {
            code: "CALYX_ONNX_GRAPH_ASSIGNMENT_EMPTY",
            message: format!(
                "committed ONNX session {label} reported zero API-24 compute nodes (providers={} assigned_operators={} assigned_nodes={})",
                assignment.per_provider,
                assignment.per_provider_operators,
                assignment.per_provider_nodes
            ),
            remediation: "preserve the exact model and runtime receipt, repair the committed-session assignment readback, and do not admit an unplaced graph",
        });
    }
    let valid = match policy {
        OnnxProviderPolicy::CudaFailLoud => {
            let Some(receipt) = optimized_graph_receipt else {
                return Err(CalyxError {
                    code: "CALYX_ONNX_PLACEMENT_CONTRACT_MISSING",
                    message: format!(
                        "committed CUDA ONNX session {label} has no inspected post-fusion optimized-graph receipt"
                    ),
                    remediation: "discard the session and rebuild it through the quarantined CUDA constructor",
                });
            };
            execution_device != "cpu"
                && receipt.total_graph_nodes > 0
                && !receipt.nodes.is_empty()
                && assignment.cuda_nodes > 0
        }
        OnnxProviderPolicy::CpuExplicit => {
            execution_device == "cpu"
                && assignment.cpu_nodes == assignment.total_nodes
                && assignment.cuda_nodes == 0
                && optimized_graph_receipt.is_none()
        }
    };
    if valid {
        return Ok(());
    }
    Err(CalyxError {
        code: "CALYX_ONNX_GRAPH_ASSIGNMENT_MISMATCH",
        message: format!(
            "committed ONNX session {label} policy={} device={execution_device} violates its quarantined provider contract, observed API24 total={} cuda={} cpu={} providers={} assigned_operators={} assigned_nodes={} optimized_graph_receipt={}",
            policy.as_str(),
            assignment.total_nodes,
            assignment.cuda_nodes,
            assignment.cpu_nodes,
            assignment.per_provider,
            assignment.per_provider_operators,
            assignment.per_provider_nodes,
            optimized_graph_receipt
                .map(|receipt| receipt.optimized_graph_sha256.as_str())
                .unwrap_or("none")
        ),
        remediation: match policy {
            OnnxProviderPolicy::CudaFailLoud => {
                "use a graph whose substantive compute is entirely CUDA and whose CPU nodes are statically proven bounded shape metadata with zero transfer nodes; never retry failed CUDA construction on CPU"
            }
            OnnxProviderPolicy::CpuExplicit => {
                "repair the explicitly authorized CPU session so every committed node is assigned only to CPU before retrying"
            }
        },
    })
}

impl OnnxRunPlan {
    /// Build the run plan for a freshly committed session and emit the
    /// readiness telemetry the #1011 acceptance requires: provider selection,
    /// device id, allocator mode, io-binding state, CPU-fallback stance.
    pub(super) fn new(
        policy: OnnxProviderPolicy,
        label: impl Into<String>,
        runtime: &'static str,
        session: &ManagedOnnxSession,
    ) -> Result<Self> {
        let label = label.into();
        if session.provider_policy() != policy {
            return Err(CalyxError {
                code: "CALYX_ONNX_SESSION_POLICY_MISMATCH",
                message: format!(
                    "run plan {label} requested provider policy {} but its committed session records {}",
                    policy.as_str(),
                    session.provider_policy().as_str()
                ),
                remediation: "discard the mismatched session and construct one run plan from the exact committed session and provider policy",
            });
        }
        super::runtime_bundle::attest_after_model_constructor(policy, session.bound_stream())?;
        let selected_device = super::runtime_bundle::selected_cuda_device(policy)?;
        let selected_device_id = selected_device
            .as_ref()
            .map(|device| i32::try_from(device.ordinal))
            .transpose()
            .map_err(|_| {
                config_invalid("attested CUDA Runtime ordinal exceeds the ORT device-id ABI")
            })?
            .unwrap_or(0);
        let device_id = session.device_id();
        if device_id != selected_device_id {
            return Err(CalyxError {
                code: "CALYX_ONNX_SESSION_IDENTITY_DRIFT",
                message: format!(
                    "committed ONNX session {label} retained CUDA Runtime ordinal {device_id}, but the shared selected-device receipt now resolves to {selected_device_id}"
                ),
                remediation: "terminate the process, preserve both device receipts, and restart from the pinned CUDA runtime boundary",
            });
        }
        let binding_env_off = std::env::var(IO_BINDING_ENV)
            .map(|raw| {
                let raw = raw.trim();
                raw == "0" || raw.eq_ignore_ascii_case("false")
            })
            .unwrap_or(false);
        let gpu_policy = matches!(policy, OnnxProviderPolicy::CudaFailLoud);
        let io_binding = gpu_policy && !binding_env_off;
        let require_static = env_flag(REQUIRE_STATIC_BINDING_ENV);
        let cuda_graphs = configured_cuda_graphs()?;
        let green_context_sms = super::green_context::configured_green_context_sms()?;
        super::green_context::validate_run_plan(policy, cuda_graphs)?;
        if cuda_graphs && !gpu_policy {
            return Err(CalyxError {
                code: "CALYX_ONNX_CUDA_GRAPHS_CPU_POLICY",
                message: format!(
                    "{CUDA_GRAPHS_ENV}=1 was requested for CPU-policy ONNX session {label}"
                ),
                remediation: "enable CUDA graphs only on CudaFailLoud sessions, or unset CALYX_ONNX_CUDA_GRAPHS for CPU sessions",
            });
        }
        if cuda_graphs && !io_binding {
            return Err(CalyxError {
                code: "CALYX_ONNX_CUDA_GRAPHS_IO_BINDING",
                message: format!(
                    "{CUDA_GRAPHS_ENV}=1 requires I/O binding for {label}, but {IO_BINDING_ENV} disabled it"
                ),
                remediation: "unset CALYX_ONNX_IO_BINDING or set it to 1 before enabling CUDA graphs",
            });
        }
        let arena_shrink =
            super::cuda_graphs::compatible_arena_shrink(cuda_graphs, configured_arena_shrink()?)?;
        let max_distinct_shapes = configured_max_distinct_shapes()?;
        let mem_limit = configured_gpu_mem_limit()?;
        let execution_device = session.execution_device().to_string();
        let selected_execution_device = selected_device
            .as_ref()
            .map(|device| device.frozen_execution_device())
            .unwrap_or_else(|| "cpu".to_string());
        if execution_device != selected_execution_device {
            return Err(CalyxError {
                code: "CALYX_ONNX_SESSION_IDENTITY_DRIFT",
                message: format!(
                    "committed ONNX session {label} retained device {execution_device}, but the shared selected-device receipt now resolves to {selected_execution_device}"
                ),
                remediation: "terminate the process, preserve both physical-device receipts, and restart from the pinned CUDA runtime boundary",
            });
        }
        let stream_receipt = session.bound_stream_receipt();
        match (policy, stream_receipt.as_ref()) {
            (OnnxProviderPolicy::CudaFailLoud, Some(_))
            | (OnnxProviderPolicy::CpuExplicit, None) => {}
            (OnnxProviderPolicy::CudaFailLoud, None) => {
                return Err(CalyxError {
                    code: "CALYX_ONNX_BOUND_STREAM_MISSING",
                    message: format!(
                        "committed CUDA ONNX session {label} has no retained execution-stream receipt"
                    ),
                    remediation: "discard the session and reconstruct the CUDA EP with an Astrolabe-owned stream retained for the full model lifetime",
                });
            }
            (OnnxProviderPolicy::CpuExplicit, Some(receipt)) => {
                return Err(CalyxError {
                    code: "CALYX_ONNX_CPU_SESSION_HAS_CUDA_STREAM",
                    message: format!(
                        "committed explicit-CPU ONNX session {label} retained unexpected stream {receipt}"
                    ),
                    remediation: "discard the session and construct CPU and CUDA lenses through distinct provider policies",
                });
            }
        }
        let assignment = session.committed_assignment().clone();
        let optimized_graph_receipt = session.optimized_graph_receipt().cloned();
        validate_committed_assignment(
            policy,
            &label,
            &execution_device,
            &assignment,
            optimized_graph_receipt.as_ref(),
        )?;
        let (allocator, cpu_fallback) = if gpu_policy {
            (
                if cuda_graphs {
                    "cuda_graph_static_device_io"
                } else if io_binding {
                    "cuda_input_bind_pinned_output"
                } else {
                    "ort_default_device_arena"
                },
                "no_content_compute_fallback_classified_cpu_shape_metadata",
            )
        } else {
            ("host", "cpu_explicit_policy")
        };
        eprintln!(
            "CALYX_ONNX_RUNTIME phase=session_quarantined label={label} runtime={runtime} provider={} device_id={device_id} physical_device={execution_device} retained_stream={} io_binding={io_binding} io_binding_env_off={binding_env_off} allocator={allocator} cpu_fallback={cpu_fallback} require_static_binding={require_static} cuda_graphs={cuda_graphs} green_context_sms={} disable_cpu_ep_fallback={} arena_extend=same_as_requested gpu_mem_limit_mib={} arena_shrink={} max_distinct_shapes={max_distinct_shapes} final_placement=pending_first_real_profile optimized_graph_sha256={} classifier={} final_graph_nodes={} api24_partition_sha256={} api24_nodes={} api24_cuda_nodes={} api24_cpu_nodes={} assigned_providers={} assigned_operators={} assigned_nodes={}",
            policy.as_str(),
            stream_receipt.as_deref().unwrap_or("none"),
            green_context_sms
                .map(|count| count.to_string())
                .unwrap_or_else(|| "off".to_string()),
            cpu_ep_fallback_session_config_enabled(policy),
            mem_limit
                .map(|bytes| (bytes / (1024 * 1024)).to_string())
                .unwrap_or_else(|| "none".to_string()),
            arena_shrink.as_str(),
            optimized_graph_receipt
                .as_ref()
                .map(|receipt| receipt.optimized_graph_sha256.as_str())
                .unwrap_or("explicit_cpu"),
            optimized_graph_receipt
                .as_ref()
                .map(|receipt| receipt.classifier_version)
                .unwrap_or("explicit_cpu"),
            optimized_graph_receipt
                .as_ref()
                .map(|receipt| receipt.total_graph_nodes)
                .unwrap_or(assignment.total_nodes),
            assignment.partition_sha256,
            assignment.total_nodes,
            assignment.cuda_nodes,
            assignment.cpu_nodes,
            assignment.per_provider,
            assignment.per_provider_operators,
            assignment.per_provider_nodes
        );
        Ok(Self {
            label,
            runtime,
            io_binding,
            gpu_policy,
            device_id,
            execution_device,
            stream_receipt,
            session_id: session.instance_id(),
            assignment,
            optimized_graph_receipt,
            execution_state: ExecutionState::Pending,
            require_static,
            cuda_graphs: CudaGraphRunConfig::new(cuda_graphs),
            arena_shrink,
            max_distinct_shapes,
            bound_shape: None,
            seen_shapes: BTreeSet::new(),
        })
    }

    /// GPU sessions pad token batches to stable power-of-two buckets so the
    /// distinct-shape set the CUDA arena retains allocations for stays
    /// bounded (#1143). CPU sessions run exact batches.
    pub(super) const fn pads_batches(&self) -> bool {
        self.gpu_policy
    }

    /// Arena shrinkage request for this run, per policy: reclaim the device
    /// arena's transient over-extension after first-seen shapes (`new-shape`),
    /// after every run (`always`), or never (`off`). Logged whenever active.
    fn run_options(
        &mut self,
        shape: (usize, usize),
        new_shape: bool,
    ) -> Result<Option<RunOptions>> {
        let shrink = self.gpu_policy
            && match self.arena_shrink {
                ArenaShrinkPolicy::Off => false,
                ArenaShrinkPolicy::NewShape => new_shape,
                ArenaShrinkPolicy::Always => true,
            };
        if !shrink && !self.cuda_graphs.enabled() {
            return Ok(None);
        }
        let mut options = RunOptions::new().map_err(|err| {
            config_invalid(format!(
                "ONNX RunOptions create failed for {}: {err}",
                self.label
            ))
        })?;
        if shrink {
            options
                .add_config_entry(ARENA_SHRINKAGE_RUN_KEY, format!("gpu:{}", self.device_id))
                .map_err(|err| {
                    config_invalid(format!(
                        "ONNX arena shrinkage config failed for {}: {err}",
                        self.label
                    ))
                })?;
            eprintln!(
                "CALYX_ONNX_RUNTIME phase=arena_shrink label={} device_id={} policy={} distinct_shapes={}",
                self.label,
                self.device_id,
                self.arena_shrink.as_str(),
                self.seen_shapes.len()
            );
        }
        self.cuda_graphs
            .add_run_options(&mut options, &self.label, shape, new_shape)?;
        Ok(Some(options))
    }

    /// Run the exact session, materialize one owned f32 output while the ORT
    /// values are live, then synchronize and commit placement attestation
    /// before any caller-provided extraction or downstream publication.
    pub(super) fn run_extract<R>(
        &mut self,
        session: &mut ManagedOnnxSession,
        inputs: Vec<(String, Tensor<i64>)>,
        shape: (usize, usize),
        output_name: &str,
        extract: impl FnOnce(&MaterializedF32Output) -> Result<R>,
    ) -> Result<R> {
        self.ensure_usable()?;
        if let Err(error) = self.validate_session_identity(session) {
            return Err(self.fail_terminal("pre_run_session_identity", error));
        }
        let output = {
            let raw_session = match session.quarantined_session_mut(self.session_id) {
                Ok(session) => session,
                Err(error) => {
                    return Err(self.fail_terminal("pre_run_session_identity", error));
                }
            };
            self.run_extract_inner(raw_session, inputs, shape, output_name)
        };
        let output = match output {
            Ok(output) => output,
            Err(error) => return Err(self.fail_terminal("forward_or_host_materialization", error)),
        };
        if let Err(error) = session.synchronize_and_attest_completion(&self.label) {
            return Err(self.fail_terminal("retained_stream_synchronization", error));
        }
        self.complete_first_inference(session)?;
        extract(&output).map_err(|error| self.fail_terminal("attested_output_validation", error))
    }

    fn run_extract_inner(
        &mut self,
        session: &mut Session,
        inputs: Vec<(String, Tensor<i64>)>,
        shape: (usize, usize),
        output_name: &str,
    ) -> Result<MaterializedF32Output> {
        validate_input_shape(&inputs, shape, &self.label)?;
        let new_shape = self.enforce_shape_contract(shape)?;
        let run_options = self.run_options(shape, new_shape)?;
        if !self.io_binding {
            let named: Vec<(String, SessionInputValue<'_>)> = inputs
                .into_iter()
                .map(|(name, tensor)| (name, SessionInputValue::from(tensor)))
                .collect();
            let outputs = match &run_options {
                Some(options) => session.run_with_options(named, options),
                None => session.run(named),
            }
            .map_err(|err| config_invalid(format!("ONNX inference failed: {err}")))?;
            let output = materialize_f32_output(&outputs, output_name, &self.label)?;
            drop(outputs);
            return Ok(output);
        }
        if self.cuda_graphs.enabled() {
            let output = self.cuda_graphs.run_extract(
                session,
                CudaGraphRunRequest {
                    label: &self.label,
                    device_id: self.device_id,
                    shape,
                    output_name,
                    options: run_options.as_ref(),
                },
                inputs,
                |outputs| materialize_f32_output(outputs, output_name, &self.label),
            )?;
            return Ok(output);
        }
        let mut binding = session.create_binding().map_err(|err| {
            config_invalid(format!(
                "ONNX io-binding create failed for {}: {err}",
                self.label
            ))
        })?;
        // Bind inputs first: the CUDA EP performs the host->device transfer
        // at bind time. The tensors stay alive until run_binding returns.
        for (name, tensor) in &inputs {
            binding.bind_input(name.as_str(), tensor).map_err(|err| {
                config_invalid(format!(
                    "ONNX io-binding bind_input {name} failed for {}: {err}",
                    self.label
                ))
            })?;
        }
        let pinned_output = MemoryInfo::new(
            AllocationDevice::CUDA_PINNED,
            self.device_id,
            AllocatorType::Device,
            MemoryType::CPUOutput,
        )
        .map_err(|err| {
            config_invalid(format!(
                "ONNX io-binding pinned-output MemoryInfo failed for {} device {}: {err}",
                self.label, self.device_id
            ))
        })?;
        binding
            .bind_output_to_device(output_name, &pinned_output)
            .map_err(|err| {
                config_invalid(format!(
                    "ONNX io-binding bind_output {output_name} failed for {}: {err}",
                    self.label
                ))
            })?;
        binding.synchronize_inputs().map_err(|error| {
            crate::runtime::common::gpu_synchronization_failed(
                &self.label,
                "onnx_bound_inputs_before_run",
                error,
            )
        })?;
        let outputs = match &run_options {
            Some(options) => session.run_binding_with_options(&binding, options),
            None => session.run_binding(&binding),
        }
        .map_err(|err| {
            config_invalid(format!(
                "ONNX io-binding inference failed for {}: {err}",
                self.label
            ))
        })?;
        binding.synchronize_outputs().map_err(|error| {
            crate::runtime::common::gpu_synchronization_failed(
                &self.label,
                "onnx_bound_outputs_before_host_extraction",
                error,
            )
        })?;
        let output = materialize_f32_output(&outputs, output_name, &self.label)?;
        drop(outputs);
        drop(binding);
        Ok(output)
    }

    fn validate_session_identity(&self, session: &ManagedOnnxSession) -> Result<()> {
        let observed_stream = session.bound_stream_receipt();
        if session.instance_id() != self.session_id
            || session.provider_policy()
                != if self.gpu_policy {
                    OnnxProviderPolicy::CudaFailLoud
                } else {
                    OnnxProviderPolicy::CpuExplicit
                }
            || session.execution_device() != self.execution_device
            || observed_stream.as_deref() != self.stream_receipt.as_deref()
            || session.committed_assignment() != &self.assignment
            || session.optimized_graph_receipt() != self.optimized_graph_receipt.as_ref()
        {
            return Err(CalyxError {
                code: "CALYX_ONNX_SESSION_IDENTITY_DRIFT",
                message: format!(
                    "run plan runtime={} label={} identity={:?} policy={} device={} stream={} partition={} graph={} does not match supplied session identity={:?} policy={} device={} stream={} partition={} graph={}",
                    self.runtime,
                    self.label,
                    self.session_id,
                    if self.gpu_policy {
                        OnnxProviderPolicy::CudaFailLoud.as_str()
                    } else {
                        OnnxProviderPolicy::CpuExplicit.as_str()
                    },
                    self.execution_device,
                    self.stream_receipt.as_deref().unwrap_or("none"),
                    self.assignment.partition_sha256,
                    self.optimized_graph_receipt
                        .as_ref()
                        .map(|receipt| receipt.optimized_graph_sha256.as_str())
                        .unwrap_or("none"),
                    session.instance_id(),
                    session.provider_policy().as_str(),
                    session.execution_device(),
                    observed_stream.as_deref().unwrap_or("none"),
                    session.committed_assignment().partition_sha256,
                    session
                        .optimized_graph_receipt()
                        .map(|receipt| receipt.optimized_graph_sha256.as_str())
                        .unwrap_or("none")
                ),
                remediation: "terminally discard both objects and keep each run plan inseparably paired with the exact managed session that created it; never execute before exact identity validation",
            });
        }
        Ok(())
    }

    fn ensure_usable(&self) -> Result<()> {
        match &self.execution_state {
            ExecutionState::Pending | ExecutionState::Attested(_) => Ok(()),
            ExecutionState::Failed(error) => Err(error.clone()),
        }
    }

    fn fail_terminal(&mut self, stage: &'static str, error: CalyxError) -> CalyxError {
        if let ExecutionState::Failed(existing) = &self.execution_state {
            return existing.clone();
        }
        let terminal = CalyxError {
            code: error.code,
            message: format!(
                "generic ONNX runtime={} label={} provider_policy={} device={} stream={} stage={stage} entered terminal Failed state: {}",
                self.runtime,
                self.label,
                if self.gpu_policy {
                    OnnxProviderPolicy::CudaFailLoud.as_str()
                } else {
                    OnnxProviderPolicy::CpuExplicit.as_str()
                },
                self.execution_device,
                self.stream_receipt.as_deref().unwrap_or("none"),
                error.message
            ),
            remediation: error.remediation,
        };
        eprintln!(
            "CALYX_ONNX_RUNTIME phase=execution_terminal_failure runtime={} label={} provider={} device={} retained_stream={} stage={stage} code={} message={} remediation={}",
            self.runtime,
            self.label,
            if self.gpu_policy {
                OnnxProviderPolicy::CudaFailLoud.as_str()
            } else {
                OnnxProviderPolicy::CpuExplicit.as_str()
            },
            self.execution_device,
            self.stream_receipt.as_deref().unwrap_or("none"),
            terminal.code,
            terminal.message,
            terminal.remediation
        );
        self.execution_state = ExecutionState::Failed(terminal.clone());
        terminal
    }

    fn complete_first_inference(&mut self, session: &mut ManagedOnnxSession) -> Result<()> {
        match &self.execution_state {
            ExecutionState::Attested(_) => return Ok(()),
            ExecutionState::Failed(error) => return Err(error.clone()),
            ExecutionState::Pending => {}
        }
        let attestation = match self.build_execution_attestation(session) {
            Ok(attestation) => attestation,
            Err(error) => {
                return Err(self.fail_terminal("first_forward_placement_attestation", error));
            }
        };
        eprintln!(
            "CALYX_ONNX_RUNTIME phase=execution_attestation_committed runtime={} label={} provider={} device={} total_nodes={} cpu_nodes={} evidence={}",
            self.runtime,
            self.label,
            attestation.provider,
            attestation.device,
            attestation.total_compute_nodes.unwrap_or(0),
            attestation.cpu_compute_nodes.unwrap_or(0),
            attestation.evidence
        );
        self.execution_state = ExecutionState::Attested(attestation);
        Ok(())
    }

    fn build_execution_attestation(
        &self,
        session: &mut ManagedOnnxSession,
    ) -> Result<RuntimeExecutionAttestation> {
        self.validate_session_identity(session)?;
        let observed_stream_receipt = session.bound_stream_receipt();
        if session.provider_policy()
            != if self.gpu_policy {
                OnnxProviderPolicy::CudaFailLoud
            } else {
                OnnxProviderPolicy::CpuExplicit
            }
            || session.execution_device() != self.execution_device
            || observed_stream_receipt.as_deref() != self.stream_receipt.as_deref()
        {
            return Err(CalyxError {
                code: "CALYX_ONNX_SESSION_IDENTITY_DRIFT",
                message: format!(
                    "run plan runtime={} label={} records policy={} device={} stream={}, but the executing session records policy={} device={} stream={}",
                    self.runtime,
                    self.label,
                    if self.gpu_policy {
                        OnnxProviderPolicy::CudaFailLoud.as_str()
                    } else {
                        OnnxProviderPolicy::CpuExplicit.as_str()
                    },
                    self.execution_device,
                    self.stream_receipt.as_deref().unwrap_or("none"),
                    session.provider_policy().as_str(),
                    session.execution_device(),
                    observed_stream_receipt.as_deref().unwrap_or("none")
                ),
                remediation: "terminate the process, preserve both receipts, and rebuild the run plan from the exact committed session",
            });
        }

        let (provider, evidence, substantive_compute_nodes, cpu_compute_nodes) = if self.gpu_policy
        {
            let optimized_receipt =
                self.optimized_graph_receipt.as_ref().ok_or_else(|| CalyxError {
                code: "CALYX_ONNX_OPTIMIZED_GRAPH_RECEIPT_MISSING",
                message: format!(
                    "first-forward CUDA attestation for {} has no retained optimized-graph receipt",
                    self.label
                ),
                remediation: "discard the session and rebuild it through the durable quarantined optimized-graph constructor",
            })?;
            if session.optimized_graph_receipt() != Some(optimized_receipt) {
                return Err(CalyxError {
                    code: "CALYX_ONNX_OPTIMIZED_GRAPH_DRIFT",
                    message: format!(
                        "run plan {} graph {} differs from its executing session",
                        self.label, optimized_receipt.optimized_graph_sha256
                    ),
                    remediation: "terminally discard the session and rebuild the run plan from the exact committed session",
                });
            }
            let snapshot = session.finish_profile_snapshot(&self.label)?;
            let trace = std::str::from_utf8(&snapshot.bytes).map_err(|error| CalyxError {
                code: "CALYX_ONNX_PROFILE_PARSE",
                message: format!(
                    "first-forward profile {} for {} is not UTF-8: {error}",
                    snapshot.final_path.display(),
                    self.label
                ),
                remediation: "preserve the malformed profile and pinned runtime logs, repair ONNX profiling output, and retry in a new process",
            })?;
            let trace_sha256 = snapshot.sha256.clone();
            let optimized_bytes = session.revalidate_optimized_graph(&self.label)?;
            let profile =
                reconcile_profile_with_optimized_graph(&self.label, trace, optimized_receipt)?;
            let contract = classify_profiled_cuda_placement(
                &self.assignment,
                optimized_receipt,
                &optimized_bytes,
                &profile,
                &trace_sha256,
            )?;
            let profile_path = snapshot.final_path.to_str().ok_or_else(|| CalyxError {
                code: "CALYX_ONNX_PROFILE_PATH_INVALID",
                message: format!(
                    "first-forward profile path for {} is not valid UTF-8: {}",
                    self.label,
                    snapshot.final_path.display()
                ),
                remediation: "use a canonical UTF-8 durable ONNX evidence path and rebuild the session; never emit lossy execution evidence",
            })?;
            let retained_stream =
                super::green_context::retained_stream_evidence(session.bound_stream()).ok_or_else(
                    || CalyxError {
                        code: "CALYX_ONNX_BOUND_STREAM_EVIDENCE_MISSING",
                        message: format!(
                            "first-forward CUDA evidence for {} has no retained, feature-backed execution-stream evidence",
                            self.label
                        ),
                        remediation: "build calyx-registry with the cuda feature, construct the CUDA execution provider with an Astrolabe-owned stream, and retain it through the first real synchronized inference",
                    },
                )?;
            let mut final_nodes = Vec::new();
            for node in &contract.cuda_compute_nodes {
                final_nodes.push(OnnxFinalGraphNodeEvidence {
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
                let proof =
                    contract
                        .cpu_metadata_proofs
                        .get(&node.name)
                        .ok_or_else(|| CalyxError {
                            code: "CALYX_ONNX_CPU_METADATA_PROOF_MISSING",
                            message: format!(
                                "placement contract {} authorizes CPU node {:?} without a retained static proof",
                                contract.contract_sha256, node.name
                            ),
                            remediation: "terminally discard the session and repair optimized-graph classification before emitting execution evidence",
                        })?;
                final_nodes.push(OnnxFinalGraphNodeEvidence {
                    name: node.name.clone(),
                    domain: node.domain.clone(),
                    operator: node.operator.clone(),
                    provider: node.provider.clone(),
                    role: OnnxPlacementNodeRole::CpuShapeMetadata,
                    max_output_elements: Some(proof.max_output_elements),
                    output_dtypes: Some(proof.output_dtypes.clone()),
                });
            }
            final_nodes.sort_by(|left, right| left.name.cmp(&right.name));
            let final_assigned_operators = final_provider_operator_summary(&final_nodes);
            let structured = OnnxCudaExecutionEvidence {
                kind: OnnxCudaExecutionEvidenceKind::Api24PartitionV2FinalGraphClassifiedV2AndFirstExactInferenceProfile,
                retained_stream,
                classifier_version: contract.classifier_version.to_string(),
                opset_inventory: contract.opset_inventory.clone(),
                opset_sha256: contract.opset_sha256.clone(),
                optimized_graph_path: contract.optimized_graph_path.clone(),
                optimized_graph_bytes: contract.optimized_graph_bytes,
                optimized_graph_sha256: contract.optimized_graph_sha256.clone(),
                api24_partition_sha256: contract.api24_partition_sha256.clone(),
                final_graph_placement_sha256: contract.final_graph_placement_sha256.clone(),
                cpu_metadata_proof_sha256: contract.cpu_metadata_proof_sha256.clone(),
                placement_contract_sha256: contract.contract_sha256.clone(),
                api24_partition: OnnxApi24PartitionReceiptEvidence {
                    schema: self.assignment.schema.to_string(),
                    subgraph_count: self.assignment.subgraph_count,
                    total_nodes: self.assignment.total_nodes,
                    cuda_nodes: self.assignment.cuda_nodes,
                    cpu_nodes: self.assignment.cpu_nodes,
                    providers: self.assignment.per_provider.clone(),
                    assigned_operators: self.assignment.per_provider_operators.clone(),
                    nodes: self
                        .assignment
                        .nodes
                        .iter()
                        .map(|node| OnnxApi24PartitionNodeEvidence {
                            subgraph_index: node.subgraph_index,
                            node_index_in_subgraph: node.node_index_in_subgraph,
                            name: node.name.clone(),
                            domain: node.domain.clone(),
                            operator: node.operator.clone(),
                            provider: node.provider.clone(),
                        })
                        .collect(),
                },
                final_graph_placement: OnnxFinalGraphPlacementEvidence {
                    total_graph_nodes: contract.total_graph_nodes(),
                    cuda_compute_nodes: contract.cuda_compute_node_count(),
                    cpu_metadata_nodes: contract.cpu_metadata_node_count(),
                    unclassified_cpu_nodes: 0,
                    inter_provider_memcpy_nodes: 0,
                    providers: profile.per_provider.clone(),
                    assigned_operators: final_assigned_operators,
                    nodes: final_nodes,
                },
                first_inference_profile: OnnxFirstInferencePlacementEvidence {
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
                            role: if node.provider == "CUDAExecutionProvider" {
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
                },
                profile_path: profile_path.to_string(),
                profile_bytes: u64::try_from(snapshot.bytes.len()).map_err(|_| CalyxError {
                    code: "CALYX_ONNX_PROFILE_SIZE_OVERFLOW",
                    message: format!(
                        "durable first profile for {} exceeds the u64 evidence contract",
                        self.label
                    ),
                    remediation: "terminally discard the session and commission a bounded first-profile trace",
                })?,
                profile_sha256: trace_sha256,
            };
            (
                format!(
                    "partition={};final={};profile={};placement_contract={}",
                    structured.api24_partition.providers,
                    structured.final_graph_placement.providers,
                    structured.first_inference_profile.providers,
                    structured.placement_contract_sha256
                ),
                super::execution_attestation::serialize_cuda_onnx_execution_evidence(&structured)?,
                contract.cuda_compute_node_count(),
                0,
            )
        } else {
            (
                self.assignment.per_provider.clone(),
                format!(
                    "onnx_api24_committed_session_after_first_real_host_materialized_inference;assigned_operators={}",
                    self.assignment.per_provider_operators
                ),
                self.assignment.total_nodes,
                self.assignment.cpu_nodes,
            )
        };
        Ok(RuntimeExecutionAttestation {
            runtime: self.runtime.to_string(),
            provider,
            device: self.execution_device.clone(),
            loader_dtype: None,
            compute_dtype: None,
            evidence,
            total_compute_nodes: Some(substantive_compute_nodes),
            cpu_compute_nodes: Some(cpu_compute_nodes),
        })
    }

    pub(super) fn execution_attestation(&self) -> Result<Option<RuntimeExecutionAttestation>> {
        match &self.execution_state {
            ExecutionState::Pending => Ok(None),
            ExecutionState::Attested(attestation) => Ok(Some(attestation.clone())),
            ExecutionState::Failed(error) => Err(error.clone()),
        }
    }

    /// Records the run shape; returns whether it is first-seen. GPU sessions
    /// fail loud when distinct-shape diversity exceeds the configured cap —
    /// the ORT CUDA BFC arena retains per-shape allocations forever, so
    /// unbounded diversity is a slow-motion device OOM (#1143), and the
    /// batch/seq bucketing upstream keeps legitimate streams far below the
    /// cap.
    pub(super) fn enforce_shape_contract(&mut self, shape: (usize, usize)) -> Result<bool> {
        let new_shape = self.seen_shapes.insert(shape);
        if new_shape {
            eprintln!(
                "CALYX_ONNX_RUNTIME phase=io_binding_shape label={} batch={} seq={} io_binding={} distinct_shapes={}",
                self.label,
                shape.0,
                shape.1,
                self.io_binding,
                self.seen_shapes.len()
            );
            if self.gpu_policy && self.seen_shapes.len() > self.max_distinct_shapes {
                return Err(CalyxError {
                    code: "CALYX_ONNX_SHAPE_DIVERSITY",
                    message: format!(
                        "{} has run {} distinct (batch, seq) shapes, exceeding {MAX_DISTINCT_SHAPES_ENV}={} — unbounded shape diversity grows the CUDA BFC arena until device OOM (new shape batch={} seq={})",
                        self.label,
                        self.seen_shapes.len(),
                        self.max_distinct_shapes,
                        shape.0,
                        shape.1
                    ),
                    remediation: "batch and sequence bucketing should cap distinct shapes; find the caller that bypasses bucketed batching, or raise CALYX_ONNX_MAX_DISTINCT_SHAPES only if the workload legitimately needs more shape classes",
                });
            }
        }
        if !self.require_static {
            return Ok(new_shape);
        }
        match self.bound_shape {
            None => {
                self.bound_shape = Some(shape);
                Ok(new_shape)
            }
            Some(bound) if bound == shape => Ok(new_shape),
            Some(bound) => Err(CalyxError {
                code: "CALYX_ONNX_STATIC_BINDING_SHAPE",
                message: format!(
                    "{} requires the captured static binding shape batch={} seq={} but received batch={} seq={} under {REQUIRE_STATIC_BINDING_ENV}=1",
                    self.label, bound.0, bound.1, shape.0, shape.1
                ),
                remediation: "bucket inputs to the captured shape (fixed batch and sequence length) or unset CALYX_ONNX_REQUIRE_STATIC_BINDING to allow per-shape rebinding",
            }),
        }
    }
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

fn materialize_f32_output(
    outputs: &SessionOutputs<'_>,
    output_name: &str,
    label: &str,
) -> Result<MaterializedF32Output> {
    let output = outputs.get(output_name).ok_or_else(|| CalyxError {
        code: "CALYX_ONNX_OUTPUT_CONTRACT_MISMATCH",
        message: format!(
            "ONNX session {label} did not return its exact bound output {output_name:?}; observed outputs=[{}]",
            outputs.keys().collect::<Vec<_>>().join(",")
        ),
        remediation:
            "discard the session, restore the frozen model output contract, and do not publish output",
    })?;
    let (shape, values) = output.try_extract_tensor::<f32>().map_err(|error| {
        CalyxError {
            code: "CALYX_ONNX_OUTPUT_CONTRACT_DTYPE_MISMATCH",
            message: format!(
                "ONNX session {label} exact output {output_name:?} is not the frozen f32 tensor: {error}"
            ),
            remediation:
                "terminally discard the session, restore the exact frozen output dtype, and do not publish output",
        }
    })?;
    Ok(MaterializedF32Output {
        shape: shape.to_vec(),
        values: values.to_vec(),
    })
}

fn validate_input_shape(
    inputs: &[(String, Tensor<i64>)],
    claimed: (usize, usize),
    label: &str,
) -> Result<()> {
    if inputs.is_empty() {
        return Err(config_invalid(format!(
            "ONNX session {label} received no named tensors for claimed batch={} seq={}",
            claimed.0, claimed.1
        )));
    }
    let expected_batch = i64::try_from(claimed.0)
        .map_err(|_| config_invalid(format!("ONNX batch {} exceeds i64", claimed.0)))?;
    let expected_seq = i64::try_from(claimed.1)
        .map_err(|_| config_invalid(format!("ONNX sequence {} exceeds i64", claimed.1)))?;
    if expected_batch <= 0 || expected_seq <= 0 {
        return Err(config_invalid(format!(
            "ONNX session {label} claimed nonpositive run shape batch={} seq={}",
            claimed.0, claimed.1
        )));
    }
    for (name, tensor) in inputs {
        let ValueType::Tensor { shape, .. } = tensor.dtype() else {
            return Err(config_invalid(format!(
                "ONNX input {name:?} for {label} is not a tensor"
            )));
        };
        if shape.as_ref() != [expected_batch, expected_seq] {
            return Err(CalyxError {
                code: "CALYX_ONNX_RUN_SHAPE_MISMATCH",
                message: format!(
                    "ONNX input {name:?} for {label} has physical shape {shape:?}, but the run plan was given batch={} seq={}",
                    claimed.0, claimed.1
                ),
                remediation: "derive run shape from the exact materialized tensors and keep every token input on the same [batch,sequence] dimensions before executing",
            });
        }
    }
    Ok(())
}
