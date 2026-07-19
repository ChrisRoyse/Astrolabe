use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use calyx_core::{
    CalyxError, OnnxApi24PartitionNodeEvidence, OnnxApi24PartitionReceiptEvidence,
    OnnxCudaExecutionEvidence, OnnxCudaExecutionEvidenceKind, OnnxFinalGraphNodeEvidence,
    OnnxFinalGraphPlacementEvidence, OnnxFirstInferencePlacementEvidence, OnnxPlacementNodeRole,
    OnnxProfiledNodeEvidence, OnnxRetainedCudaStreamEvidence, Result, RuntimeExecutionAttestation,
};
use fastembed::SessionPolicy;
use ort::session::Session;

use super::cpu_fallback_audit::{
    CommittedGraphAssignment, read_committed_graph_assignment,
    reconcile_profile_with_optimized_graph, validate_partition_receipt,
};
use super::evidence_artifact::{DurableOnnxArtifact, OnnxEvidenceTransaction};
use super::fastembed_artifacts::FrozenFastembedReceipt;
use super::placement_contract::{
    OptimizedGraphReceipt, classify_profiled_cuda_placement, inspect_optimized_graph,
};
use super::{OnnxModelFiles, OnnxProviderPolicy};

const CUDA_REMEDIATION: &str = "verify the process-global pinned CUDA 13 ONNX Runtime identity, its attested selected physical device, and the CUDA kernel roster for every frozen operator; select the explicit CPU constructor only when CUDA is genuinely unavailable before session construction, and never retry a failed CUDA session on CPU";
const CPU_REMEDIATION: &str = "verify the process-global pinned ONNX Runtime identity and repair the explicitly authorized CPU model/session configuration before retrying";
const MAX_PROTO_RECURSION: usize = 64;

#[derive(Debug)]
pub(super) struct FastembedModelContext {
    label: String,
    model_code: String,
    model_path: PathBuf,
    weights_sha256: String,
    artifact_bytes: u64,
    model_sha256: String,
    tokenizer_sha256: String,
    external_sha256: String,
    provider_policy: OnnxProviderPolicy,
    device: String,
    profile_prefix: Option<PathBuf>,
    optimized_staging_path: Option<PathBuf>,
    evidence_transaction: Option<OnnxEvidenceTransaction>,
    optimized_graph_artifact: Option<DurableOnnxArtifact>,
    frozen_operators: String,
}

impl FastembedModelContext {
    pub(super) fn new(
        label: String,
        model_code: &str,
        files: &OnnxModelFiles,
        receipt: &FrozenFastembedReceipt,
        provider_policy: OnnxProviderPolicy,
    ) -> Result<Self> {
        let selected_device = super::runtime_bundle::selected_cuda_device(provider_policy)?;
        let device = selected_device
            .map(|device| device.frozen_execution_device())
            .unwrap_or_else(|| "cpu".to_string());
        let evidence_transaction = (provider_policy == OnnxProviderPolicy::CudaFailLoud)
            .then(|| OnnxEvidenceTransaction::begin(&files.model_file, &label))
            .transpose()?;
        let profile_prefix = evidence_transaction
            .as_ref()
            .map(|transaction| transaction.profile_prefix().to_path_buf());
        let optimized_staging_path = evidence_transaction
            .as_ref()
            .map(|transaction| transaction.optimized_graph_path().to_path_buf());
        Ok(Self {
            label,
            model_code: model_code.to_string(),
            model_path: files.model_file.clone(),
            weights_sha256: hex_sha256(receipt.weights_sha256),
            artifact_bytes: receipt.artifact_bytes,
            model_sha256: receipt.model_sha256.clone(),
            tokenizer_sha256: receipt.tokenizer_sha256.clone(),
            external_sha256: receipt.external_sha256.clone(),
            provider_policy,
            device,
            profile_prefix,
            optimized_staging_path,
            evidence_transaction,
            optimized_graph_artifact: None,
            frozen_operators: receipt.frozen_operators.clone(),
        })
    }

    pub(super) fn session_policy(&self) -> Result<SessionPolicy> {
        match self.provider_policy {
            OnnxProviderPolicy::CudaFailLoud => Ok(SessionPolicy::cuda_attested_placement(
                self.profile_prefix.as_ref().cloned().ok_or_else(|| {
                    self.error(
                        "session_policy",
                        "CUDA FastEmbed context has no profiling prefix",
                    )
                })?,
                self.optimized_staging_path
                    .as_ref()
                    .cloned()
                    .ok_or_else(|| {
                        self.error(
                            "session_policy",
                            "CUDA FastEmbed context has no optimized-graph path",
                        )
                    })?,
            )),
            OnnxProviderPolicy::CpuExplicit => Ok(SessionPolicy::explicit_cpu()),
        }
    }

    fn snapshot_optimized_graph(&self) -> Result<(PathBuf, Vec<u8>)> {
        let artifact = self.optimized_graph_artifact.as_ref().ok_or_else(|| {
            self.error(
                "optimized_graph_readback",
                "CUDA FastEmbed context has no durable optimized-graph artifact",
            )
        })?;
        let bytes = artifact
            .revalidate()
            .map_err(|error| self.preserve("optimized_graph_readback", error))?;
        Ok((artifact.final_path.clone(), bytes))
    }

    fn preserve(&self, stage: &'static str, error: CalyxError) -> CalyxError {
        let contextual = self.error(stage, &error.message);
        CalyxError {
            code: error.code,
            message: contextual.message,
            remediation: error.remediation,
        }
    }

    pub(super) fn error(&self, stage: &'static str, reason: impl ToString) -> CalyxError {
        CalyxError {
            code: "CALYX_ONNX_FASTEMBED_EXECUTION_UNATTESTED",
            message: format!(
                "fastembed model={} path={} weights_sha256={} artifact_bytes={} model_sha256={} tokenizer_sha256={} external_sha256={} provider={} device={} profile_prefix={} optimized_graph_path={} stage={} frozen_operators={} reason={}",
                self.model_code,
                self.model_path.display(),
                self.weights_sha256,
                self.artifact_bytes,
                self.model_sha256,
                self.tokenizer_sha256,
                self.external_sha256,
                self.provider_policy.as_str(),
                self.device,
                self.profile_prefix
                    .as_ref()
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(|| "none".to_string()),
                self.optimized_staging_path
                    .as_ref()
                    .map(|path| path.display().to_string())
                    .or_else(|| self
                        .optimized_graph_artifact
                        .as_ref()
                        .map(|artifact| artifact.final_path.display().to_string()))
                    .unwrap_or_else(|| "none".to_string()),
                stage,
                self.frozen_operators,
                reason.to_string()
            ),
            remediation: match self.provider_policy {
                OnnxProviderPolicy::CudaFailLoud => CUDA_REMEDIATION,
                OnnxProviderPolicy::CpuExplicit => CPU_REMEDIATION,
            },
        }
    }
}

#[derive(Debug)]
enum ExecutionState {
    Pending(Option<OnnxEvidenceTransaction>),
    Finalizing,
    Attested {
        attestation: RuntimeExecutionAttestation,
        _profile_artifact: Option<DurableOnnxArtifact>,
    },
    Failed(CalyxError),
}

/// Placement evidence retained for one exact committed FastEmbed session.
pub(super) struct FastembedExecutionState {
    context: FastembedModelContext,
    assignment: CommittedGraphAssignment,
    optimized_graph_receipt: Option<OptimizedGraphReceipt>,
    retained_stream: Option<OnnxRetainedCudaStreamEvidence>,
    state: Mutex<ExecutionState>,
}

impl FastembedExecutionState {
    pub(super) fn inspect(
        session: &Session,
        mut context: FastembedModelContext,
        retained_stream: Option<OnnxRetainedCudaStreamEvidence>,
    ) -> Result<Self> {
        let assignment = read_committed_graph_assignment(session, &context.label)
            .map_err(|error| context.preserve("api24_graph_assignment_readback", error))?;
        let optimized_graph_receipt = match context.provider_policy {
            OnnxProviderPolicy::CudaFailLoud => {
                validate_partition_receipt(&assignment, &context.label, true)
                    .map_err(|error| context.preserve("api24_partition_validation", error))?;
                let missing_transaction = context.error(
                    "optimized_graph_publish",
                    "CUDA FastEmbed context lost its durable evidence transaction",
                );
                let transaction = context
                    .evidence_transaction
                    .as_mut()
                    .ok_or(missing_transaction)?;
                let artifact = transaction
                    .publish_optimized_graph()
                    .map_err(|error| context.preserve("optimized_graph_publish", error))?;
                let receipt = inspect_optimized_graph(&artifact.final_path, &artifact.bytes)
                    .map_err(|error| context.preserve("optimized_graph_inspection", error))?;
                context.optimized_graph_artifact = Some(artifact);
                Some(receipt)
            }
            OnnxProviderPolicy::CpuExplicit => {
                validate_explicit_cpu_assignment(&context, &assignment)?;
                None
            }
        };
        match (context.provider_policy, retained_stream.as_ref()) {
            (OnnxProviderPolicy::CudaFailLoud, Some(stream))
                if stream.physical_device == context.device => {}
            (OnnxProviderPolicy::CudaFailLoud, Some(stream)) => {
                return Err(context.error(
                    "retained_stream_identity",
                    format!(
                        "retained stream physical device {} differs from selected execution device {}",
                        stream.physical_device, context.device
                    ),
                ));
            }
            (OnnxProviderPolicy::CudaFailLoud, None) => {
                return Err(context.error(
                    "retained_stream_identity",
                    "CUDA FastEmbed session has no retained Astrolabe-owned stream evidence",
                ));
            }
            (OnnxProviderPolicy::CpuExplicit, Some(stream)) => {
                return Err(context.error(
                    "retained_stream_identity",
                    format!(
                        "explicit-CPU FastEmbed session unexpectedly retained CUDA stream {}",
                        stream.stream_address
                    ),
                ));
            }
            (OnnxProviderPolicy::CpuExplicit, None) => {}
        }
        eprintln!(
            "CALYX_ONNX_RUNTIME phase=fastembed_api24_graph_assignment label={} model={} path={} weights_sha256={} artifact_bytes={} model_sha256={} tokenizer_sha256={} external_sha256={} provider={} device={} total_nodes={} cuda_nodes={} cpu_nodes={} providers={} assigned_operators={}",
            context.label,
            context.model_code,
            context.model_path.display(),
            context.weights_sha256,
            context.artifact_bytes,
            context.model_sha256,
            context.tokenizer_sha256,
            context.external_sha256,
            context.provider_policy.as_str(),
            context.device,
            assignment.total_nodes,
            assignment.cuda_nodes,
            assignment.cpu_nodes,
            assignment.per_provider,
            assignment.per_provider_operators,
        );
        Ok(Self {
            state: Mutex::new(ExecutionState::Pending(context.evidence_transaction.take())),
            context,
            assignment,
            optimized_graph_receipt,
            retained_stream,
        })
    }

    /// Permanently poisons this committed session after any execution-path
    /// failure. A later call observes the first terminal error instead of
    /// retrying a CUDA session whose stream or provider state may be damaged.
    pub(super) fn fail_terminal(&self, stage: &'static str, reason: impl ToString) -> CalyxError {
        let error = self.context.error(stage, reason);
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => {
                let state_error = self.context.error(
                    "execution_attestation_state",
                    format!(
                        "FastEmbed execution-attestation mutex is poisoned while latching terminal failure code={} message={}",
                        error.code, error.message
                    ),
                );
                self.log_terminal_failure(&state_error);
                return state_error;
            }
        };
        if let ExecutionState::Failed(existing) = &*state {
            return existing.clone();
        }
        self.log_terminal_failure(&error);
        *state = ExecutionState::Failed(error.clone());
        error
    }

    pub(super) fn ensure_usable(&self) -> Result<()> {
        match &*self.lock_state()? {
            ExecutionState::Failed(error) => Err(error.clone()),
            ExecutionState::Finalizing => Err(self.context.error(
                "first_inference_profile_state",
                "profiling finalization is already in progress",
            )),
            ExecutionState::Pending(_) | ExecutionState::Attested { .. } => Ok(()),
        }
    }

    /// Returns whether the next CUDA inference must be exactly one ORT Run so
    /// its session-wide profile can be reconciled one-to-one with the final
    /// optimized graph. Callers hold their model mutex while consulting this
    /// state, then execute and seal one real item before any batch remainder.
    pub(super) fn requires_single_run_profile(&self) -> Result<bool> {
        match &*self.lock_state()? {
            ExecutionState::Pending(transaction) => Ok(transaction.is_some()),
            ExecutionState::Attested { .. } => Ok(false),
            ExecutionState::Failed(error) => Err(error.clone()),
            ExecutionState::Finalizing => Err(self.context.error(
                "first_inference_profile_state",
                "profiling finalization is already in progress",
            )),
        }
    }

    /// Finalizes profiling at most once, after the caller has completed and
    /// synchronized a successful real inference and materialized its output.
    pub(super) fn complete_first_inference(
        &self,
        end_profiling: impl FnOnce() -> ort::Result<String>,
    ) -> Result<()> {
        let mut state = self.lock_state()?;
        let transaction = match std::mem::replace(&mut *state, ExecutionState::Finalizing) {
            ExecutionState::Pending(transaction) => transaction,
            attested @ ExecutionState::Attested { .. } => {
                *state = attested;
                return Ok(());
            }
            ExecutionState::Failed(error) => {
                *state = ExecutionState::Failed(error.clone());
                return Err(error);
            }
            ExecutionState::Finalizing => {
                let error = self.context.error(
                    "first_inference_profile_state",
                    "profiling finalization is already in progress",
                );
                self.log_terminal_failure(&error);
                *state = ExecutionState::Failed(error.clone());
                return Err(error);
            }
        };

        let result = match self.context.provider_policy {
            OnnxProviderPolicy::CudaFailLoud => match transaction {
                Some(transaction) => self.cuda_profile_attestation(transaction, end_profiling),
                None => Err(self.context.error(
                    "first_inference_evidence_transaction",
                    "CUDA FastEmbed session has no pending durable evidence transaction",
                )),
            },
            OnnxProviderPolicy::CpuExplicit => {
                if transaction.is_some() {
                    Err(self.context.error(
                        "first_inference_evidence_transaction",
                        "explicit-CPU FastEmbed session unexpectedly retained a CUDA evidence transaction",
                    ))
                } else {
                    Ok((
                        self.assignment_attestation(
                            "onnx_api24_committed_session_after_first_real_synchronized_inference",
                            self.assignment.per_provider.clone(),
                            None,
                        ),
                        None,
                    ))
                }
            }
        };
        match result {
            Ok((attestation, profile_artifact)) => {
                eprintln!(
                    "CALYX_ONNX_RUNTIME phase=fastembed_execution_attestation_committed label={} model={} provider={} device={} total_nodes={} cpu_nodes={}",
                    self.context.label,
                    self.context.model_code,
                    attestation.provider,
                    attestation.device,
                    attestation.total_compute_nodes.unwrap_or(0),
                    attestation.cpu_compute_nodes.unwrap_or(0)
                );
                *state = ExecutionState::Attested {
                    attestation,
                    _profile_artifact: profile_artifact,
                };
                Ok(())
            }
            Err(error) => {
                self.log_terminal_failure(&error);
                *state = ExecutionState::Failed(error.clone());
                Err(error)
            }
        }
    }

    pub(super) fn execution_attestation(&self) -> Result<Option<RuntimeExecutionAttestation>> {
        match &*self.lock_state()? {
            ExecutionState::Pending(_) | ExecutionState::Finalizing => Ok(None),
            ExecutionState::Attested { attestation, .. } => Ok(Some(attestation.clone())),
            ExecutionState::Failed(error) => Err(error.clone()),
        }
    }

    fn cuda_profile_attestation(
        &self,
        mut transaction: OnnxEvidenceTransaction,
        end_profiling: impl FnOnce() -> ort::Result<String>,
    ) -> Result<(RuntimeExecutionAttestation, Option<DurableOnnxArtifact>)> {
        let trace_path = end_profiling()
            .map_err(|error| self.context.error("first_inference_end_profiling", error))?;
        let profile_artifact = transaction
            .publish_profile(Path::new(&trace_path))
            .map_err(|error| {
                self.context
                    .preserve("first_inference_profile_publish", error)
            })?;
        let trace = std::str::from_utf8(&profile_artifact.bytes).map_err(|error| {
            self.context.error(
                "first_inference_profile_parse",
                format!(
                    "profile {} is not UTF-8: {error}",
                    profile_artifact.final_path.display()
                ),
            )
        })?;
        let trace_sha256 = profile_artifact.sha256.clone();
        let optimized_receipt = self.optimized_graph_receipt.as_ref().ok_or_else(|| {
            self.context.error(
                "first_inference_optimized_graph_receipt",
                "CUDA FastEmbed session has no retained optimized-graph receipt",
            )
        })?;
        let (optimized_path, optimized_bytes) = self.context.snapshot_optimized_graph()?;
        let observed_receipt = inspect_optimized_graph(&optimized_path, &optimized_bytes)
            .map_err(|error| self.context.preserve("optimized_graph_reinspection", error))?;
        if observed_receipt != *optimized_receipt {
            return Err(self.context.error(
                "optimized_graph_reinspection",
                format!(
                    "optimized graph drifted after session quarantine: retained={} observed={}",
                    optimized_receipt.optimized_graph_sha256,
                    observed_receipt.optimized_graph_sha256
                ),
            ));
        }
        let profile =
            reconcile_profile_with_optimized_graph(&self.context.label, trace, optimized_receipt)
                .map_err(|error| {
                self.context
                    .preserve("first_inference_profile_reconciliation", error)
            })?;
        let contract = classify_profiled_cuda_placement(
            &self.assignment,
            optimized_receipt,
            &optimized_bytes,
            &profile,
            &trace_sha256,
        )
        .map_err(|error| {
            self.context
                .preserve("first_inference_placement_classification", error)
        })?;
        eprintln!(
            "CALYX_ONNX_RUNTIME phase=fastembed_first_inference_attested label={} model={} provider={} api24_nodes={} cuda_compute_nodes={} cpu_metadata_nodes={} profile_nodes={} placement_contract_sha256={} profile_path={} profile_sha256={}",
            self.context.label,
            self.context.model_code,
            self.context.provider_policy.as_str(),
            self.assignment.total_nodes,
            profile.cuda_compute_nodes,
            profile.cpu_metadata_nodes,
            profile.total_nodes,
            contract.contract_sha256,
            profile_artifact.final_path.display(),
            trace_sha256
        );
        let profile_path = profile_artifact.final_path.to_str().ok_or_else(|| {
            self.context.error(
                "first_inference_profile_path_validation",
                format!(
                    "profile path {} is not valid UTF-8; lossy execution evidence is forbidden",
                    profile_artifact.final_path.display()
                ),
            )
        })?;
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
            let proof = contract
                .cpu_metadata_proofs
                .get(&node.name)
                .ok_or_else(|| {
                    self.context.error(
                        "first_inference_placement_contract",
                        format!(
                            "placement contract {} authorizes CPU node {:?} without a retained static proof",
                            contract.contract_sha256, node.name
                        ),
                    )
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
            retained_stream: self.retained_stream.clone().ok_or_else(|| {
                self.context.error(
                    "first_inference_retained_stream",
                    "CUDA FastEmbed execution completed without retained stream evidence",
                )
            })?,
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
            profile_bytes: u64::try_from(profile_artifact.bytes.len()).map_err(|_| {
                self.context.error(
                    "first_inference_profile_size",
                    "durable first-inference profile exceeds the u64 evidence contract",
                )
            })?,
            profile_sha256: trace_sha256,
        };
        let attestation = RuntimeExecutionAttestation {
            runtime: super::execution_attestation::ONNX_FASTEMBED_RUNTIME_ID.to_string(),
            provider: format!(
                "partition={};final={};profile={};placement_contract={}",
                structured.api24_partition.providers,
                structured.final_graph_placement.providers,
                structured.first_inference_profile.providers,
                structured.placement_contract_sha256
            ),
            device: self.context.device.clone(),
            loader_dtype: None,
            compute_dtype: None,
            evidence: super::execution_attestation::serialize_cuda_onnx_execution_evidence(
                &structured,
            )?,
            total_compute_nodes: Some(contract.cuda_compute_node_count()),
            cpu_compute_nodes: Some(0),
        };
        Ok((attestation, Some(profile_artifact)))
    }

    fn assignment_attestation(
        &self,
        evidence_mechanism: &str,
        provider: String,
        profile: Option<(&str, &str)>,
    ) -> RuntimeExecutionAttestation {
        let profile_evidence = profile
            .map(|(path, sha256)| format!(";profile_path={path};profile_sha256={sha256}"))
            .unwrap_or_default();
        RuntimeExecutionAttestation {
            runtime: super::execution_attestation::ONNX_FASTEMBED_RUNTIME_ID.to_string(),
            provider,
            device: self.context.device.clone(),
            loader_dtype: None,
            compute_dtype: None,
            evidence: format!(
                "{};model={};path={};weights_sha256={};artifact_bytes={};model_sha256={};tokenizer_sha256={};external_sha256={};profile_prefix={};frozen_operators={};assigned_operators={}{}",
                evidence_mechanism,
                self.context.model_code,
                self.context.model_path.display(),
                self.context.weights_sha256,
                self.context.artifact_bytes,
                self.context.model_sha256,
                self.context.tokenizer_sha256,
                self.context.external_sha256,
                self.context
                    .profile_prefix
                    .as_ref()
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(|| "none".to_string()),
                self.context.frozen_operators,
                self.assignment.per_provider_operators,
                profile_evidence
            ),
            total_compute_nodes: Some(self.assignment.total_nodes),
            cpu_compute_nodes: Some(self.assignment.cpu_nodes),
        }
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, ExecutionState>> {
        self.state.lock().map_err(|_| {
            self.context.error(
                "execution_attestation_state",
                "FastEmbed execution-attestation mutex is poisoned",
            )
        })
    }

    fn log_terminal_failure(&self, error: &CalyxError) {
        eprintln!(
            "CALYX_ONNX_RUNTIME phase=fastembed_execution_terminal_failure label={} model={} code={} message={} remediation={}",
            self.context.label,
            self.context.model_code,
            error.code,
            error.message,
            error.remediation
        );
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

fn validate_explicit_cpu_assignment(
    context: &FastembedModelContext,
    assignment: &CommittedGraphAssignment,
) -> Result<()> {
    validate_partition_receipt(assignment, &context.label, false)
        .map_err(|error| context.preserve("api24_partition_validation", error))?;
    if assignment.total_nodes == 0 {
        return Err(context.error(
            "api24_graph_assignment_validation",
            "API-24 graph assignment reported zero compute nodes",
        ));
    }
    if context.provider_policy != OnnxProviderPolicy::CpuExplicit
        || assignment.cpu_nodes != assignment.total_nodes
        || assignment.cuda_nodes != 0
        || assignment
            .nodes
            .iter()
            .any(|node| node.provider != "CPUExecutionProvider")
    {
        return Err(context.error(
            "api24_graph_assignment_validation",
            format!(
                "explicit CPU session requires every exact committed node on CPUExecutionProvider, observed total={} cuda={} cpu={} providers={} nodes={}",
                assignment.total_nodes,
                assignment.cuda_nodes,
                assignment.cpu_nodes,
                assignment.per_provider,
                assignment.per_provider_nodes
            ),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FrozenModelInspection {
    pub(super) operator_inventory: String,
    pub(super) external_locations: BTreeSet<String>,
    pub(super) external_references: Vec<ExternalTensorReference>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ExternalTensorReference {
    pub(super) location: String,
    pub(super) offset: Option<u64>,
    pub(super) length: Option<u64>,
    pub(super) checksum: Option<String>,
}

#[derive(Default)]
struct InspectionBuilder {
    operators: BTreeMap<String, u64>,
    external_locations: BTreeSet<String>,
    external_references: Vec<ExternalTensorReference>,
}

pub(super) fn inspect_frozen_model(
    bytes: &[u8],
) -> std::result::Result<FrozenModelInspection, String> {
    if bytes.is_empty() {
        return Err("frozen ONNX graph is empty".to_string());
    }
    let mut model = ProtoCursor::new(bytes);
    let mut inspection = InspectionBuilder::default();
    let mut has_main_graph = false;
    while let Some(field) = model.next_field()? {
        match field.number {
            7 => {
                if has_main_graph {
                    return Err("ModelProto contains more than one graph field".to_string());
                }
                has_main_graph = true;
                parse_graph(field.bytes("ModelProto.graph")?, 0, &mut inspection)?;
            }
            20 => parse_training_info(field.bytes("ModelProto.training_info")?, &mut inspection)?,
            25 => parse_function(field.bytes("ModelProto.functions")?, &mut inspection)?,
            _ => {}
        }
    }
    if !has_main_graph {
        return Err("ModelProto has no graph field".to_string());
    }
    if inspection.operators.is_empty() {
        return Err("frozen ONNX graph contains no operator nodes".to_string());
    }
    let operator_inventory = inspection
        .operators
        .into_iter()
        .map(|(operator, count)| format!("{operator}:{count}"))
        .collect::<Vec<_>>()
        .join(",");
    Ok(FrozenModelInspection {
        operator_inventory,
        external_locations: inspection.external_locations,
        external_references: inspection.external_references,
    })
}

fn parse_training_info(
    bytes: &[u8],
    inspection: &mut InspectionBuilder,
) -> std::result::Result<(), String> {
    let mut training_info = ProtoCursor::new(bytes);
    let mut has_initialization = false;
    let mut has_algorithm = false;
    while let Some(field) = training_info.next_field()? {
        match field.number {
            1 => {
                if has_initialization {
                    return Err(
                        "TrainingInfoProto contains more than one initialization graph".to_string(),
                    );
                }
                has_initialization = true;
                parse_graph(
                    field.bytes("TrainingInfoProto.initialization")?,
                    0,
                    inspection,
                )?;
            }
            2 => {
                if has_algorithm {
                    return Err(
                        "TrainingInfoProto contains more than one algorithm graph".to_string()
                    );
                }
                has_algorithm = true;
                parse_graph(field.bytes("TrainingInfoProto.algorithm")?, 0, inspection)?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn parse_function(
    bytes: &[u8],
    inspection: &mut InspectionBuilder,
) -> std::result::Result<(), String> {
    let mut function = ProtoCursor::new(bytes);
    while let Some(field) = function.next_field()? {
        match field.number {
            7 => parse_node(field.bytes("FunctionProto.node")?, 0, inspection)?,
            11 => parse_attribute(field.bytes("FunctionProto.attribute_proto")?, 0, inspection)?,
            _ => {}
        }
    }
    Ok(())
}

fn parse_graph(
    bytes: &[u8],
    depth: usize,
    inspection: &mut InspectionBuilder,
) -> std::result::Result<(), String> {
    if depth > MAX_PROTO_RECURSION {
        return Err(format!(
            "ONNX nested graph depth exceeds {MAX_PROTO_RECURSION}"
        ));
    }
    let mut graph = ProtoCursor::new(bytes);
    while let Some(field) = graph.next_field()? {
        match field.number {
            1 => parse_node(field.bytes("GraphProto.node")?, depth, inspection)?,
            5 => parse_tensor(field.bytes("GraphProto.initializer")?, inspection)?,
            15 => parse_sparse_tensor(field.bytes("GraphProto.sparse_initializer")?, inspection)?,
            _ => {}
        }
    }
    Ok(())
}

fn parse_node(
    bytes: &[u8],
    depth: usize,
    inspection: &mut InspectionBuilder,
) -> std::result::Result<(), String> {
    let mut node = ProtoCursor::new(bytes);
    let mut operator = None;
    let mut domain = None;
    let mut attributes = Vec::new();
    while let Some(field) = node.next_field()? {
        match field.number {
            4 => {
                if operator
                    .replace(field.string("NodeProto.op_type")?)
                    .is_some()
                {
                    return Err("NodeProto contains more than one op_type field".to_string());
                }
            }
            5 => attributes.push(field.bytes("NodeProto.attribute")?),
            7 => {
                if domain.replace(field.string("NodeProto.domain")?).is_some() {
                    return Err("NodeProto contains more than one domain field".to_string());
                }
            }
            _ => {}
        }
    }
    let operator = operator
        .filter(|operator| !operator.is_empty())
        .ok_or_else(|| "ONNX NodeProto has no non-empty op_type".to_string())?;
    let key = domain
        .filter(|domain| !domain.is_empty())
        .map(|domain| format!("{domain}::{operator}"))
        .unwrap_or_else(|| operator.to_string());
    let count = inspection.operators.entry(key).or_default();
    *count = count
        .checked_add(1)
        .ok_or_else(|| "ONNX operator count exceeds u64".to_string())?;
    for attribute in attributes {
        parse_attribute(attribute, depth, inspection)?;
    }
    Ok(())
}

fn parse_attribute(
    bytes: &[u8],
    depth: usize,
    inspection: &mut InspectionBuilder,
) -> std::result::Result<(), String> {
    let mut attribute = ProtoCursor::new(bytes);
    while let Some(field) = attribute.next_field()? {
        match field.number {
            5 => parse_tensor(field.bytes("AttributeProto.t")?, inspection)?,
            6 => parse_graph(
                field.bytes("AttributeProto.g")?,
                next_graph_depth(depth)?,
                inspection,
            )?,
            10 => parse_tensor(field.bytes("AttributeProto.tensors")?, inspection)?,
            11 => parse_graph(
                field.bytes("AttributeProto.graphs")?,
                next_graph_depth(depth)?,
                inspection,
            )?,
            22 => parse_sparse_tensor(field.bytes("AttributeProto.sparse_tensor")?, inspection)?,
            23 => parse_sparse_tensor(field.bytes("AttributeProto.sparse_tensors")?, inspection)?,
            _ => {}
        }
    }
    Ok(())
}

fn next_graph_depth(depth: usize) -> std::result::Result<usize, String> {
    depth
        .checked_add(1)
        .filter(|depth| *depth <= MAX_PROTO_RECURSION)
        .ok_or_else(|| format!("ONNX nested graph depth exceeds {MAX_PROTO_RECURSION}"))
}

fn parse_sparse_tensor(
    bytes: &[u8],
    inspection: &mut InspectionBuilder,
) -> std::result::Result<(), String> {
    let mut sparse = ProtoCursor::new(bytes);
    let mut has_values = false;
    let mut has_indices = false;
    while let Some(field) = sparse.next_field()? {
        match field.number {
            1 => {
                if has_values {
                    return Err(
                        "SparseTensorProto contains more than one values tensor".to_string()
                    );
                }
                has_values = true;
                parse_tensor(field.bytes("SparseTensorProto.values")?, inspection)?;
            }
            2 => {
                if has_indices {
                    return Err(
                        "SparseTensorProto contains more than one indices tensor".to_string()
                    );
                }
                has_indices = true;
                parse_tensor(field.bytes("SparseTensorProto.indices")?, inspection)?;
            }
            _ => {}
        }
    }
    if !has_values || !has_indices {
        return Err("SparseTensorProto requires values and indices tensors".to_string());
    }
    Ok(())
}

fn parse_tensor(
    bytes: &[u8],
    inspection: &mut InspectionBuilder,
) -> std::result::Result<(), String> {
    let mut tensor = ProtoCursor::new(bytes);
    let mut external_data = BTreeMap::<String, String>::new();
    let mut data_location = None;
    let mut inline_data_fields = BTreeSet::<u32>::new();
    while let Some(field) = tensor.next_field()? {
        match field.number {
            4 | 5 | 6 | 7 | 9 | 10 | 11 => {
                inline_data_fields.insert(field.number);
            }
            13 => {
                let (key, value) =
                    parse_string_string_entry(field.bytes("TensorProto.external_data")?)?;
                if external_data.insert(key.clone(), value).is_some() {
                    return Err(format!(
                        "TensorProto.external_data contains duplicate key {key:?}"
                    ));
                }
            }
            14 => {
                let location = field.varint("TensorProto.data_location")?;
                if data_location.replace(location).is_some() {
                    return Err(
                        "TensorProto contains more than one data_location field".to_string()
                    );
                }
            }
            _ => {}
        }
    }

    if let Some(location) = data_location {
        if location > 1 {
            return Err(format!(
                "TensorProto.data_location has unknown enum value {location}"
            ));
        }
    }
    let is_external = data_location == Some(1);
    if is_external != !external_data.is_empty() {
        return Err(if is_external {
            "TensorProto declares data_location=EXTERNAL without external_data metadata".to_string()
        } else {
            "TensorProto has external_data metadata without data_location=EXTERNAL".to_string()
        });
    }
    if !is_external {
        return Ok(());
    }
    if !inline_data_fields.is_empty() {
        return Err(format!(
            "external TensorProto also declares inline data field(s) {inline_data_fields:?}"
        ));
    }

    for key in external_data.keys() {
        match key.as_str() {
            "location" | "offset" | "length" | "checksum" => {}
            "basepath" => {
                return Err(
                    "TensorProto.external_data key \"basepath\" is forbidden; locations must be canonical paths relative to the model"
                        .to_string(),
                );
            }
            _ => {
                return Err(format!(
                    "TensorProto.external_data contains unknown key {key:?}"
                ));
            }
        }
    }
    let location = external_data
        .remove("location")
        .ok_or_else(|| "TensorProto.external_data has no location".to_string())?;
    validate_external_location(&location)?;
    let offset = external_data
        .remove("offset")
        .map(|value| parse_external_u64("offset", &value))
        .transpose()?;
    let length = external_data
        .remove("length")
        .map(|value| parse_external_u64("length", &value))
        .transpose()?;
    let checksum = external_data
        .remove("checksum")
        .map(|value| validate_external_checksum(&value))
        .transpose()?;
    debug_assert!(external_data.is_empty());

    inspection.external_locations.insert(location.clone());
    inspection
        .external_references
        .push(ExternalTensorReference {
            location,
            offset,
            length,
            checksum,
        });
    Ok(())
}

fn parse_string_string_entry(bytes: &[u8]) -> std::result::Result<(String, String), String> {
    let mut entry = ProtoCursor::new(bytes);
    let mut key = None;
    let mut value = None;
    while let Some(field) = entry.next_field()? {
        match field.number {
            1 => {
                let field = field.string("StringStringEntryProto.key")?;
                if key.replace(field.to_string()).is_some() {
                    return Err(
                        "StringStringEntryProto contains more than one key field".to_string()
                    );
                }
            }
            2 => {
                let field = field.string("StringStringEntryProto.value")?;
                if value.replace(field.to_string()).is_some() {
                    return Err(
                        "StringStringEntryProto contains more than one value field".to_string()
                    );
                }
            }
            _ => {}
        }
    }
    let key = key.ok_or_else(|| "StringStringEntryProto has no key".to_string())?;
    if key.is_empty() {
        return Err("StringStringEntryProto key is empty".to_string());
    }
    let value = value.ok_or_else(|| "StringStringEntryProto has no value".to_string())?;
    Ok((key, value))
}

fn validate_external_location(location: &str) -> std::result::Result<(), String> {
    if location.is_empty()
        || location.starts_with('/')
        || location.contains('\\')
        || location.chars().any(char::is_control)
    {
        return Err(format!(
            "TensorProto.external_data location must be a non-empty relative POSIX path: {location:?}"
        ));
    }
    if location
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == ".." || part.contains(':'))
    {
        return Err(format!(
            "TensorProto.external_data location is not a canonical relative POSIX path: {location:?}"
        ));
    }
    Ok(())
}

fn parse_external_u64(key: &str, value: &str) -> std::result::Result<u64, String> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!(
            "TensorProto.external_data {key} must be a non-empty unsigned decimal integer: {value:?}"
        ));
    }
    value
        .parse::<u64>()
        .map_err(|error| format!("TensorProto.external_data {key} exceeds u64: {value:?}: {error}"))
}

fn validate_external_checksum(value: &str) -> std::result::Result<String, String> {
    if value.len() != 40 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "TensorProto.external_data checksum must be exactly 40 hexadecimal SHA1 characters: {value:?}"
        ));
    }
    Ok(value.to_ascii_lowercase())
}

struct ProtoField<'a> {
    number: u32,
    value: ProtoValue<'a>,
}

impl<'a> ProtoField<'a> {
    fn bytes(self, label: &str) -> std::result::Result<&'a [u8], String> {
        match self.value {
            ProtoValue::Bytes(bytes) => Ok(bytes),
            _ => Err(format!("{label} is not length-delimited")),
        }
    }

    fn string(self, label: &str) -> std::result::Result<&'a str, String> {
        std::str::from_utf8(self.bytes(label)?)
            .map_err(|error| format!("{label} is not UTF-8: {error}"))
    }

    fn varint(self, label: &str) -> std::result::Result<u64, String> {
        match self.value {
            ProtoValue::Varint(value) => Ok(value),
            _ => Err(format!("{label} is not a varint")),
        }
    }
}

enum ProtoValue<'a> {
    Varint(u64),
    Fixed,
    Bytes(&'a [u8]),
}

struct ProtoCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ProtoCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn next_field(&mut self) -> std::result::Result<Option<ProtoField<'a>>, String> {
        if self.offset == self.bytes.len() {
            return Ok(None);
        }
        let key = self.varint()?;
        let number =
            u32::try_from(key >> 3).map_err(|_| "protobuf field number exceeds u32".to_string())?;
        if number == 0 {
            return Err("protobuf field number is zero".to_string());
        }
        let value = match key & 0x07 {
            0 => ProtoValue::Varint(self.varint()?),
            1 => {
                self.advance(8)?;
                ProtoValue::Fixed
            }
            2 => {
                let length = usize::try_from(self.varint()?)
                    .map_err(|_| "protobuf length exceeds usize".to_string())?;
                let start = self.offset;
                self.advance(length)?;
                ProtoValue::Bytes(&self.bytes[start..self.offset])
            }
            5 => {
                self.advance(4)?;
                ProtoValue::Fixed
            }
            wire => return Err(format!("unsupported protobuf wire type {wire}")),
        };
        Ok(Some(ProtoField { number, value }))
    }

    fn varint(&mut self) -> std::result::Result<u64, String> {
        let mut value = 0u64;
        for shift in (0..70).step_by(7) {
            let byte = *self
                .bytes
                .get(self.offset)
                .ok_or_else(|| "truncated protobuf varint".to_string())?;
            self.offset += 1;
            if shift == 63 && byte > 1 {
                return Err("protobuf varint exceeds u64".to_string());
            }
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err("protobuf varint exceeds ten bytes".to_string())
    }

    fn advance(&mut self, length: usize) -> std::result::Result<(), String> {
        self.offset = self
            .offset
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| "protobuf field extends past end of input".to_string())?;
        Ok(())
    }
}

fn hex_sha256(hash: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut rendered = String::with_capacity(64);
    for byte in hash {
        rendered.push(char::from(HEX[usize::from(byte >> 4)]));
        rendered.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    rendered
}
