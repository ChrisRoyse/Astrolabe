use crate::get_cache_dir;
use ort::execution_providers::ExecutionProviderDispatch;
use ort::session::builder::SessionBuilder;
use std::path::PathBuf;

const GRAPH_ASSIGNMENT_CONFIG: &str = "session.record_ep_graph_assignment_info";

/// Applied ONNX Runtime session policy.
///
/// CUDA sessions are fail-closed: every graph node must be assigned outside
/// the implicit CPU execution provider, and the first real inference is
/// recorded so the caller can independently attest per-node placement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionPolicy {
    /// No execution policy was selected. Session construction refuses this state.
    Unspecified,
    /// Require one explicit CPU execution provider.
    ExplicitCpu,
    /// Require complete non-CPU graph placement and record provider assignment.
    CudaNoCpuFallback {
        graph_assignment_profile_path: PathBuf,
    },
}

impl SessionPolicy {
    pub const fn explicit_cpu() -> Self {
        Self::ExplicitCpu
    }

    pub fn cuda_no_cpu_fallback(graph_assignment_profile_path: impl Into<PathBuf>) -> Self {
        Self::CudaNoCpuFallback {
            graph_assignment_profile_path: graph_assignment_profile_path.into(),
        }
    }

    pub(crate) fn validate_execution_providers(
        &self,
        execution_providers: &[ExecutionProviderDispatch],
    ) -> anyhow::Result<ValidatedSessionPolicy> {
        match self {
            Self::Unspecified => Err(policy_failure(
                "UNSPECIFIED",
                "session policy was not selected",
            )),
            Self::ExplicitCpu => {
                require_exact_provider::<ort::ep::CPU>(execution_providers, "CPU")?;
                Ok(ValidatedSessionPolicy::ExplicitCpu)
            }
            Self::CudaNoCpuFallback {
                graph_assignment_profile_path,
            } => {
                require_exact_provider::<ort::ep::CUDA>(execution_providers, "CUDA")?;
                if graph_assignment_profile_path.as_os_str().is_empty() {
                    return Err(policy_failure(
                        "PROFILE_PATH_EMPTY",
                        "CUDA graph-assignment profile path is empty",
                    ));
                }
                Ok(ValidatedSessionPolicy::CudaNoCpuFallback {
                    graph_assignment_profile_path: graph_assignment_profile_path.clone(),
                })
            }
        }
    }
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self::Unspecified
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ValidatedSessionPolicy {
    ExplicitCpu,
    CudaNoCpuFallback {
        graph_assignment_profile_path: PathBuf,
    },
}

impl ValidatedSessionPolicy {
    pub(crate) const fn label(&self) -> &'static str {
        match self {
            Self::ExplicitCpu => "cpu:explicit,graph_assignment",
            Self::CudaNoCpuFallback { .. } => "cuda:no_cpu_fallback,graph_assignment_profile",
        }
    }

    pub(crate) fn apply_to(&self, builder: SessionBuilder) -> anyhow::Result<SessionBuilder> {
        let result = match self {
            Self::ExplicitCpu => builder.with_config_entry(GRAPH_ASSIGNMENT_CONFIG, "1"),
            Self::CudaNoCpuFallback {
                graph_assignment_profile_path,
            } => builder
                .with_disable_cpu_fallback()
                .and_then(|builder| builder.with_config_entry(GRAPH_ASSIGNMENT_CONFIG, "1"))
                .and_then(|builder| builder.with_profiling(graph_assignment_profile_path)),
        };
        result.map_err(|error| {
            policy_failure(
                "APPLY_FAILED",
                format!("policy={} reason={error}", self.label()),
            )
        })
    }
}

fn require_exact_provider<E: ort::ep::ExecutionProvider>(
    execution_providers: &[ExecutionProviderDispatch],
    expected: &'static str,
) -> anyhow::Result<()> {
    if execution_providers.len() != 1 {
        return Err(policy_failure(
            "PROVIDER_COUNT_MISMATCH",
            format!(
                "policy requires exactly one {expected} execution provider, observed count={} providers={execution_providers:?}",
                execution_providers.len()
            ),
        ));
    }
    if execution_providers[0].downcast_ref::<E>().is_none() {
        return Err(policy_failure(
            "PROVIDER_TYPE_MISMATCH",
            format!(
                "policy requires exactly one {expected} execution provider, observed providers={execution_providers:?}"
            ),
        ));
    }
    Ok(())
}

fn policy_failure(code: &'static str, detail: impl std::fmt::Display) -> anyhow::Error {
    anyhow::Error::msg(format!(
        "FASTEMBED_SESSION_POLICY[{code}] detail={detail}; remediation=select SessionPolicy::explicit_cpu with exactly one CPU execution provider, or SessionPolicy::cuda_no_cpu_fallback with exactly one CUDA execution provider and a non-empty profile path"
    ))
}

pub trait HasMaxLength {
    const MAX_LENGTH: usize;
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct InitOptionsWithLength<M> {
    pub model_name: M,
    pub execution_providers: Vec<ExecutionProviderDispatch>,
    pub session_policy: SessionPolicy,
    pub cache_dir: PathBuf,
    pub show_download_progress: bool,
    pub max_length: usize,
    /// Number of intra-op threads for ONNX Runtime. `None` (the default) uses
    /// every available CPU core via `std::thread::available_parallelism`.
    /// Set this to cap CPU usage (e.g. on laptops) at the cost of throughput.
    pub intra_threads: Option<usize>,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct InitOptions<M> {
    pub model_name: M,
    pub execution_providers: Vec<ExecutionProviderDispatch>,
    pub session_policy: SessionPolicy,
    pub cache_dir: PathBuf,
    pub show_download_progress: bool,
    /// Number of intra-op threads for ONNX Runtime. `None` (the default) uses
    /// every available CPU core via `std::thread::available_parallelism`.
    /// Set this to cap CPU usage (e.g. on laptops) at the cost of throughput.
    pub intra_threads: Option<usize>,
}

impl<M: Default + HasMaxLength> Default for InitOptionsWithLength<M> {
    fn default() -> Self {
        Self {
            model_name: M::default(),
            execution_providers: Default::default(),
            session_policy: SessionPolicy::default(),
            cache_dir: get_cache_dir().into(),
            show_download_progress: true,
            max_length: M::MAX_LENGTH,
            intra_threads: None,
        }
    }
}

impl<M: Default> Default for InitOptions<M> {
    fn default() -> Self {
        Self {
            model_name: M::default(),
            execution_providers: Default::default(),
            session_policy: SessionPolicy::default(),
            cache_dir: get_cache_dir().into(),
            show_download_progress: true,
            intra_threads: None,
        }
    }
}

impl<M: Default + HasMaxLength> InitOptionsWithLength<M> {
    /// Create a new InitOptionsWithLength with the given model name
    pub fn new(model_name: M) -> Self {
        Self {
            model_name,
            ..Default::default()
        }
    }

    /// Set the maximum length
    pub fn with_max_length(mut self, max_length: usize) -> Self {
        self.max_length = max_length;
        self
    }

    /// Set the cache directory for the model file
    pub fn with_cache_dir(mut self, cache_dir: PathBuf) -> Self {
        self.cache_dir = cache_dir;
        self
    }

    /// Set the execution providers for the model
    pub fn with_execution_providers(
        mut self,
        execution_providers: Vec<ExecutionProviderDispatch>,
    ) -> Self {
        self.execution_providers = execution_providers;
        self
    }

    /// Apply an explicit ONNX Runtime session policy.
    pub fn with_session_policy(mut self, session_policy: SessionPolicy) -> Self {
        self.session_policy = session_policy;
        self
    }

    /// Set the number of intra-op threads ONNX Runtime uses. By default
    /// (`None`) all available CPU cores are used; capping this limits CPU
    /// usage at the cost of per-inference throughput.
    pub fn with_intra_threads(mut self, intra_threads: usize) -> Self {
        self.intra_threads = Some(intra_threads);
        self
    }

    /// Set whether to show download progress
    pub fn with_show_download_progress(mut self, show_download_progress: bool) -> Self {
        self.show_download_progress = show_download_progress;
        self
    }
}

impl<M: Default> InitOptions<M> {
    /// Create a new InitOptions with the given model name
    pub fn new(model_name: M) -> Self {
        Self {
            model_name,
            ..Default::default()
        }
    }

    /// Set the cache directory for the model file
    pub fn with_cache_dir(mut self, cache_dir: PathBuf) -> Self {
        self.cache_dir = cache_dir;
        self
    }

    /// Set the execution providers for the model
    pub fn with_execution_providers(
        mut self,
        execution_providers: Vec<ExecutionProviderDispatch>,
    ) -> Self {
        self.execution_providers = execution_providers;
        self
    }

    /// Apply an explicit ONNX Runtime session policy.
    pub fn with_session_policy(mut self, session_policy: SessionPolicy) -> Self {
        self.session_policy = session_policy;
        self
    }

    /// Set the number of intra-op threads ONNX Runtime uses. By default
    /// (`None`) all available CPU cores are used; capping this limits CPU
    /// usage at the cost of per-inference throughput.
    pub fn with_intra_threads(mut self, intra_threads: usize) -> Self {
        self.intra_threads = Some(intra_threads);
        self
    }

    /// Set whether to show download progress
    pub fn with_show_download_progress(mut self, show_download_progress: bool) -> Self {
        self.show_download_progress = show_download_progress;
        self
    }
}
