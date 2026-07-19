//! Durable, content-addressed ONNX execution evidence.
//!
//! ORT requires writable paths for optimized-model serialization and profiling.
//! Those paths must not live under process TEMP because the execution receipt
//! outlives the launcher that created it. This module gives ORT exclusive
//! transaction-local paths under the model's real directory, snapshots the
//! resulting bytes through retained Windows handles, publishes them without
//! overwrite into a SHA-256 blob store, and reopens the published bytes before
//! returning them to the placement attestor.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use calyx_core::{CalyxError, Result};
use sha2::{Digest, Sha256};

pub(super) const STORE_DIRECTORY: &str = ".calyx-onnx-execution-v2";
pub(super) const MAX_OPTIMIZED_GRAPH_BYTES: u64 = 4 * 1024 * 1024 * 1024;
pub(super) const MAX_PROFILE_TRACE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ArtifactKind {
    OptimizedGraph,
    FirstInferenceProfile,
}

impl ArtifactKind {
    const fn directory(self) -> &'static str {
        match self {
            Self::OptimizedGraph => "optimized",
            Self::FirstInferenceProfile => "profiles",
        }
    }

    const fn extension(self) -> &'static str {
        match self {
            Self::OptimizedGraph => "onnx",
            Self::FirstInferenceProfile => "json",
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::OptimizedGraph => "optimized ONNX graph",
            Self::FirstInferenceProfile => "first-inference ONNX profile",
        }
    }

    const fn maximum_bytes(self) -> u64 {
        match self {
            Self::OptimizedGraph => MAX_OPTIMIZED_GRAPH_BYTES,
            Self::FirstInferenceProfile => MAX_PROFILE_TRACE_BYTES,
        }
    }
}

/// One published evidence blob retained against replacement for the lifetime
/// of its session.
#[derive(Debug)]
pub(super) struct DurableOnnxArtifact {
    pub(super) final_path: PathBuf,
    pub(super) bytes: Vec<u8>,
    pub(super) sha256: String,
    file: calyx_onnx_runtime::RetainedImmutableFile,
    ancestry: Vec<Arc<calyx_onnx_runtime::ImmutableDirectoryRoot>>,
}

impl DurableOnnxArtifact {
    pub(super) fn byte_len(&self) -> Result<u64> {
        u64::try_from(self.bytes.len()).map_err(|_| {
            artifact_error(
                "CALYX_ONNX_EVIDENCE_SIZE_OVERFLOW",
                format!(
                    "durable evidence artifact {} exceeds the u64 receipt contract",
                    self.final_path.display()
                ),
                "commission an ONNX artifact that fits the native process address space",
            )
        })
    }

    /// Independently reopens the content-addressed blob and proves the path,
    /// bytes, and digest still match the retained receipt.
    pub(super) fn revalidate(&self) -> Result<Vec<u8>> {
        let expected_bytes = self.byte_len()?;
        for root in &self.ancestry {
            root.attest_unchanged()?;
        }
        let root = self.ancestry.last().ok_or_else(|| {
            artifact_error(
                "CALYX_ONNX_EVIDENCE_ANCESTRY_MISSING",
                format!(
                    "durable evidence artifact {} lost its retained physical ancestry",
                    self.final_path.display()
                ),
                "terminally discard the session and rebuild the evidence receipt from one retained model-root chain",
            )
        })?;
        let snapshot = self.file.snapshot(Some(root.as_ref()), expected_bytes)?;
        for root in &self.ancestry {
            root.attest_unchanged()?;
        }
        let observed_sha256 = sha256_bytes(&snapshot.bytes);
        if snapshot.final_path != self.final_path
            || snapshot.bytes != self.bytes
            || observed_sha256 != self.sha256
        {
            return Err(artifact_error(
                "CALYX_ONNX_EVIDENCE_DRIFT",
                format!(
                    "durable ONNX evidence drifted: expected path={} bytes={} sha256={}, observed path={} bytes={} sha256={observed_sha256}",
                    self.final_path.display(),
                    self.bytes.len(),
                    self.sha256,
                    snapshot.final_path.display(),
                    snapshot.bytes.len()
                ),
                "terminally discard the session, preserve both byte inventories, and restore the exact content-addressed evidence blob",
            ));
        }
        Ok(snapshot.bytes)
    }
}

/// Exclusive writable paths used by one ORT session until its graph and first
/// profile have both been published.
#[derive(Debug)]
pub(super) struct OnnxEvidenceTransaction {
    transaction_directory: PathBuf,
    transaction_root: Option<Arc<calyx_onnx_runtime::ImmutableDirectoryRoot>>,
    optimized_graph_path: PathBuf,
    profile_prefix: PathBuf,
    model_root: Arc<calyx_onnx_runtime::ImmutableDirectoryRoot>,
    store_root: Arc<calyx_onnx_runtime::ImmutableDirectoryRoot>,
    _pending_root: Arc<calyx_onnx_runtime::ImmutableDirectoryRoot>,
    blobs_root: Arc<calyx_onnx_runtime::ImmutableDirectoryRoot>,
    blob_root: Arc<calyx_onnx_runtime::ImmutableDirectoryRoot>,
    optimized_published: bool,
    profile_published: bool,
}

impl OnnxEvidenceTransaction {
    pub(super) fn begin(model_file: &Path, label: &str) -> Result<Self> {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);

        let model_parent = model_file.parent().ok_or_else(|| {
            artifact_error(
                "CALYX_ONNX_EVIDENCE_MODEL_PATH_INVALID",
                format!(
                    "ONNX model path {} has no parent for its explicit evidence store",
                    model_file.display()
                ),
                "place the model in a writable, durable directory and retry",
            )
        })?;
        let model_root = Arc::new(calyx_onnx_runtime::open_immutable_directory(model_parent)?);
        let store_root = model_root.final_path().join(STORE_DIRECTORY);
        create_directory_component(&store_root)?;
        let store_root_handle = Arc::new(calyx_onnx_runtime::open_immutable_child_directory(
            &model_root,
            STORE_DIRECTORY.as_ref(),
        )?);
        let pending_root = store_root_handle.final_path().join("pending");
        create_directory_component(&pending_root)?;
        let pending_root_handle = Arc::new(calyx_onnx_runtime::open_immutable_child_directory(
            &store_root_handle,
            "pending".as_ref(),
        )?);
        let blobs_root = store_root_handle.final_path().join("blobs");
        create_directory_component(&blobs_root)?;
        let blobs_root_handle = Arc::new(calyx_onnx_runtime::open_immutable_child_directory(
            &store_root_handle,
            "blobs".as_ref(),
        )?);
        let blob_root = blobs_root_handle.final_path().join("sha256");
        create_directory_component(&blob_root)?;
        let blob_root_handle = Arc::new(calyx_onnx_runtime::open_immutable_child_directory(
            &blobs_root_handle,
            "sha256".as_ref(),
        )?);

        let label_hash = sha256_bytes(label.as_bytes());
        let transaction_name = loop {
            let sequence = SEQUENCE
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                    current.checked_add(1)
                })
                .map_err(|_| {
                    artifact_error(
                        "CALYX_ONNX_EVIDENCE_TRANSACTION_EXHAUSTED",
                        "ONNX evidence transaction sequence exhausted u64",
                        "restart the process and preserve the allocation diagnostics",
                    )
                })?;
            let candidate_name = format!("{}-{sequence}-{}", std::process::id(), &label_hash[..16]);
            let candidate = pending_root_handle.final_path().join(&candidate_name);
            match fs::create_dir(&candidate) {
                Ok(()) => break candidate_name,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(artifact_error(
                        "CALYX_ONNX_EVIDENCE_TRANSACTION_CREATE_FAILED",
                        format!(
                            "create exclusive ONNX evidence transaction {} failed: {error}",
                            candidate.display()
                        ),
                        "repair the model-directory evidence-store permissions and retry in a new process",
                    ));
                }
            }
        };
        let transaction_root = Arc::new(calyx_onnx_runtime::open_immutable_child_directory(
            &pending_root_handle,
            transaction_name.as_ref(),
        )?);
        let transaction_directory = transaction_root.final_path().to_path_buf();
        let optimized_graph_path = transaction_root.final_path().join("optimized.onnx");
        let profile_prefix = transaction_root.final_path().join("first-inference");
        Ok(Self {
            transaction_directory,
            transaction_root: Some(transaction_root),
            optimized_graph_path,
            profile_prefix,
            model_root,
            store_root: store_root_handle,
            _pending_root: pending_root_handle,
            blobs_root: blobs_root_handle,
            blob_root: blob_root_handle,
            optimized_published: false,
            profile_published: false,
        })
    }

    pub(super) fn optimized_graph_path(&self) -> &Path {
        &self.optimized_graph_path
    }

    pub(super) fn profile_prefix(&self) -> &Path {
        &self.profile_prefix
    }

    pub(super) fn publish_optimized_graph(&mut self) -> Result<DurableOnnxArtifact> {
        if self.optimized_published {
            return Err(artifact_error(
                "CALYX_ONNX_EVIDENCE_PHASE_INVALID",
                format!(
                    "optimized graph transaction {} was already published",
                    self.transaction_directory.display()
                ),
                "discard the session and create one fresh evidence transaction per ORT session",
            ));
        }
        let artifact = self.publish_path(
            ArtifactKind::OptimizedGraph,
            &self.optimized_graph_path,
            None,
        )?;
        self.optimized_published = true;
        Ok(artifact)
    }

    pub(super) fn publish_profile(&mut self, returned_path: &Path) -> Result<DurableOnnxArtifact> {
        if !self.optimized_published || self.profile_published {
            return Err(artifact_error(
                "CALYX_ONNX_EVIDENCE_PHASE_INVALID",
                format!(
                    "profile publication for {} requires exactly one preceding optimized graph and no preceding profile; optimized_published={} profile_published={}",
                    self.transaction_directory.display(),
                    self.optimized_published,
                    self.profile_published
                ),
                "discard the session and preserve the transaction directory for investigation",
            ));
        }
        let artifact = self.publish_path(
            ArtifactKind::FirstInferenceProfile,
            returned_path,
            Some(&self.profile_prefix),
        )?;
        self.profile_published = true;
        Ok(artifact)
    }

    fn publish_path(
        &self,
        kind: ArtifactKind,
        source_path: &Path,
        required_prefix: Option<&Path>,
    ) -> Result<DurableOnnxArtifact> {
        let transaction_root = self.transaction_root.as_ref().ok_or_else(|| {
            artifact_error(
                "CALYX_ONNX_EVIDENCE_TRANSACTION_ROOT_MISSING",
                format!(
                    "ONNX evidence transaction {} lost its retained root",
                    self.transaction_directory.display()
                ),
                "terminally discard the session and preserve its evidence directory",
            )
        })?;
        let source_bytes = fs::metadata(source_path)
            .map_err(|error| {
                artifact_error(
                    "CALYX_ONNX_EVIDENCE_SOURCE_MISSING",
                    format!(
                        "read {} metadata at {} failed: {error}",
                        kind.label(),
                        source_path.display()
                    ),
                    "preserve the ORT logs and repair mandatory evidence serialization before retrying",
                )
            })?
            .len();
        if source_bytes == 0 || source_bytes > kind.maximum_bytes() {
            return Err(artifact_error(
                "CALYX_ONNX_EVIDENCE_SOURCE_SIZE_INVALID",
                format!(
                    "{} at {} has {source_bytes} bytes outside the required 1..={} range",
                    kind.label(),
                    source_path.display(),
                    kind.maximum_bytes()
                ),
                "commission a bounded nonempty evidence artifact and retry",
            ));
        }
        let source = calyx_onnx_runtime::snapshot_immutable_file(
            source_path,
            Some(transaction_root.as_ref()),
            kind.maximum_bytes(),
        )?;
        match kind {
            ArtifactKind::OptimizedGraph => {
                if source_path != self.optimized_graph_path
                    || source.final_path != self.optimized_graph_path
                {
                    return Err(artifact_error(
                        "CALYX_ONNX_EVIDENCE_SOURCE_PATH_INVALID",
                        format!(
                            "optimized graph source must be exact transaction file {}, requested {} resolved {}",
                            self.optimized_graph_path.display(),
                            source_path.display(),
                            source.final_path.display()
                        ),
                        "preserve the transaction and repair ORT optimized-model serialization so it writes only the exact retained transaction path",
                    ));
                }
            }
            ArtifactKind::FirstInferenceProfile => {
                if source_path != source.final_path
                    || source.final_path.parent() != Some(transaction_root.final_path())
                {
                    return Err(artifact_error(
                        "CALYX_ONNX_EVIDENCE_PROFILE_PATH_INVALID",
                        format!(
                            "returned profile must be one exact direct transaction child: returned={} resolved={} transaction={}",
                            source_path.display(),
                            source.final_path.display(),
                            transaction_root.final_path().display()
                        ),
                        "preserve the returned path and repair ORT profiling serialization; nested, aliased, and reparse paths are forbidden",
                    ));
                }
            }
        }
        if let Some(prefix) = required_prefix {
            let expected_name = prefix
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| {
                    artifact_error(
                        "CALYX_ONNX_EVIDENCE_PROFILE_PREFIX_INVALID",
                        format!(
                            "profile prefix {} has no canonical UTF-8 name",
                            prefix.display()
                        ),
                        "use a canonical UTF-8 model/evidence directory",
                    )
                })?;
            let observed_name = source
                .final_path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| {
                    artifact_error(
                        "CALYX_ONNX_EVIDENCE_PROFILE_PATH_INVALID",
                        format!(
                            "returned profile {} has no canonical UTF-8 name",
                            source.final_path.display()
                        ),
                        "preserve the returned path and repair ORT profiling serialization",
                    )
                })?;
            let required_stem = format!("{expected_name}_");
            if !observed_name.starts_with(&required_stem)
                || !observed_name.ends_with(".json")
                || observed_name[required_stem.len()..observed_name.len() - 5].is_empty()
                || observed_name.chars().any(char::is_control)
            {
                return Err(artifact_error(
                    "CALYX_ONNX_EVIDENCE_PROFILE_PATH_INVALID",
                    format!(
                        "ORT returned profile {} outside strict direct-child grammar {}<nonempty>.json",
                        source.final_path.display(),
                        required_stem
                    ),
                    "terminally discard the session and repair the profiling path contract",
                ));
            }
        }
        let sha256 = sha256_bytes(&source.bytes);
        let kind_root_path = self.blob_root.final_path().join(kind.directory());
        create_directory_component(&kind_root_path)?;
        let kind_root = Arc::new(calyx_onnx_runtime::open_immutable_child_directory(
            &self.blob_root,
            kind.directory().as_ref(),
        )?);
        let final_parent = kind_root.final_path().join(&sha256[..2]);
        create_directory_component(&final_parent)?;
        let final_root = Arc::new(calyx_onnx_runtime::open_immutable_child_directory(
            &kind_root,
            sha256[..2].as_ref(),
        )?);
        let final_path = final_root
            .final_path()
            .join(format!("{sha256}.{}", kind.extension()));
        publish_without_overwrite(
            final_root.as_ref(),
            &final_path,
            &source.bytes,
            &sha256,
            kind,
        )?;
        let (final_file, final_snapshot) = calyx_onnx_runtime::retain_immutable_file(
            &final_path,
            Some(final_root.as_ref()),
            kind.maximum_bytes(),
        )?;
        let final_sha256 = sha256_bytes(&final_snapshot.bytes);
        if final_snapshot.bytes != source.bytes || final_sha256 != sha256 {
            return Err(artifact_error(
                "CALYX_ONNX_EVIDENCE_PUBLISH_MISMATCH",
                format!(
                    "published {} {} differs from transaction bytes: expected bytes={} sha256={sha256}, observed bytes={} sha256={final_sha256}",
                    kind.label(),
                    final_snapshot.final_path.display(),
                    source.bytes.len(),
                    final_snapshot.bytes.len()
                ),
                "quarantine both artifacts and repair the content-addressed publisher before retrying",
            ));
        }
        Ok(DurableOnnxArtifact {
            final_path: final_snapshot.final_path,
            bytes: final_snapshot.bytes,
            sha256,
            file: final_file,
            ancestry: vec![
                Arc::clone(&self.model_root),
                Arc::clone(&self.store_root),
                Arc::clone(&self.blobs_root),
                Arc::clone(&self.blob_root),
                kind_root,
                final_root,
            ],
        })
    }
}

impl Drop for OnnxEvidenceTransaction {
    fn drop(&mut self) {
        if self.optimized_published && self.profile_published {
            tracing::info!(
                transaction = %self.transaction_directory.display(),
                "durable ONNX evidence transaction published both required artifacts"
            );
        } else {
            tracing::error!(
                code = "CALYX_ONNX_EVIDENCE_TRANSACTION_INCOMPLETE",
                transaction = %self.transaction_directory.display(),
                optimized_published = self.optimized_published,
                profile_published = self.profile_published,
                remediation = "preserve this unreferenced pending directory for root-cause inspection; it is not accepted execution state",
                "ONNX evidence transaction ended before both required artifacts were published"
            );
        }
    }
}

fn publish_without_overwrite(
    final_root: &calyx_onnx_runtime::ImmutableDirectoryRoot,
    final_path: &Path,
    bytes: &[u8],
    sha256: &str,
    kind: ArtifactKind,
) -> Result<()> {
    static PUBLISH_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let sequence = PUBLISH_SEQUENCE
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .map_err(|_| {
            artifact_error(
                "CALYX_ONNX_EVIDENCE_PUBLISH_EXHAUSTED",
                "ONNX evidence publish sequence exhausted u64",
                "restart the process and preserve the publish diagnostics",
            )
        })?;
    let staging_path = final_root.final_path().join(format!(
        ".publish-{}-{sequence}.{}",
        std::process::id(),
        kind.extension()
    ));
    let mut staging = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&staging_path)
        .map_err(|error| {
            artifact_error(
                "CALYX_ONNX_EVIDENCE_STAGING_CREATE_FAILED",
                format!(
                    "create exclusive {} staging file {} failed: {error}",
                    kind.label(),
                    staging_path.display()
                ),
                "repair the durable evidence-store permissions and retry",
            )
        })?;
    staging.write_all(bytes).map_err(|error| {
        artifact_error(
            "CALYX_ONNX_EVIDENCE_STAGING_WRITE_FAILED",
            format!(
                "write {} staging file {} failed: {error}",
                kind.label(),
                staging_path.display()
            ),
            "preserve the storage diagnostics, repair the evidence volume, and retry",
        )
    })?;
    staging.sync_all().map_err(|error| {
        artifact_error(
            "CALYX_ONNX_EVIDENCE_STAGING_SYNC_FAILED",
            format!(
                "flush {} staging file {} failed: {error}",
                kind.label(),
                staging_path.display()
            ),
            "repair the evidence volume durability failure before retrying",
        )
    })?;
    drop(staging);

    match fs::hard_link(&staging_path, final_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = calyx_onnx_runtime::snapshot_immutable_file(
                final_path,
                Some(final_root),
                kind.maximum_bytes(),
            )?;
            let existing_sha256 = sha256_bytes(&existing.bytes);
            if existing.bytes != bytes || existing_sha256 != sha256 {
                return Err(artifact_error(
                    "CALYX_ONNX_EVIDENCE_CONTENT_ADDRESS_COLLISION",
                    format!(
                        "{} content address {} already exists with bytes={} sha256={existing_sha256}, expected bytes={} sha256={sha256}",
                        kind.label(),
                        existing.final_path.display(),
                        existing.bytes.len(),
                        bytes.len()
                    ),
                    "stop all writers, preserve both byte sequences, and investigate the evidence store before any session is admitted",
                ));
            }
        }
        Err(error) => {
            return Err(artifact_error(
                "CALYX_ONNX_EVIDENCE_PUBLISH_FAILED",
                format!(
                    "atomically publish {} {} failed: {error}",
                    kind.label(),
                    final_path.display()
                ),
                "repair same-volume hard-link support and evidence-store permissions; no copy or overwrite fallback is allowed",
            ));
        }
    }
    fs::remove_file(&staging_path).map_err(|error| {
        artifact_error(
            "CALYX_ONNX_EVIDENCE_STAGING_CLEANUP_FAILED",
            format!(
                "remove published staging link {} failed: {error}",
                staging_path.display()
            ),
            "preserve the published blob, repair evidence-store cleanup, and remove only the exact unreferenced staging link",
        )
    })
}

fn create_directory_component(path: &Path) -> Result<()> {
    match fs::create_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(artifact_error(
            "CALYX_ONNX_EVIDENCE_DIRECTORY_CREATE_FAILED",
            format!(
                "create exact durable ONNX evidence directory component {} failed: {error}",
                path.display()
            ),
            "place the model under a writable durable directory and repair each exact evidence-store path component",
        )),
    }
}

fn sha256_bytes(bytes: impl AsRef<[u8]>) -> String {
    format!("{:x}", Sha256::digest(bytes.as_ref()))
}

fn artifact_error(
    code: &'static str,
    message: impl Into<String>,
    remediation: &'static str,
) -> CalyxError {
    let message = message.into();
    tracing::error!(code, message = %message, remediation, "durable ONNX evidence operation failed closed");
    CalyxError {
        code,
        message,
        remediation,
    }
}
