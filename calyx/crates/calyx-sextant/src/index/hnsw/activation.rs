//! Atomic serving-pointer activation for persisted packed HNSW artifacts.
//!
//! Anneal may only promote a quantization configuration after a measured
//! candidate artifact has been staged here. The stable pointer is a separate,
//! versioned, checksummed file. Activation atomically replaces that file,
//! reopens it and the referenced artifact, and returns the physical readback.
//! A later cache/ledger failure can restore the exact prior pointer bytes.

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use calyx_anneal::{
    IndexArtifactActivation, IndexArtifactActivator, IndexArtifactPromotionRequest,
};
use calyx_core::{Result, SlotId};

use super::{HnswArtifactExpectation, HnswIndex};
use crate::error::{
    CALYX_SEXTANT_HNSW_POINTER_CORRUPT, CALYX_SEXTANT_HNSW_POINTER_IO,
    CALYX_SEXTANT_HNSW_POINTER_STALE, CALYX_SEXTANT_HNSW_POINTER_UNSTAGED, sextant_error,
};
use crate::index::QuantKind;

pub const HNSW_ACTIVE_POINTER_MAGIC: [u8; 8] = *b"CLXHNPT1";
pub const HNSW_ACTIVE_POINTER_VERSION: u16 = 1;

const POINTER_HEADER_BYTES: usize = 112;
const DIGEST_BYTES: usize = 32;
const MAX_POINTER_PATH_BYTES: usize = 32_768;
const MAX_POINTER_BYTES: usize = POINTER_HEADER_BYTES + MAX_POINTER_PATH_BYTES + DIGEST_BYTES;
static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

/// Fully validated state read from the stable active pointer and its artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HnswActivePointer {
    pub slot: SlotId,
    pub quant_bits: u8,
    pub config_hash: [u8; 32],
    pub artifact_path: PathBuf,
    pub artifact_digest: [u8; 32],
    pub artifact_bytes: u64,
    pub heldout_query_count: u64,
    pub expectation: HnswArtifactExpectation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StagedArtifact {
    pointer: HnswActivePointer,
}

#[derive(Clone, Debug)]
struct RollbackState {
    activation: IndexArtifactActivation,
    prior_bytes: Vec<u8>,
}

/// Exclusive serving owner for one slot's stable active HNSW pointer.
///
/// One instance must own mutations for the pointer path. Readers remain safe
/// across the swap because the pointer file itself is atomically replaced.
pub struct HnswArtifactActivator {
    active_pointer_path: PathBuf,
    slot: SlotId,
    staged: HashMap<[u8; 32], StagedArtifact>,
    rollback_state: Option<RollbackState>,
}

impl HnswArtifactActivator {
    pub fn new(active_pointer_path: impl Into<PathBuf>, slot: SlotId) -> Self {
        Self {
            active_pointer_path: active_pointer_path.into(),
            slot,
            staged: HashMap::new(),
            rollback_state: None,
        }
    }

    pub fn active_pointer_path(&self) -> &Path {
        &self.active_pointer_path
    }

    /// Establishes the first active generation. Existing pointer bytes are
    /// never overwritten by initialization.
    pub fn initialize_active(
        &self,
        config_hash: [u8; 32],
        quant_bits: u8,
        artifact_path: &Path,
        expectation: HnswArtifactExpectation,
        heldout_query_count: u64,
    ) -> Result<HnswActivePointer> {
        if self.active_pointer_path.exists() {
            return Err(pointer_error(
                CALYX_SEXTANT_HNSW_POINTER_STALE,
                format!(
                    "refusing to initialize existing active HNSW pointer {}",
                    self.active_pointer_path.display()
                ),
            ));
        }
        let target = self.validated_target(
            config_hash,
            quant_bits,
            artifact_path,
            expectation,
            heldout_query_count,
        )?;
        let bytes = encode_pointer(&target)?;
        publish_initial(&self.active_pointer_path, &bytes)?;
        let (_, observed) = self.open_active()?;
        if observed != target {
            return Err(pointer_error(
                CALYX_SEXTANT_HNSW_POINTER_CORRUPT,
                "initialized active HNSW pointer did not reread as the exact published target",
            ));
        }
        Ok(observed)
    }

    /// Adds an already persisted and held-out-measured artifact to the exact
    /// Anneal config hash it may serve. Staging reopens the artifact now;
    /// activation reopens it again after the pointer swap.
    pub fn stage_candidate(
        &mut self,
        config_hash: [u8; 32],
        quant_bits: u8,
        artifact_path: &Path,
        expectation: HnswArtifactExpectation,
        heldout_query_count: u64,
    ) -> Result<HnswActivePointer> {
        let target = self.validated_target(
            config_hash,
            quant_bits,
            artifact_path,
            expectation,
            heldout_query_count,
        )?;
        if let Some(existing) = self.staged.get(&config_hash) {
            if existing.pointer != target {
                return Err(pointer_error(
                    CALYX_SEXTANT_HNSW_POINTER_STALE,
                    "candidate config hash is already staged with different physical bytes",
                ));
            }
            return Ok(existing.pointer.clone());
        }
        self.staged.insert(
            config_hash,
            StagedArtifact {
                pointer: target.clone(),
            },
        );
        Ok(target)
    }

    /// Opens the stable pointer, validates its checksum and identity, then
    /// reopens and validates every byte of the referenced packed artifact.
    pub fn open_active(&self) -> Result<(HnswIndex, HnswActivePointer)> {
        let pointer_bytes = read_pointer_bytes(&self.active_pointer_path)?;
        let pointer = decode_pointer(&pointer_bytes)?;
        if pointer.slot != self.slot {
            return Err(pointer_error(
                CALYX_SEXTANT_HNSW_POINTER_STALE,
                format!(
                    "active HNSW pointer slot {} does not match serving owner slot {}",
                    pointer.slot.get(),
                    self.slot.get()
                ),
            ));
        }
        let (index, metadata) =
            HnswIndex::load_artifact(&pointer.artifact_path, pointer.expectation)?;
        if metadata.digest != pointer.artifact_digest
            || metadata.artifact_bytes != pointer.artifact_bytes
        {
            return Err(pointer_error(
                CALYX_SEXTANT_HNSW_POINTER_CORRUPT,
                format!(
                    "active artifact {} digest/length differs from its stable pointer",
                    pointer.artifact_path.display()
                ),
            ));
        }
        Ok((index, pointer))
    }

    fn validated_target(
        &self,
        config_hash: [u8; 32],
        quant_bits: u8,
        artifact_path: &Path,
        expectation: HnswArtifactExpectation,
        heldout_query_count: u64,
    ) -> Result<HnswActivePointer> {
        if config_hash == [0_u8; 32] {
            return Err(pointer_error(
                CALYX_SEXTANT_HNSW_POINTER_UNSTAGED,
                "candidate config hash cannot be all zeroes",
            ));
        }
        if expectation.slot != self.slot {
            return Err(pointer_error(
                CALYX_SEXTANT_HNSW_POINTER_UNSTAGED,
                format!(
                    "artifact slot {} does not match activator slot {}",
                    expectation.slot.get(),
                    self.slot.get()
                ),
            ));
        }
        let expected_bits = quant_bits_for_kind(expectation.quant_kind);
        if quant_bits != expected_bits {
            return Err(pointer_error(
                CALYX_SEXTANT_HNSW_POINTER_UNSTAGED,
                format!(
                    "artifact codec {:?} physically carries {expected_bits} bits, not declared {quant_bits}",
                    expectation.quant_kind
                ),
            ));
        }
        if heldout_query_count == 0 {
            return Err(pointer_error(
                CALYX_SEXTANT_HNSW_POINTER_UNSTAGED,
                "candidate artifact has no held-out search measurements",
            ));
        }
        let canonical_path = artifact_path.canonicalize().map_err(|error| {
            pointer_error(
                CALYX_SEXTANT_HNSW_POINTER_IO,
                format!(
                    "canonicalize candidate artifact {}: {error}",
                    artifact_path.display()
                ),
            )
        })?;
        let (_, metadata) = HnswIndex::load_artifact(&canonical_path, expectation)?;
        if metadata.artifact_bytes == 0 || metadata.digest == [0_u8; 32] {
            return Err(pointer_error(
                CALYX_SEXTANT_HNSW_POINTER_CORRUPT,
                "candidate artifact readback has no physical bytes or digest",
            ));
        }
        Ok(HnswActivePointer {
            slot: self.slot,
            quant_bits,
            config_hash,
            artifact_path: canonical_path,
            artifact_digest: metadata.digest,
            artifact_bytes: metadata.artifact_bytes,
            heldout_query_count,
            expectation,
        })
    }

    fn restore_after_failed_activation(
        &self,
        prior_bytes: &[u8],
        activation_error: calyx_core::CalyxError,
    ) -> Result<IndexArtifactActivation> {
        if let Err(rollback_error) = replace_pointer(&self.active_pointer_path, prior_bytes)
            .and_then(|_| self.open_active().map(|_| ()))
        {
            return Err(pointer_error(
                CALYX_SEXTANT_HNSW_POINTER_CORRUPT,
                format!(
                    "candidate activation failed ({}) and restoring the prior pointer also failed ({})",
                    activation_error.message, rollback_error.message
                ),
            ));
        }
        Err(activation_error)
    }
}

impl IndexArtifactActivator for HnswArtifactActivator {
    fn activate(
        &mut self,
        request: &IndexArtifactPromotionRequest,
    ) -> Result<IndexArtifactActivation> {
        if request.slot_id != self.slot {
            return Err(pointer_error(
                CALYX_SEXTANT_HNSW_POINTER_STALE,
                format!(
                    "Anneal promotion slot {} does not match activator slot {}",
                    request.slot_id.get(),
                    self.slot.get()
                ),
            ));
        }
        let prior_bytes = read_pointer_bytes(&self.active_pointer_path)?;
        let (_, prior) = self.open_active()?;
        if prior.config_hash != request.prior_config_hash
            || prior.quant_bits != request.prior_quant_bits
        {
            return Err(pointer_error(
                CALYX_SEXTANT_HNSW_POINTER_STALE,
                "active HNSW pointer does not match Anneal's claimed incumbent config",
            ));
        }
        let candidate = self
            .staged
            .get(&request.candidate_config_hash)
            .ok_or_else(|| {
                pointer_error(
                    CALYX_SEXTANT_HNSW_POINTER_UNSTAGED,
                    "no measured physical HNSW artifact is staged for the candidate config hash",
                )
            })?
            .pointer
            .clone();
        if candidate.config_hash != request.candidate_config_hash
            || candidate.quant_bits != request.candidate_quant_bits
        {
            return Err(pointer_error(
                CALYX_SEXTANT_HNSW_POINTER_STALE,
                "staged HNSW artifact does not match Anneal's candidate config",
            ));
        }
        if candidate.artifact_path == prior.artifact_path
            || candidate.artifact_digest == prior.artifact_digest
        {
            return Err(pointer_error(
                CALYX_SEXTANT_HNSW_POINTER_STALE,
                "quant promotion did not identify different physical artifact bytes",
            ));
        }

        let candidate_bytes = encode_pointer(&candidate)?;
        replace_pointer(&self.active_pointer_path, &candidate_bytes)?;
        let observed = match self.open_active() {
            Ok((_, observed)) => observed,
            Err(error) => return self.restore_after_failed_activation(&prior_bytes, error),
        };
        let observed_bytes = match read_pointer_bytes(&self.active_pointer_path) {
            Ok(bytes) => bytes,
            Err(error) => return self.restore_after_failed_activation(&prior_bytes, error),
        };
        if observed != candidate || observed_bytes != candidate_bytes {
            return self.restore_after_failed_activation(
                &prior_bytes,
                pointer_error(
                    CALYX_SEXTANT_HNSW_POINTER_CORRUPT,
                    "post-swap pointer/artifact readback differs from the staged candidate",
                ),
            );
        }

        let activation = IndexArtifactActivation {
            prior_pointer: path_string(&prior.artifact_path)?,
            candidate_pointer: path_string(&candidate.artifact_path)?,
            observed_pointer: path_string(&observed.artifact_path)?,
            prior_pointer_digest: *blake3::hash(&prior_bytes).as_bytes(),
            candidate_pointer_digest: *blake3::hash(&candidate_bytes).as_bytes(),
            observed_pointer_digest: *blake3::hash(&observed_bytes).as_bytes(),
            prior_artifact_digest: prior.artifact_digest,
            candidate_artifact_digest: candidate.artifact_digest,
            observed_artifact_digest: observed.artifact_digest,
            candidate_artifact_bytes: observed.artifact_bytes,
            heldout_query_count: observed.heldout_query_count,
            candidate_quant_bits: observed.quant_bits,
        };
        self.rollback_state = Some(RollbackState {
            activation: activation.clone(),
            prior_bytes,
        });
        Ok(activation)
    }

    fn rollback(&mut self, activation: &IndexArtifactActivation) -> Result<()> {
        let rollback = self.rollback_state.as_ref().ok_or_else(|| {
            pointer_error(
                CALYX_SEXTANT_HNSW_POINTER_STALE,
                "no matching activation is available for rollback",
            )
        })?;
        if &rollback.activation != activation {
            return Err(pointer_error(
                CALYX_SEXTANT_HNSW_POINTER_STALE,
                "rollback request does not match the most recent activation",
            ));
        }
        let (_, current) = self.open_active()?;
        if path_string(&current.artifact_path)? != activation.candidate_pointer
            || current.artifact_digest != activation.candidate_artifact_digest
        {
            return Err(pointer_error(
                CALYX_SEXTANT_HNSW_POINTER_STALE,
                "active pointer advanced or changed after activation; refusing stale rollback",
            ));
        }
        let prior_bytes = rollback.prior_bytes.clone();
        replace_pointer(&self.active_pointer_path, &prior_bytes)?;
        let (_, restored) = self.open_active()?;
        if path_string(&restored.artifact_path)? != activation.prior_pointer
            || restored.artifact_digest != activation.prior_artifact_digest
        {
            return Err(pointer_error(
                CALYX_SEXTANT_HNSW_POINTER_CORRUPT,
                "rollback did not restore the exact prior pointer and artifact digest",
            ));
        }
        self.rollback_state = None;
        Ok(())
    }
}

fn encode_pointer(pointer: &HnswActivePointer) -> Result<Vec<u8>> {
    let path = path_string(&pointer.artifact_path)?;
    let path_bytes = path.as_bytes();
    if path_bytes.is_empty() || path_bytes.len() > MAX_POINTER_PATH_BYTES {
        return Err(pointer_error(
            CALYX_SEXTANT_HNSW_POINTER_IO,
            format!(
                "active artifact path length {} is outside 1..={MAX_POINTER_PATH_BYTES}",
                path_bytes.len()
            ),
        ));
    }
    let mut bytes = Vec::with_capacity(POINTER_HEADER_BYTES + path_bytes.len() + DIGEST_BYTES);
    bytes.extend_from_slice(&HNSW_ACTIVE_POINTER_MAGIC);
    bytes.extend_from_slice(&HNSW_ACTIVE_POINTER_VERSION.to_le_bytes());
    bytes.extend_from_slice(&pointer.slot.get().to_le_bytes());
    bytes.push(pointer.quant_bits);
    bytes.push(quant_tag(pointer.expectation.quant_kind));
    bytes.extend_from_slice(&[0_u8; 2]);
    bytes.extend_from_slice(&pointer.expectation.dim.to_le_bytes());
    bytes.extend_from_slice(&pointer.expectation.base_seq.to_le_bytes());
    bytes.extend_from_slice(&pointer.config_hash);
    bytes.extend_from_slice(&pointer.artifact_digest);
    bytes.extend_from_slice(&pointer.artifact_bytes.to_le_bytes());
    bytes.extend_from_slice(&pointer.heldout_query_count.to_le_bytes());
    bytes.extend_from_slice(&(path_bytes.len() as u32).to_le_bytes());
    bytes.extend_from_slice(path_bytes);
    let digest = blake3::hash(&bytes);
    bytes.extend_from_slice(digest.as_bytes());
    Ok(bytes)
}

fn decode_pointer(bytes: &[u8]) -> Result<HnswActivePointer> {
    if bytes.len() < POINTER_HEADER_BYTES + DIGEST_BYTES {
        return Err(pointer_error(
            CALYX_SEXTANT_HNSW_POINTER_CORRUPT,
            "active HNSW pointer is truncated before its fixed header/footer",
        ));
    }
    let payload_len = bytes.len() - DIGEST_BYTES;
    let computed = blake3::hash(&bytes[..payload_len]);
    if computed.as_bytes() != &bytes[payload_len..] {
        return Err(pointer_error(
            CALYX_SEXTANT_HNSW_POINTER_CORRUPT,
            "active HNSW pointer checksum mismatch",
        ));
    }
    if bytes[..8] != HNSW_ACTIVE_POINTER_MAGIC {
        return Err(pointer_error(
            CALYX_SEXTANT_HNSW_POINTER_CORRUPT,
            "active HNSW pointer magic is invalid",
        ));
    }
    let version = u16::from_le_bytes(fixed(&bytes[8..10])?);
    if version != HNSW_ACTIVE_POINTER_VERSION {
        return Err(pointer_error(
            CALYX_SEXTANT_HNSW_POINTER_CORRUPT,
            format!("active HNSW pointer version {version} is unsupported"),
        ));
    }
    if bytes[14..16] != [0_u8; 2] {
        return Err(pointer_error(
            CALYX_SEXTANT_HNSW_POINTER_CORRUPT,
            "active HNSW pointer reserved bytes are nonzero",
        ));
    }
    let slot = SlotId::new(u16::from_le_bytes(fixed(&bytes[10..12])?));
    let quant_bits = bytes[12];
    let quant_kind = quant_from_tag(bytes[13])?;
    if quant_bits != quant_bits_for_kind(quant_kind) {
        return Err(pointer_error(
            CALYX_SEXTANT_HNSW_POINTER_CORRUPT,
            "active HNSW pointer quant_bits disagree with its codec",
        ));
    }
    let dim = u32::from_le_bytes(fixed(&bytes[16..20])?);
    let base_seq = u64::from_le_bytes(fixed(&bytes[20..28])?);
    let config_hash = fixed(&bytes[28..60])?;
    let artifact_digest = fixed(&bytes[60..92])?;
    let artifact_bytes = u64::from_le_bytes(fixed(&bytes[92..100])?);
    let heldout_query_count = u64::from_le_bytes(fixed(&bytes[100..108])?);
    let path_len = u32::from_le_bytes(fixed(&bytes[108..112])?) as usize;
    if path_len == 0 || path_len > MAX_POINTER_PATH_BYTES {
        return Err(pointer_error(
            CALYX_SEXTANT_HNSW_POINTER_CORRUPT,
            "active HNSW pointer artifact path length is invalid",
        ));
    }
    let expected_len = POINTER_HEADER_BYTES
        .checked_add(path_len)
        .and_then(|value| value.checked_add(DIGEST_BYTES))
        .ok_or_else(|| {
            pointer_error(
                CALYX_SEXTANT_HNSW_POINTER_CORRUPT,
                "active HNSW pointer length overflow",
            )
        })?;
    if bytes.len() != expected_len {
        return Err(pointer_error(
            CALYX_SEXTANT_HNSW_POINTER_CORRUPT,
            "active HNSW pointer has trailing or missing bytes",
        ));
    }
    if config_hash == [0_u8; 32]
        || artifact_digest == [0_u8; 32]
        || artifact_bytes == 0
        || heldout_query_count == 0
    {
        return Err(pointer_error(
            CALYX_SEXTANT_HNSW_POINTER_CORRUPT,
            "active HNSW pointer is missing config/artifact/measurement identity",
        ));
    }
    let path_text =
        std::str::from_utf8(&bytes[POINTER_HEADER_BYTES..payload_len]).map_err(|_| {
            pointer_error(
                CALYX_SEXTANT_HNSW_POINTER_CORRUPT,
                "active HNSW pointer artifact path is not UTF-8",
            )
        })?;
    let artifact_path = PathBuf::from(path_text);
    if !artifact_path.is_absolute() {
        return Err(pointer_error(
            CALYX_SEXTANT_HNSW_POINTER_CORRUPT,
            "active HNSW pointer artifact path is not absolute",
        ));
    }
    Ok(HnswActivePointer {
        slot,
        quant_bits,
        config_hash,
        artifact_path,
        artifact_digest,
        artifact_bytes,
        heldout_query_count,
        expectation: HnswArtifactExpectation {
            slot,
            dim,
            quant_kind,
            base_seq,
        },
    })
}

fn read_pointer_bytes(path: &Path) -> Result<Vec<u8>> {
    let mut file = File::open(path).map_err(|error| {
        pointer_error(
            CALYX_SEXTANT_HNSW_POINTER_IO,
            format!("open active HNSW pointer {}: {error}", path.display()),
        )
    })?;
    let length = file
        .metadata()
        .map_err(|error| {
            pointer_error(
                CALYX_SEXTANT_HNSW_POINTER_IO,
                format!("stat active HNSW pointer {}: {error}", path.display()),
            )
        })?
        .len();
    if length > MAX_POINTER_BYTES as u64 {
        return Err(pointer_error(
            CALYX_SEXTANT_HNSW_POINTER_CORRUPT,
            format!("active HNSW pointer is {length} bytes, above {MAX_POINTER_BYTES}"),
        ));
    }
    let capacity = length as usize;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(capacity).map_err(|error| {
        pointer_error(
            CALYX_SEXTANT_HNSW_POINTER_IO,
            format!("reserve {capacity} pointer bytes: {error}"),
        )
    })?;
    file.read_to_end(&mut bytes).map_err(|error| {
        pointer_error(
            CALYX_SEXTANT_HNSW_POINTER_IO,
            format!("read active HNSW pointer {}: {error}", path.display()),
        )
    })?;
    if bytes.len() != capacity {
        return Err(pointer_error(
            CALYX_SEXTANT_HNSW_POINTER_IO,
            format!(
                "active HNSW pointer {} changed during read: stat={capacity} read={}",
                path.display(),
                bytes.len()
            ),
        ));
    }
    Ok(bytes)
}

fn publish_initial(path: &Path, bytes: &[u8]) -> Result<()> {
    write_then_publish(path, bytes, false)
}

fn replace_pointer(path: &Path, bytes: &[u8]) -> Result<()> {
    write_then_publish(path, bytes, true)
}

fn write_then_publish(path: &Path, bytes: &[u8], replace: bool) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        pointer_error(
            CALYX_SEXTANT_HNSW_POINTER_IO,
            format!("active pointer path {} has no parent", path.display()),
        )
    })?;
    std::fs::create_dir_all(parent).map_err(|error| {
        pointer_error(
            CALYX_SEXTANT_HNSW_POINTER_IO,
            format!(
                "create active pointer directory {}: {error}",
                parent.display()
            ),
        )
    })?;
    let temp = unique_temp_path(path)?;
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp)
            .map_err(|error| {
                pointer_error(
                    CALYX_SEXTANT_HNSW_POINTER_IO,
                    format!(
                        "create temporary active pointer {}: {error}",
                        temp.display()
                    ),
                )
            })?;
        file.write_all(bytes).map_err(|error| {
            pointer_error(
                CALYX_SEXTANT_HNSW_POINTER_IO,
                format!("write temporary active pointer {}: {error}", temp.display()),
            )
        })?;
        file.sync_all().map_err(|error| {
            pointer_error(
                CALYX_SEXTANT_HNSW_POINTER_IO,
                format!("sync temporary active pointer {}: {error}", temp.display()),
            )
        })?;
        decode_pointer(&read_pointer_bytes(&temp)?)?;
        publish_temp(&temp, path, replace)
    })();
    if result.is_err() && temp.exists() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

fn unique_temp_path(path: &Path) -> Result<PathBuf> {
    let name = path.file_name().ok_or_else(|| {
        pointer_error(
            CALYX_SEXTANT_HNSW_POINTER_IO,
            format!("active pointer path {} has no file name", path.display()),
        )
    })?;
    let mut temp_name = OsString::from(".");
    temp_name.push(name);
    temp_name.push(format!(
        ".{}.{}.tmp",
        std::process::id(),
        NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed)
    ));
    Ok(path.with_file_name(temp_name))
}

#[cfg(windows)]
fn publish_temp(temp: &Path, path: &Path, replace: bool) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;

    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let mut temp_wide = temp.as_os_str().encode_wide().collect::<Vec<_>>();
    let mut path_wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if temp_wide.contains(&0) || path_wide.contains(&0) {
        return Err(pointer_error(
            CALYX_SEXTANT_HNSW_POINTER_IO,
            "active pointer path contains an interior NUL",
        ));
    }
    temp_wide.push(0);
    path_wide.push(0);
    let mut flags = MOVEFILE_WRITE_THROUGH;
    if replace {
        flags |= MOVEFILE_REPLACE_EXISTING;
    }
    // SAFETY: both buffers are NUL-terminated UTF-16 and remain alive for the
    // duration of MoveFileExW, which does not retain either pointer.
    let moved = unsafe { MoveFileExW(temp_wide.as_ptr(), path_wide.as_ptr(), flags) };
    if moved == 0 {
        return Err(pointer_error(
            CALYX_SEXTANT_HNSW_POINTER_IO,
            format!(
                "publish active pointer {} -> {} replace={replace}: {}",
                temp.display(),
                path.display(),
                std::io::Error::last_os_error()
            ),
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
fn publish_temp(temp: &Path, path: &Path, replace: bool) -> Result<()> {
    if !replace && path.exists() {
        return Err(pointer_error(
            CALYX_SEXTANT_HNSW_POINTER_STALE,
            format!("active pointer {} already exists", path.display()),
        ));
    }
    std::fs::rename(temp, path).map_err(|error| {
        pointer_error(
            CALYX_SEXTANT_HNSW_POINTER_IO,
            format!(
                "publish active pointer {} -> {}: {error}",
                temp.display(),
                path.display()
            ),
        )
    })
}

fn quant_bits_for_kind(kind: QuantKind) -> u8 {
    match kind {
        QuantKind::None => 32,
        QuantKind::Scalar8 => 8,
        QuantKind::Binary => 1,
    }
}

fn quant_tag(kind: QuantKind) -> u8 {
    match kind {
        QuantKind::None => 0,
        QuantKind::Scalar8 => 1,
        QuantKind::Binary => 2,
    }
}

fn quant_from_tag(tag: u8) -> Result<QuantKind> {
    match tag {
        0 => Ok(QuantKind::None),
        1 => Ok(QuantKind::Scalar8),
        2 => Ok(QuantKind::Binary),
        _ => Err(pointer_error(
            CALYX_SEXTANT_HNSW_POINTER_CORRUPT,
            format!("active HNSW pointer codec tag {tag} is invalid"),
        )),
    }
}

fn path_string(path: &Path) -> Result<String> {
    path.to_str().map(str::to_owned).ok_or_else(|| {
        pointer_error(
            CALYX_SEXTANT_HNSW_POINTER_IO,
            format!("active artifact path {} is not UTF-8", path.display()),
        )
    })
}

fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N]> {
    bytes.try_into().map_err(|_| {
        pointer_error(
            CALYX_SEXTANT_HNSW_POINTER_CORRUPT,
            "active HNSW pointer fixed-width field is truncated",
        )
    })
}

fn pointer_error(code: &'static str, message: impl Into<String>) -> calyx_core::CalyxError {
    sextant_error(code, message)
}
