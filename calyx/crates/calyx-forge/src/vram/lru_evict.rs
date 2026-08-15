//! Exact-identity lifecycle for GPU-resident Forge allocations.
//!
//! A tracked allocation is removed only after the CUDA boundary independently
//! proves that its exact pointer is absent. Any free, identity, device, probe,
//! or journal ambiguity moves the allocation into a preserving quarantine and
//! keeps its [`VramGuard`] alive. Admission refuses while quarantine exists.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::vram::{AllocationJournal, AllocationJournalEvent, VramBudgeter, VramGuard, VramProbe};
use crate::{ForgeError, PinnedCudaDeviceIdentity, Result};

const DEALLOCATION_REMEDIATION: &str = "preserve the exact allocation journal and process; inspect the recorded CUDA error and pointer readback, then recover only with the same block generation, pointer, and device identity";
const IDENTITY_REMEDIATION: &str = "use the exact nonzero allocation generation, pointer, byte count, owner, and pinned physical CUDA device recorded when the allocation was created";

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
/// Logical identity assigned by the Forge allocation owner.
pub struct BlockId(pub u64);

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
/// Exact CUDA device-pointer token returned for one physical allocation.
pub struct DevicePtr(pub u64);

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Scheduling class for one GPU allocation.
pub enum BlockKind {
    /// Serving, embedding, or scratch allocation.
    General,
    /// ANN frontier allocation subject to the configured frontier count.
    Frontier,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
/// Owner-assigned logical block identity and nonzero allocation generation.
pub struct AllocationKey {
    /// Stable logical block identifier.
    pub block_id: BlockId,
    /// Monotonic nonzero physical-allocation generation for the block.
    pub allocation_generation: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// Complete identity required to attribute or recover one physical allocation.
pub struct GpuAllocationIdentity {
    /// Logical block and generation.
    pub key: AllocationKey,
    /// Non-empty allocation owner label.
    pub owner: String,
    /// Exact pinned physical CUDA device.
    pub device: PinnedCudaDeviceIdentity,
    /// Exact CUDA device pointer.
    pub ptr: DevicePtr,
    /// Physical allocation length and matching reservation length.
    pub size_bytes: usize,
}

type AllocationRecordKey = (AllocationKey, DevicePtr);

impl GpuAllocationIdentity {
    /// Refuse incomplete or non-canonical allocation identities.
    pub fn validate(&self) -> Result<()> {
        if self.key.allocation_generation == 0 {
            return Err(identity_error("allocation generation is zero"));
        }
        if self.owner.is_empty() || self.owner.trim() != self.owner {
            return Err(identity_error(
                "allocation owner must be non-empty and contain no surrounding whitespace",
            ));
        }
        if self.ptr.0 == 0 {
            return Err(identity_error("device pointer is zero"));
        }
        if self.size_bytes == 0 {
            return Err(identity_error("allocation size is zero"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// One physical-device memory observation made under the pinned CUDA context.
pub struct DeviceMemoryObservation {
    /// Device that produced the observation.
    pub device: PinnedCudaDeviceIdentity,
    /// Driver-reported free bytes.
    pub free_bytes: u64,
    /// Driver-reported total bytes.
    pub total_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
/// Exact address-range readback for a CUDA pointer token.
pub enum DeviceAllocationState {
    /// The pointer resolves to this base address and allocation length.
    Present {
        /// Base pointer returned by `cuMemGetAddressRange_v2`.
        base: DevicePtr,
        /// Full allocation length returned by the driver.
        size_bytes: usize,
    },
    /// The CUDA driver reports that the pointer is not allocated.
    Absent,
}

/// Physical CUDA operations required by the allocation registry.
pub trait BlockDeallocator: Send + Sync {
    /// Read physical memory state and the exact device identity.
    fn device_observation(&self) -> Result<DeviceMemoryObservation>;
    /// Read the address range currently owning `ptr`.
    fn allocation_state(&self, ptr: DevicePtr) -> Result<DeviceAllocationState>;
    /// Request physical release of the exact pointer and byte length.
    fn free(&self, ptr: DevicePtr, size_bytes: usize) -> Result<()>;
}

#[cfg(feature = "cuda")]
#[derive(Clone)]
/// CUDA Driver API implementation of exact allocation readback and release.
pub struct RawCudaBlockDeallocator {
    ctx: std::sync::Arc<crate::cuda::CudaContext>,
}

#[cfg(feature = "cuda")]
impl RawCudaBlockDeallocator {
    /// Bind deallocation operations to an already pinned CUDA context.
    pub fn new(ctx: std::sync::Arc<crate::cuda::CudaContext>) -> Self {
        Self { ctx }
    }

    /// Return the pinned context used for all physical operations.
    pub fn context(&self) -> &std::sync::Arc<crate::cuda::CudaContext> {
        &self.ctx
    }
}

#[cfg(feature = "cuda")]
impl BlockDeallocator for RawCudaBlockDeallocator {
    fn device_observation(&self) -> Result<DeviceMemoryObservation> {
        self.ctx.inner().bind_to_thread().map_err(cuda_error)?;
        let (free_bytes, total_bytes) = self.ctx.inner().mem_get_info().map_err(cuda_error)?;
        Ok(DeviceMemoryObservation {
            device: self.ctx.physical_identity(),
            free_bytes: u64::try_from(free_bytes)
                .map_err(|_| identity_error("CUDA free-byte observation exceeds u64"))?,
            total_bytes: u64::try_from(total_bytes)
                .map_err(|_| identity_error("CUDA total-byte observation exceeds u64"))?,
        })
    }

    fn allocation_state(&self, ptr: DevicePtr) -> Result<DeviceAllocationState> {
        use cudarc::driver::{result, sys};
        self.ctx.inner().bind_to_thread().map_err(cuda_error)?;
        let mut base = 0_u64;
        let mut size_bytes = 0_usize;
        let status = unsafe { sys::cuMemGetAddressRange_v2(&mut base, &mut size_bytes, ptr.0) };
        if status == sys::CUresult::CUDA_SUCCESS {
            return Ok(DeviceAllocationState::Present {
                base: DevicePtr(base),
                size_bytes,
            });
        }
        if status == sys::CUresult::CUDA_ERROR_INVALID_VALUE {
            return Ok(DeviceAllocationState::Absent);
        }
        Err(cuda_error(result::DriverError(status)))
    }

    fn free(&self, ptr: DevicePtr, _size_bytes: usize) -> Result<()> {
        self.ctx.inner().bind_to_thread().map_err(cuda_error)?;
        unsafe { cudarc::driver::result::free_sync(ptr.0) }.map_err(cuda_error)
    }
}

#[cfg(feature = "cuda")]
fn cuda_error(error: cudarc::driver::result::DriverError) -> ForgeError {
    ForgeError::RuntimeBoundary {
        code: "CALYX_FORGE_GPU_DEALLOCATION_FAILED",
        detail: format!(
            "CUDA driver status={:?} numeric={}",
            error.0, error.0 as i32
        ),
        remediation: DEALLOCATION_REMEDIATION,
    }
}

struct GpuBlock<'b, P: VramProbe> {
    identity: GpuAllocationIdentity,
    kind: BlockKind,
    state: AllocationLifecycle,
    guard: VramGuard<'b, P>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum AllocationLifecycle {
    Resident,
    Quarantined {
        failure_code: String,
        detail: String,
    },
}

impl AllocationLifecycle {
    fn label(&self) -> &'static str {
        match self {
            Self::Resident => "resident",
            Self::Quarantined { .. } => "quarantined",
        }
    }

    fn failure(&self) -> Option<(&str, &str)> {
        match self {
            Self::Resident => None,
            Self::Quarantined {
                failure_code,
                detail,
            } => Some((failure_code, detail)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
/// Read-only telemetry row for one tracked allocation.
pub struct GpuBlockSnapshot {
    /// Exact allocation identity.
    pub identity: GpuAllocationIdentity,
    /// Scheduling class.
    pub kind: BlockKind,
    /// `resident` or `quarantined`.
    pub state: String,
    /// Exact underlying failure code for a quarantined allocation.
    pub failure_code: Option<String>,
    /// Full structured failure detail.
    pub detail: Option<String>,
    /// Reservation bytes still held for this allocation.
    pub reserved_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
/// Registry, budgeter, and journal accounting readback.
pub struct GpuBlockStats {
    /// Number of allocations eligible for ordinary use or eviction.
    pub resident_blocks: usize,
    /// Bytes held by resident allocations.
    pub resident_bytes: usize,
    /// Number of preserving terminal allocations.
    pub quarantined_blocks: usize,
    /// Bytes held by quarantined allocations.
    pub quarantined_bytes: usize,
    /// All registry-owned reservation bytes.
    pub reserved_bytes: usize,
    /// All bytes currently reserved by the shared budgeter.
    pub budgeter_reserved_bytes: usize,
    /// Budgeter reservations owned outside this registry.
    pub external_reserved_bytes: usize,
    /// Whether every registry/budgeter/quarantine byte identity agrees.
    pub accounting_equation_valid: bool,
    /// Completed physical releases, including explicit recovery.
    pub evictions_total: u64,
    /// Durable allocation-journal height.
    pub journal_entries: u64,
    /// Durable allocation-journal head digest.
    pub journal_head_sha256: String,
    /// Allocation-journal source-of-truth path.
    pub journal_path: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
/// Physical and accounting proof returned after an exact release.
pub struct GpuAllocationReleaseReceipt {
    /// Exact released allocation identity.
    pub identity: GpuAllocationIdentity,
    /// Lifecycle state before release.
    pub prior_state: String,
    /// Failure code retained by the prior quarantine state, when any.
    pub prior_failure_code: Option<String>,
    /// Failure detail retained by the prior quarantine state, when any.
    pub prior_failure_detail: Option<String>,
    /// Device observation before release.
    pub device_before: DeviceMemoryObservation,
    /// Device observation after pointer absence was proven.
    pub device_after: DeviceMemoryObservation,
    /// Budgeter bytes before release.
    pub budgeter_reserved_bytes_before: usize,
    /// Budgeter bytes after release.
    pub budgeter_reserved_bytes_after: usize,
    /// Registry-owned bytes after release.
    pub registry_reserved_bytes_after: usize,
    /// Post-release accounting equation result.
    pub accounting_equation_valid_after: bool,
    /// Journal sequence that recorded the release.
    pub journal_seq: u64,
    /// Journal head after durable readback.
    pub journal_head_sha256: String,
}

/// Exact-identity registry that owns every tracked allocation reservation.
pub struct GpuBlockRegistry<'b, P: VramProbe, D: BlockDeallocator> {
    blocks: BTreeMap<AllocationRecordKey, GpuBlock<'b, P>>,
    quarantined_keys: BTreeSet<AllocationRecordKey>,
    quarantined_reserved_bytes: usize,
    active_by_id: HashMap<BlockId, AllocationRecordKey>,
    lru: VecDeque<AllocationRecordKey>,
    budgeter: &'b VramBudgeter<P>,
    dealloc: D,
    journal: AllocationJournal,
    max_frontier_blocks: usize,
    evictions_total: u64,
}

impl<'b, P: VramProbe, D: BlockDeallocator> GpuBlockRegistry<'b, P, D> {
    /// Open a fresh in-process registry and validate the existing journal chain.
    pub fn open(
        budgeter: &'b VramBudgeter<P>,
        dealloc: D,
        max_frontier_blocks: usize,
        journal_path: impl AsRef<Path>,
    ) -> Result<Self> {
        Ok(Self {
            blocks: BTreeMap::new(),
            quarantined_keys: BTreeSet::new(),
            quarantined_reserved_bytes: 0,
            active_by_id: HashMap::new(),
            lru: VecDeque::new(),
            budgeter,
            dealloc,
            journal: AllocationJournal::open(journal_path)?,
            max_frontier_blocks,
            evictions_total: 0,
        })
    }

    /// Register a physical allocation only after device and address-range readback.
    pub fn insert(
        &mut self,
        identity: GpuAllocationIdentity,
        kind: BlockKind,
        guard: VramGuard<'b, P>,
    ) -> Result<()> {
        let key = identity.key;
        let record_key = (key, identity.ptr);
        if self.blocks.contains_key(&record_key) {
            let error = identity_error(format!(
                "allocation identity is already tracked: block_id={} generation={} ptr={} incoming_owner={:?} incoming_bytes={}",
                key.block_id.0,
                key.allocation_generation,
                identity.ptr.0,
                identity.owner,
                identity.size_bytes
            ));
            return Err(self.quarantine(record_key, &error));
        }
        let block = GpuBlock {
            identity,
            kind,
            state: AllocationLifecycle::Resident,
            guard,
        };
        self.blocks.insert(record_key, block);

        if let Err(error) = self.validate_new_block(record_key) {
            return Err(self.quarantine(record_key, &error));
        }
        let collisions = self
            .blocks
            .keys()
            .copied()
            .filter(|candidate| {
                *candidate != record_key && (candidate.0 == key || candidate.1 == record_key.1)
            })
            .collect::<Vec<_>>();
        if !collisions.is_empty() {
            let collision_detail = format!(
                "allocation identity collides with {} tracked record(s) by generation or pointer",
                collisions.len()
            );
            for collision in collisions {
                let error = identity_error(format!(
                    "{collision_detail}: incoming_block_id={} incoming_generation={} incoming_ptr={}",
                    key.block_id.0, key.allocation_generation, record_key.1.0
                ));
                let _ = self.quarantine(collision, &error);
            }
            let error = identity_error(collision_detail);
            return Err(self.quarantine(record_key, &error));
        }
        if self.has_quarantine_except(record_key) {
            let error = quarantine_error(
                &self.block(record_key)?.identity,
                "another allocation is quarantined; new GPU admission is unsafe",
            );
            return Err(self.quarantine(record_key, &error));
        }
        if let Some(existing) = self.active_by_id.get(&key.block_id).copied()
            && let Err(error) = self.release_key(existing, false)
        {
            let error = quarantine_error(
                &self.block(record_key)?.identity,
                format!("prior block generation could not be released: {error}"),
            );
            return Err(self.quarantine(record_key, &error));
        }
        if kind == BlockKind::Frontier && self.frontier_count() >= self.max_frontier_blocks {
            let Some(frontier) = self.oldest_frontier_key() else {
                let error =
                    identity_error("frontier count is nonzero but no resident frontier key exists");
                return Err(self.quarantine(record_key, &error));
            };
            if let Err(error) = self.release_key(frontier, false) {
                let error = quarantine_error(
                    &self.block(record_key)?.identity,
                    format!("frontier cap eviction failed: {error}"),
                );
                return Err(self.quarantine(record_key, &error));
            }
        }

        self.active_by_id.insert(key.block_id, record_key);
        self.lru.push_back(record_key);
        if let Err(error) = self.append_event(record_key, "registered", "", None, None, None) {
            return Err(self.quarantine(record_key, &error));
        }
        Ok(())
    }

    /// Mark a resident logical block as most recently used.
    pub fn touch(&mut self, id: &BlockId) {
        if let Some(key) = self.active_by_id.get(id).copied() {
            self.move_to_mru(key);
        }
    }

    /// Return a resident block pointer and mark it most recently used.
    pub fn get(&mut self, id: &BlockId) -> Option<DevicePtr> {
        let key = self.active_by_id.get(id).copied()?;
        let ptr = self.blocks.get(&key)?.identity.ptr;
        self.move_to_mru(key);
        Some(ptr)
    }

    /// Release the least-recently-used resident allocation.
    pub fn evict_lru(&mut self) -> Result<Option<usize>> {
        self.refuse_quarantined_admission()?;
        let Some(key) = self.lru.front().copied() else {
            return Ok(None);
        };
        let size = self.block(key)?.identity.size_bytes;
        self.release_key(key, false)?;
        Ok(Some(size))
    }

    /// Release resident allocations until `needed_bytes` fits the soft cap.
    pub fn evict_until(&mut self, needed_bytes: usize) -> Result<()> {
        self.refuse_quarantined_admission()?;
        let soft_cap = self.budgeter.soft_cap_bytes();
        loop {
            let projected = self
                .budgeter
                .allocated_bytes()
                .checked_add(needed_bytes)
                .ok_or_else(|| identity_error("VRAM admission byte arithmetic overflow"))?;
            if projected <= soft_cap {
                return Ok(());
            }
            if self.evict_lru()?.is_none() {
                return Err(ForgeError::VramBudget {
                    detail: format!(
                        "eviction exhausted the GPU block registry but {needed_bytes} bytes still do not fit: allocated={} soft_cap={soft_cap}",
                        self.budgeter.allocated_bytes()
                    ),
                    remediation: crate::vram::VRAM_BUDGET_REMEDIATION.to_string(),
                });
            }
        }
    }

    /// Refuse GPU admission while any allocation is quarantined.
    pub fn ensure_admission_safe(&self) -> Result<()> {
        self.refuse_quarantined_admission()
    }

    /// Explicitly recover one exact quarantined generation, pointer, and device.
    pub fn recover_quarantined(
        &mut self,
        key: AllocationKey,
        expected_ptr: DevicePtr,
        expected_device: PinnedCudaDeviceIdentity,
    ) -> Result<GpuAllocationReleaseReceipt> {
        let record_key = (key, expected_ptr);
        let block = self.blocks.get(&record_key).ok_or_else(|| {
            identity_error(format!(
                "recovery identity is not tracked: block_id={} generation={} ptr={}",
                key.block_id.0, key.allocation_generation, expected_ptr.0
            ))
        })?;
        if block.identity.device != expected_device {
            return Err(identity_error(format!(
                "recovery identity mismatch for block_id={} generation={}: expected_ptr={} expected_device={} observed_device={}",
                key.block_id.0,
                key.allocation_generation,
                expected_ptr.0,
                expected_device,
                block.identity.device
            )));
        }
        if !matches!(block.state, AllocationLifecycle::Quarantined { .. }) {
            return Err(identity_error(format!(
                "recovery requested for non-quarantined allocation state={}",
                block.state.label()
            )));
        }
        self.release_key(record_key, true)
    }

    /// Read and validate the registry/budgeter/journal accounting equation.
    pub fn stats(&self) -> Result<GpuBlockStats> {
        let resident_bytes = checked_block_bytes(
            self.blocks
                .values()
                .filter(|block| matches!(block.state, AllocationLifecycle::Resident))
                .map(|block| block.identity.size_bytes),
            "resident byte total",
        )?;
        let quarantined_bytes = checked_block_bytes(
            self.blocks
                .values()
                .filter(|block| matches!(block.state, AllocationLifecycle::Quarantined { .. }))
                .map(|block| block.identity.size_bytes),
            "quarantined byte total",
        )?;
        let reserved_bytes = checked_block_bytes(
            self.blocks.values().map(|block| block.guard.bytes()),
            "registry reservation total",
        )?;
        let budgeter_reserved_bytes = self.budgeter.allocated_bytes();
        let external_reserved_bytes = budgeter_reserved_bytes
            .checked_sub(reserved_bytes)
            .ok_or_else(|| {
                identity_error(format!(
                    "registry reservations exceed budgeter accounting: registry={reserved_bytes} budgeter={budgeter_reserved_bytes}"
                ))
            })?;
        let tracked_bytes = resident_bytes.checked_add(quarantined_bytes);
        let accounting_equation_valid = tracked_bytes == Some(reserved_bytes)
            && quarantined_bytes == self.quarantined_reserved_bytes
            && self.quarantined_keys.len()
                == self
                    .blocks
                    .values()
                    .filter(|block| matches!(block.state, AllocationLifecycle::Quarantined { .. }))
                    .count()
            && reserved_bytes
                .checked_add(external_reserved_bytes)
                .is_some_and(|total| total == budgeter_reserved_bytes)
            && self
                .blocks
                .values()
                .all(|block| block.guard.bytes() == block.identity.size_bytes);
        Ok(GpuBlockStats {
            resident_blocks: self
                .blocks
                .values()
                .filter(|block| matches!(block.state, AllocationLifecycle::Resident))
                .count(),
            resident_bytes,
            quarantined_blocks: self.quarantined_keys.len(),
            quarantined_bytes,
            reserved_bytes,
            budgeter_reserved_bytes,
            external_reserved_bytes,
            accounting_equation_valid,
            evictions_total: self.evictions_total,
            journal_entries: self.journal.next_seq(),
            journal_head_sha256: self.journal.head_sha256().to_string(),
            journal_path: self.journal.path().display().to_string(),
        })
    }

    /// Return every tracked allocation in deterministic identity order.
    pub fn allocations(&self) -> Vec<GpuBlockSnapshot> {
        self.blocks
            .values()
            .map(|block| {
                let failure = block.state.failure();
                GpuBlockSnapshot {
                    identity: block.identity.clone(),
                    kind: block.kind,
                    state: block.state.label().to_string(),
                    failure_code: failure.map(|(code, _)| code.to_string()),
                    detail: failure.map(|(_, detail)| detail.to_string()),
                    reserved_bytes: block.guard.bytes(),
                }
            })
            .collect()
    }

    /// Return resident bytes after validating all accounting identities.
    pub fn resident_bytes(&self) -> Result<usize> {
        Ok(self.stats()?.resident_bytes)
    }

    /// Count resident frontier allocations.
    pub fn frontier_count(&self) -> usize {
        self.blocks
            .values()
            .filter(|block| {
                block.kind == BlockKind::Frontier
                    && matches!(block.state, AllocationLifecycle::Resident)
            })
            .count()
    }

    fn validate_new_block(&self, key: AllocationRecordKey) -> Result<()> {
        let block = self.block(key)?;
        block.identity.validate()?;
        if block.guard.bytes() != block.identity.size_bytes {
            return Err(identity_error(format!(
                "guard byte count does not match allocation: guard={} identity={}",
                block.guard.bytes(),
                block.identity.size_bytes
            )));
        }
        let observation = self.dealloc.device_observation()?;
        if observation.device != block.identity.device {
            return Err(identity_error(format!(
                "physical CUDA device mismatch: allocation={} observed={}",
                block.identity.device, observation.device
            )));
        }
        match self.dealloc.allocation_state(block.identity.ptr)? {
            DeviceAllocationState::Present { base, size_bytes }
                if base == block.identity.ptr && size_bytes == block.identity.size_bytes =>
            {
                Ok(())
            }
            DeviceAllocationState::Present { base, size_bytes } => Err(identity_error(format!(
                "physical allocation mismatch: expected_ptr={} expected_bytes={} observed_base={} observed_bytes={size_bytes}",
                block.identity.ptr.0, block.identity.size_bytes, base.0
            ))),
            DeviceAllocationState::Absent => Err(identity_error(format!(
                "physical allocation is absent at pointer {}",
                block.identity.ptr.0
            ))),
        }
    }

    fn release_key(
        &mut self,
        key: AllocationRecordKey,
        recovery: bool,
    ) -> Result<GpuAllocationReleaseReceipt> {
        let identity = self
            .blocks
            .get(&key)
            .ok_or_else(|| identity_error("release key is not tracked"))?
            .identity
            .clone();
        let prior_block = self.block(key)?;
        let prior_state = prior_block.state.label().to_string();
        let (prior_failure_code, prior_failure_detail) = prior_block
            .state
            .failure()
            .map(|(code, detail)| (Some(code.to_string()), Some(detail.to_string())))
            .unwrap_or((None, None));
        let next_evictions_total = self
            .evictions_total
            .checked_add(1)
            .ok_or_else(|| identity_error("eviction counter overflow before physical release"))?;
        let budgeter_reserved_bytes_before = self.budgeter.allocated_bytes();
        let device_before = match self.dealloc.device_observation() {
            Ok(observation) => observation,
            Err(error) => return Err(self.pre_free_failure(key, recovery, &error)),
        };
        if device_before.device != identity.device {
            let error = identity_error(format!(
                "release device mismatch: allocation={} observed={}",
                identity.device, device_before.device
            ));
            return Err(self.pre_free_failure(key, recovery, &error));
        }

        let before_state = match self.dealloc.allocation_state(identity.ptr) {
            Ok(state) => state,
            Err(error) => return Err(self.pre_free_failure(key, recovery, &error)),
        };
        let mut free_error = None;
        match before_state {
            DeviceAllocationState::Present { base, size_bytes }
                if base == identity.ptr && size_bytes == identity.size_bytes =>
            {
                if let Err(error) = self.dealloc.free(identity.ptr, identity.size_bytes) {
                    free_error = Some((error.code().to_string(), error.to_string()));
                }
            }
            DeviceAllocationState::Present { base, size_bytes } => {
                let error = identity_error(format!(
                    "release pointer reuse/mismatch: expected_ptr={} expected_bytes={} observed_base={} observed_bytes={size_bytes}",
                    identity.ptr.0, identity.size_bytes, base.0
                ));
                return Err(self.pre_free_failure(key, recovery, &error));
            }
            DeviceAllocationState::Absent if recovery => {}
            DeviceAllocationState::Absent => {
                let error = identity_error(format!(
                    "resident allocation {} was absent before release",
                    identity.ptr.0
                ));
                return Err(self.quarantine(key, &error));
            }
        }

        match self.dealloc.allocation_state(identity.ptr) {
            Ok(DeviceAllocationState::Absent) => {}
            Ok(DeviceAllocationState::Present { base, size_bytes }) => {
                let detail = format!(
                    "CUDA allocation remained present after free: base={} bytes={size_bytes} free_error={free_error:?}",
                    base.0
                );
                let error = quarantine_error(&identity, detail);
                if let Some((failure_code, _)) = &free_error {
                    return Err(self.quarantine_with_failure(key, &error, failure_code));
                }
                return Err(self.quarantine(key, &error));
            }
            Err(error) => return Err(self.quarantine(key, &error)),
        }
        if let Some((failure_code, failure_detail)) = &free_error {
            let error = quarantine_error(
                &identity,
                format!(
                    "cudaFree returned {failure_code} even though pointer absence was observed afterward; explicit exact-identity recovery is required: {failure_detail}"
                ),
            );
            return Err(self.quarantine_with_failure(key, &error, failure_code));
        }
        let device_after = self
            .dealloc
            .device_observation()
            .map_err(|error| self.quarantine(key, &error))?;
        if device_after.device != identity.device {
            let error = identity_error(format!(
                "post-free device mismatch: allocation={} observed={}",
                identity.device, device_after.device
            ));
            return Err(self.quarantine(key, &error));
        }

        let transition = if recovery { "recovered" } else { "evicted" };
        let seq = self.journal.next_seq();
        if let Err(error) = self.append_event(
            key,
            transition,
            "CUDA pointer absence independently proven",
            free_error.as_ref().map(|(code, _)| code.as_str()),
            Some(device_after),
            None,
        ) {
            return Err(self.quarantine(key, &error));
        }
        self.remove_tracking(key)?;
        self.evictions_total = next_evictions_total;
        let stats_after = self.stats()?;
        Ok(GpuAllocationReleaseReceipt {
            identity,
            prior_state,
            prior_failure_code,
            prior_failure_detail,
            device_before,
            device_after,
            budgeter_reserved_bytes_before,
            budgeter_reserved_bytes_after: stats_after.budgeter_reserved_bytes,
            registry_reserved_bytes_after: stats_after.reserved_bytes,
            accounting_equation_valid_after: stats_after.accounting_equation_valid,
            journal_seq: seq,
            journal_head_sha256: self.journal.head_sha256().to_string(),
        })
    }

    fn pre_free_failure(
        &mut self,
        key: AllocationRecordKey,
        recovery: bool,
        error: &ForgeError,
    ) -> ForgeError {
        if recovery {
            error.clone()
        } else {
            self.quarantine(key, error)
        }
    }

    fn quarantine(&mut self, key: AllocationRecordKey, error: &ForgeError) -> ForgeError {
        self.quarantine_with_failure(key, error, error.code())
    }

    fn quarantine_with_failure(
        &mut self,
        key: AllocationRecordKey,
        error: &ForgeError,
        failure_code: &str,
    ) -> ForgeError {
        let Some(identity) = self.blocks.get(&key).map(|block| block.identity.clone()) else {
            return identity_error(format!(
                "cannot quarantine missing allocation record: block_id={} generation={} ptr={}",
                key.0.block_id.0, key.0.allocation_generation, key.1.0
            ));
        };
        let mut detail = error.to_string();
        let failure_code = failure_code.to_string();
        let newly_quarantined = !self.quarantined_keys.contains(&key);
        if newly_quarantined {
            let size_bytes = identity.size_bytes;
            let Some(total) = self.quarantined_reserved_bytes.checked_add(size_bytes) else {
                return quarantine_error(
                    &identity,
                    format!("{detail}; quarantined-byte counter overflowed before mutation"),
                );
            };
            self.quarantined_keys.insert(key);
            self.quarantined_reserved_bytes = total;
        }
        self.remove_active_if_exact(key);
        if let Some(index) = self.lru.iter().position(|candidate| *candidate == key) {
            self.lru.remove(index);
        }

        let (observation, observation_error) = match self.dealloc.device_observation() {
            Ok(observation) => (Some(observation), None),
            Err(observation_error) => {
                detail.push_str(&format!(
                    "; quarantine device observation failed: {observation_error}"
                ));
                (None, Some(observation_error))
            }
        };
        if let Some(block) = self.blocks.get_mut(&key) {
            block.state = AllocationLifecycle::Quarantined {
                failure_code: failure_code.clone(),
                detail: detail.clone(),
            };
        }
        if failure_code == "CALYX_FORGE_GPU_ALLOCATION_JOURNAL" {
            return quarantine_error(
                &identity,
                format!("{detail}; no further journal write was attempted after the journal fault"),
            );
        }
        if let Err(journal_error) = self.append_event(
            key,
            "quarantined",
            &detail,
            Some(&failure_code),
            observation,
            observation_error.as_ref(),
        ) {
            return quarantine_error(
                &identity,
                format!("{detail}; allocation journal also failed: {journal_error}"),
            );
        }
        quarantine_error(&identity, detail)
    }

    fn append_event(
        &mut self,
        key: AllocationRecordKey,
        transition: &str,
        detail: &str,
        failure_code: Option<&str>,
        observation: Option<DeviceMemoryObservation>,
        observation_error: Option<&ForgeError>,
    ) -> Result<()> {
        let block = self
            .blocks
            .get(&key)
            .ok_or_else(|| identity_error("journal event allocation is not tracked"))?;
        self.journal.append(AllocationJournalEvent {
            transition: transition.to_string(),
            block_id: key.0.block_id.0,
            allocation_generation: key.0.allocation_generation,
            owner: block.identity.owner.clone(),
            device_uuid: block.identity.device.canonical_uuid(),
            device_ptr: block.identity.ptr.0,
            size_bytes: block.identity.size_bytes,
            state: block.state.label().to_string(),
            failure_code: failure_code.map(str::to_string),
            detail: detail.to_string(),
            observed_device_uuid: observation.map(|value| value.device.canonical_uuid()),
            device_free_bytes: observation.map(|value| value.free_bytes),
            device_total_bytes: observation.map(|value| value.total_bytes),
            observation_failure_code: observation_error.map(|error| error.code().to_string()),
            observation_failure_detail: observation_error.map(ToString::to_string),
        })
    }

    fn remove_tracking(&mut self, key: AllocationRecordKey) -> Result<()> {
        let block = self.blocks.get(&key).ok_or_else(|| {
            identity_error("release path lost the exact allocation before removal")
        })?;
        let next_quarantined_bytes = if self.quarantined_keys.contains(&key) {
            Some(
                self.quarantined_reserved_bytes
                    .checked_sub(block.identity.size_bytes)
                    .ok_or_else(|| {
                        identity_error(
                            "quarantined-byte counter did not include the exact allocation",
                        )
                    })?,
            )
        } else {
            None
        };
        self.remove_active_if_exact(key);
        if let Some(index) = self.lru.iter().position(|candidate| *candidate == key) {
            self.lru.remove(index);
        }
        let block = self.blocks.remove(&key).ok_or_else(|| {
            identity_error("release path lost the exact allocation during removal")
        })?;
        if let Some(next_quarantined_bytes) = next_quarantined_bytes {
            self.quarantined_keys.remove(&key);
            self.quarantined_reserved_bytes = next_quarantined_bytes;
        }
        drop(block);
        Ok(())
    }

    fn refuse_quarantined_admission(&self) -> Result<()> {
        let Some(key) = self.quarantined_keys.first() else {
            return Ok(());
        };
        let block = self.block(*key)?;
        Err(quarantine_error(
            &block.identity,
            format!(
                "unsafe admission refused: quarantined_blocks={} quarantined_bytes={}",
                self.quarantined_keys.len(),
                self.quarantined_reserved_bytes
            ),
        ))
    }

    fn has_quarantine_except(&self, key: AllocationRecordKey) -> bool {
        self.quarantined_keys.len() > usize::from(self.quarantined_keys.contains(&key))
    }

    fn oldest_frontier_key(&self) -> Option<AllocationRecordKey> {
        self.lru.iter().copied().find(|key| {
            self.blocks.get(key).is_some_and(|block| {
                block.kind == BlockKind::Frontier
                    && matches!(block.state, AllocationLifecycle::Resident)
            })
        })
    }

    fn move_to_mru(&mut self, key: AllocationRecordKey) {
        if let Some(index) = self.lru.iter().position(|candidate| *candidate == key) {
            self.lru.remove(index);
        }
        self.lru.push_back(key);
    }

    fn remove_active_if_exact(&mut self, key: AllocationRecordKey) {
        if self.active_by_id.get(&key.0.block_id) == Some(&key) {
            self.active_by_id.remove(&key.0.block_id);
        }
    }

    fn block(&self, key: AllocationRecordKey) -> Result<&GpuBlock<'b, P>> {
        self.blocks.get(&key).ok_or_else(|| {
            identity_error(format!(
                "allocation record is missing: block_id={} generation={} ptr={}",
                key.0.block_id.0, key.0.allocation_generation, key.1.0
            ))
        })
    }
}

fn identity_error(detail: impl Into<String>) -> ForgeError {
    ForgeError::RuntimeBoundary {
        code: "CALYX_FORGE_GPU_ALLOCATION_IDENTITY_MISMATCH",
        detail: detail.into(),
        remediation: IDENTITY_REMEDIATION,
    }
}

fn quarantine_error(identity: &GpuAllocationIdentity, detail: impl Into<String>) -> ForgeError {
    ForgeError::RuntimeBoundary {
        code: "CALYX_FORGE_GPU_DEALLOCATION_QUARANTINED",
        detail: format!(
            "block_id={} generation={} owner={:?} device={} ptr={} bytes={} {}",
            identity.key.block_id.0,
            identity.key.allocation_generation,
            identity.owner,
            identity.device,
            identity.ptr.0,
            identity.size_bytes,
            detail.into()
        ),
        remediation: DEALLOCATION_REMEDIATION,
    }
}

fn checked_block_bytes(
    values: impl IntoIterator<Item = usize>,
    label: &'static str,
) -> Result<usize> {
    values.into_iter().try_fold(0_usize, |total, value| {
        total
            .checked_add(value)
            .ok_or_else(|| identity_error(format!("{label} overflow")))
    })
}
