#[cfg(not(feature = "cuda"))]
fn main() {
    eprintln!("CALYX_FORGE_GPU_ALLOCATION_FSV_FEATURE_MISSING: build with --features cuda");
    std::process::exit(2);
}

#[cfg(feature = "cuda")]
mod enabled {
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::ptr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, MutexGuard};
    use std::time::{Duration, Instant};

    use calyx_forge::{
        AdmissionController, AllocationJournal, AllocationKey, BlockDeallocator, BlockId,
        BlockKind, CudaVramProbe, DeviceAllocationState, DeviceMemoryObservation, DevicePtr,
        ForgeError, GpuAllocationIdentity, GpuBlockRegistry, PinnedCudaDeviceIdentity,
        RawCudaBlockDeallocator, Result as ForgeResult, VramBudgeter,
        configured_cuda_runtime_ordinal, init_cuda_native_kernel,
    };
    use cudarc::driver::result;
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};

    const ALLOCATION_BYTES: usize = 64 * 1024 * 1024;
    const SOFT_CAP_BYTES: usize = 256 * 1024 * 1024;
    const FAILURE_CODE: &str = "CALYX_FSV_INDUCED_CUDA_FREE_FAILURE";
    const DEVICE_FAILURE_CODE: &str = "CALYX_FSV_INDUCED_DEVICE_UNAVAILABLE";

    type AnyResult<T> = Result<T, Box<dyn std::error::Error>>;

    #[derive(Clone)]
    struct InducedFailureDeallocator {
        raw: RawCudaBlockDeallocator,
        fail_free_once: Arc<AtomicBool>,
        fail_observation_once: Arc<AtomicBool>,
    }

    impl InducedFailureDeallocator {
        fn new(raw: RawCudaBlockDeallocator) -> Self {
            Self {
                raw,
                fail_free_once: Arc::new(AtomicBool::new(false)),
                fail_observation_once: Arc::new(AtomicBool::new(false)),
            }
        }

        fn arm_free_failure(&self) {
            self.fail_free_once.store(true, Ordering::Release);
        }

        fn arm_observation_failure(&self) {
            self.fail_observation_once.store(true, Ordering::Release);
        }

        fn detach_current_context(&self) -> ForgeResult<()> {
            self.raw
                .context()
                .inner()
                .bind_to_thread()
                .map_err(driver_boundary_error)?;
            unsafe { result::ctx::set_current(ptr::null_mut()) }.map_err(driver_boundary_error)
        }

        fn restore_current_context(&self) -> ForgeResult<()> {
            self.raw
                .context()
                .inner()
                .bind_to_thread()
                .map_err(driver_boundary_error)
        }
    }

    impl BlockDeallocator for InducedFailureDeallocator {
        fn device_observation(&self) -> ForgeResult<DeviceMemoryObservation> {
            if !self.fail_observation_once.swap(false, Ordering::AcqRel) {
                return self.raw.device_observation();
            }
            self.detach_current_context()?;
            let observed = result::mem_get_info();
            self.restore_current_context()?;
            match observed {
                Err(error) => Err(ForgeError::RuntimeBoundary {
                    code: DEVICE_FAILURE_CODE,
                    detail: format!(
                        "real cuMemGetInfo with no current CUDA context failed as induced: status={:?} numeric={}",
                        error.0, error.0 as i32
                    ),
                    remediation: "restore the exact pinned CUDA context before retrying the same allocation generation",
                }),
                Ok((free_bytes, total_bytes)) => Err(ForgeError::RuntimeBoundary {
                    code: "CALYX_FSV_CUDA_FAILURE_INDUCTION_FAILED",
                    detail: format!(
                        "cuMemGetInfo unexpectedly succeeded with no current context: free={free_bytes} total={total_bytes}"
                    ),
                    remediation: "do not accept this FSV run; inspect the installed CUDA driver context semantics",
                }),
            }
        }

        fn allocation_state(&self, ptr: DevicePtr) -> ForgeResult<DeviceAllocationState> {
            self.raw.allocation_state(ptr)
        }

        fn free(&self, ptr: DevicePtr, size_bytes: usize) -> ForgeResult<()> {
            if !self.fail_free_once.swap(false, Ordering::AcqRel) {
                return self.raw.free(ptr, size_bytes);
            }
            self.detach_current_context()?;
            let observed = unsafe { result::free_sync(ptr.0) };
            self.restore_current_context()?;
            match observed {
                Err(error) => Err(ForgeError::RuntimeBoundary {
                    code: FAILURE_CODE,
                    detail: format!(
                        "real cuMemFree with no current CUDA context failed as induced: status={:?} numeric={}",
                        error.0, error.0 as i32
                    ),
                    remediation: "retain the exact allocation and restore the pinned CUDA context before explicit recovery",
                }),
                Ok(()) => Err(ForgeError::RuntimeBoundary {
                    code: "CALYX_FSV_CUDA_FAILURE_INDUCTION_FAILED",
                    detail: "cuMemFree unexpectedly succeeded with no current CUDA context"
                        .to_string(),
                    remediation: "do not accept this FSV run; inspect the installed CUDA driver context semantics",
                }),
            }
        }
    }

    pub fn run() -> AnyResult<()> {
        let output_dir = std::env::args_os()
            .nth(1)
            .map(PathBuf::from)
            .ok_or("usage: gpu_allocation_ownership_fsv <fresh-output-directory>")?;
        prepare_fresh_output(&output_dir)?;

        let context = Arc::new(init_cuda_native_kernel(
            configured_cuda_runtime_ordinal()?,
            true,
        )?);
        context.attest_physical_identity()?;
        context
            .inner()
            .synchronize()
            .map_err(driver_boundary_error)?;
        let raw = RawCudaBlockDeallocator::new(Arc::clone(&context));
        let injected = InducedFailureDeallocator::new(raw.clone());
        let budgeter =
            VramBudgeter::with_soft_cap(SOFT_CAP_BYTES, CudaVramProbe::new(Arc::clone(&context)));
        let journal_path = output_dir.join("allocation-journal.ndjson");
        let registry = Arc::new(Mutex::new(GpuBlockRegistry::open(
            &budgeter,
            injected.clone(),
            8,
            &journal_path,
        )?));
        let admission = AdmissionController::new(&budgeter, Arc::clone(&registry), 0, 1);

        let initial = capture_locked_state("initial", &registry, &raw)?;
        write_state(&output_dir, "00-initial.json", &initial)?;

        let happy_key = AllocationKey {
            block_id: BlockId(872_001),
            allocation_generation: 1,
        };
        let happy_ptr =
            allocate_tracked(&context, &budgeter, &registry, happy_key, "issue-872-happy")?;
        let happy_before = capture_locked_state("happy_before", &registry, &raw)?;
        let happy_receipt = lock_registry(&registry)?
            .evict_lru()?
            .ok_or("happy allocation was not evicted")?;
        require(
            happy_receipt == ALLOCATION_BYTES,
            "happy eviction byte count differed from the allocation",
        )?;
        require_absent(&raw, happy_ptr, "happy allocation after eviction")?;
        let happy_after = capture_locked_state("happy_after", &registry, &raw)?;
        write_transition(
            &output_dir,
            "10-happy.json",
            "happy_cuda_free",
            &happy_before,
            json!({"freed_bytes": happy_receipt, "pointer": happy_ptr.0}),
            &happy_after,
        )?;

        let quarantine_key = AllocationKey {
            block_id: BlockId(872_002),
            allocation_generation: 2,
        };
        let quarantine_ptr = allocate_tracked(
            &context,
            &budgeter,
            &registry,
            quarantine_key,
            "issue-872-quarantine",
        )?;
        let before_failed_free = capture_locked_state("failed_free_before", &registry, &raw)?;
        injected.arm_free_failure();
        let failed_free = lock_registry(&registry)?
            .evict_lru()
            .expect_err("induced cuMemFree failure must quarantine the allocation");
        require(
            failed_free.code() == "CALYX_FORGE_GPU_DEALLOCATION_QUARANTINED",
            "induced cuMemFree failure did not surface the quarantine code",
        )?;
        require_present(
            &raw,
            quarantine_ptr,
            ALLOCATION_BYTES,
            "allocation after induced cuMemFree failure",
        )?;
        let after_failed_free = capture_locked_state("failed_free_after", &registry, &raw)?;
        require_quarantine_accounting(&after_failed_free)?;
        write_transition(
            &output_dir,
            "20-induced-free-failure.json",
            "real_cuda_free_failure",
            &before_failed_free,
            error_value(&failed_free),
            &after_failed_free,
        )?;

        let admission_before = capture_locked_state("admission_before", &registry, &raw)?;
        let callback_ran = AtomicBool::new(false);
        let admission_error = admission
            .run_with_admission(
                1,
                1,
                Instant::now() + Duration::from_secs(10),
                |_offset, _len| {
                    callback_ran.store(true, Ordering::Release);
                    Ok(())
                },
            )
            .expect_err("quarantine-dependent admission must fail closed");
        require(
            admission_error.code() == "CALYX_FORGE_GPU_DEALLOCATION_QUARANTINED"
                && !callback_ran.load(Ordering::Acquire),
            "unsafe admission did not refuse before dispatch",
        )?;
        let admission_after = capture_locked_state("admission_after", &registry, &raw)?;
        require_same_state(
            &admission_before,
            &admission_after,
            "unsafe admission refusal",
        )?;
        write_transition(
            &output_dir,
            "30-admission-refusal.json",
            "quarantine_blocks_admission",
            &admission_before,
            error_value(&admission_error),
            &admission_after,
        )?;

        exercise_identity_edges(
            &output_dir,
            &context,
            &registry,
            &injected,
            &raw,
            quarantine_key,
            quarantine_ptr,
        )?;

        let recovery_before = capture_locked_state("recovery_before", &registry, &raw)?;
        let recovery_receipt = lock_registry(&registry)?.recover_quarantined(
            quarantine_key,
            quarantine_ptr,
            context.physical_identity(),
        )?;
        require_absent(
            &raw,
            quarantine_ptr,
            "quarantined allocation after recovery",
        )?;
        let recovery_after = capture_locked_state("recovery_after", &registry, &raw)?;
        require_released_accounting(&recovery_after)?;
        write_transition(
            &output_dir,
            "50-recovery.json",
            "exact_generation_recovery",
            &recovery_before,
            serde_json::to_value(&recovery_receipt)?,
            &recovery_after,
        )?;

        let final_stats = lock_registry(&registry)?.stats()?;
        let final_journal = AllocationJournal::open(&journal_path)?;
        require(
            final_journal.next_seq() == final_stats.journal_entries
                && final_journal.head_sha256() == final_stats.journal_head_sha256,
            "independent journal reopen disagreed with registry telemetry",
        )?;
        let nvidia_smi = capture_nvidia_smi(&output_dir)?;
        context.attest_physical_identity()?;
        let report = json!({
            "schema": "calyx.forge.gpu-allocation-ownership-fsv.v1",
            "issue": 872,
            "physical_device": context.physical_identity(),
            "device_name": context.name(),
            "allocation_bytes": ALLOCATION_BYTES,
            "final_stats": final_stats,
            "journal_readback": {
                "path": journal_path,
                "entries": final_journal.next_seq(),
                "head_sha256": final_journal.head_sha256(),
            },
            "nvidia_smi": nvidia_smi,
            "evidence_files": sorted_file_names(&output_dir)?,
        });
        write_state(&output_dir, "report.json", &report)?;
        let report_bytes = fs::read(output_dir.join("report.json"))?;
        let report_sha256 = hex_lower(&Sha256::digest(&report_bytes));
        write_bytes(
            &output_dir.join("report.sha256"),
            format!("{report_sha256}  report.json\r\n").as_bytes(),
        )?;
        println!(
            "{}",
            serde_json::to_string(&json!({
                "event": "gpu_allocation_ownership_fsv_readback",
                "report_sha256": report_sha256,
                "report": serde_json::from_slice::<Value>(&report_bytes)?,
            }))?
        );
        Ok(())
    }

    fn exercise_identity_edges<'b>(
        output_dir: &Path,
        context: &Arc<calyx_forge::CudaContext>,
        registry: &Arc<Mutex<GpuBlockRegistry<'b, CudaVramProbe, InducedFailureDeallocator>>>,
        injected: &InducedFailureDeallocator,
        raw: &RawCudaBlockDeallocator,
        key: AllocationKey,
        ptr: DevicePtr,
    ) -> AnyResult<()> {
        let wrong_generation = AllocationKey {
            block_id: key.block_id,
            allocation_generation: key.allocation_generation + 1,
        };
        exercise_refusal_edge(
            output_dir,
            "40-edge-wrong-generation.json",
            "wrong_generation",
            registry,
            raw,
            || {
                lock_registry(registry)?.recover_quarantined(
                    wrong_generation,
                    ptr,
                    context.physical_identity(),
                )?;
                Ok(())
            },
        )?;

        context.inner().bind_to_thread()?;
        let other_ptr = DevicePtr(unsafe { result::malloc_sync(ALLOCATION_BYTES) }?);
        require(
            other_ptr != ptr,
            "second live CUDA allocation reused the still-present quarantined pointer",
        )?;
        exercise_refusal_edge(
            output_dir,
            "41-edge-reused-pointer.json",
            "live_wrong_pointer_token",
            registry,
            raw,
            || {
                lock_registry(registry)?.recover_quarantined(
                    key,
                    other_ptr,
                    context.physical_identity(),
                )?;
                Ok(())
            },
        )?;
        raw.free(other_ptr, ALLOCATION_BYTES)?;
        require_absent(raw, other_ptr, "secondary edge allocation after cleanup")?;

        let mut wrong_uuid = context.physical_identity().uuid_bytes();
        wrong_uuid[15] ^= 1;
        let wrong_device = PinnedCudaDeviceIdentity::from_pci_and_uuid_bytes(
            &context.physical_identity().canonical_pci_bus_id(),
            wrong_uuid,
        )
        .map_err(std::io::Error::other)?;
        exercise_refusal_edge(
            output_dir,
            "42-edge-wrong-device.json",
            "wrong_device_identity",
            registry,
            raw,
            || {
                lock_registry(registry)?.recover_quarantined(key, ptr, wrong_device)?;
                Ok(())
            },
        )?;

        injected.arm_observation_failure();
        let unavailable = exercise_refusal_edge(
            output_dir,
            "43-edge-unavailable-device.json",
            "real_unavailable_device",
            registry,
            raw,
            || {
                lock_registry(registry)?.recover_quarantined(
                    key,
                    ptr,
                    context.physical_identity(),
                )?;
                Ok(())
            },
        )?;
        require(
            unavailable["action"]["code"] == DEVICE_FAILURE_CODE,
            "unavailable-device edge did not contain the real detached-context driver failure",
        )?;
        require(
            lock_registry(registry)?.stats()?.budgeter_reserved_bytes == ALLOCATION_BYTES,
            "identity edges changed the retained budget reservation",
        )?;
        Ok(())
    }

    fn exercise_refusal_edge<'b, F>(
        output_dir: &Path,
        file_name: &str,
        name: &str,
        registry: &Arc<Mutex<GpuBlockRegistry<'b, CudaVramProbe, InducedFailureDeallocator>>>,
        raw: &RawCudaBlockDeallocator,
        action: F,
    ) -> AnyResult<Value>
    where
        F: FnOnce() -> AnyResult<()>,
    {
        let before = capture_locked_state(&format!("{name}_before"), registry, raw)?;
        let error = action().expect_err("identity/device edge must refuse without mutation");
        let after = capture_locked_state(&format!("{name}_after"), registry, raw)?;
        require_same_state(&before, &after, name)?;
        let transition = json!({
            "edge": name,
            "before": before,
            "action": {
                "code": forge_code_from_error(error.as_ref()),
                "detail": error.to_string(),
            },
            "after": after,
        });
        write_state(output_dir, file_name, &transition)?;
        println!("{}", serde_json::to_string(&transition)?);
        Ok(transition)
    }

    fn allocate_tracked<'b>(
        context: &Arc<calyx_forge::CudaContext>,
        budgeter: &'b VramBudgeter<CudaVramProbe>,
        registry: &Arc<Mutex<GpuBlockRegistry<'b, CudaVramProbe, InducedFailureDeallocator>>>,
        key: AllocationKey,
        owner: &str,
    ) -> AnyResult<DevicePtr> {
        let guard = budgeter.reserve(ALLOCATION_BYTES)?;
        context.inner().bind_to_thread()?;
        let ptr = DevicePtr(unsafe { result::malloc_sync(ALLOCATION_BYTES) }?);
        lock_registry(registry)?.insert(
            GpuAllocationIdentity {
                key,
                owner: owner.to_string(),
                device: context.physical_identity(),
                ptr,
                size_bytes: ALLOCATION_BYTES,
            },
            BlockKind::General,
            guard,
        )?;
        Ok(ptr)
    }

    fn capture_state<P, D>(
        label: &str,
        registry: &GpuBlockRegistry<'_, P, D>,
        raw: &RawCudaBlockDeallocator,
    ) -> AnyResult<Value>
    where
        P: calyx_forge::VramProbe,
        D: BlockDeallocator,
    {
        let allocations = registry.allocations();
        let physical = allocations
            .iter()
            .map(|allocation| {
                Ok(json!({
                    "key": allocation.identity.key,
                    "pointer": allocation.identity.ptr,
                    "state": raw.allocation_state(allocation.identity.ptr)?,
                }))
            })
            .collect::<ForgeResult<Vec<_>>>()?;
        Ok(json!({
            "label": label,
            "device": raw.device_observation()?,
            "stats": registry.stats()?,
            "allocations": allocations,
            "physical_allocations": physical,
        }))
    }

    fn capture_locked_state<'b>(
        label: &str,
        registry: &Arc<Mutex<GpuBlockRegistry<'b, CudaVramProbe, InducedFailureDeallocator>>>,
        raw: &RawCudaBlockDeallocator,
    ) -> AnyResult<Value> {
        let registry = lock_registry(registry)?;
        capture_state(label, &registry, raw)
    }

    fn lock_registry<'a, 'b>(
        registry: &'a Arc<Mutex<GpuBlockRegistry<'b, CudaVramProbe, InducedFailureDeallocator>>>,
    ) -> AnyResult<MutexGuard<'a, GpuBlockRegistry<'b, CudaVramProbe, InducedFailureDeallocator>>>
    {
        registry
            .lock()
            .map_err(|_| "GPU allocation registry lock poisoned during FSV".into())
    }

    fn require_quarantine_accounting(state: &Value) -> AnyResult<()> {
        require(
            state["stats"]["resident_bytes"] == 0
                && state["stats"]["quarantined_bytes"] == ALLOCATION_BYTES
                && state["stats"]["reserved_bytes"] == ALLOCATION_BYTES
                && state["stats"]["budgeter_reserved_bytes"] == ALLOCATION_BYTES
                && state["stats"]["accounting_equation_valid"] == true
                && state["allocations"][0]["state"] == "quarantined"
                && state["physical_allocations"][0]["state"]["Present"]["size_bytes"]
                    == ALLOCATION_BYTES,
            "failed free did not preserve exact quarantine/accounting/physical state",
        )
    }

    fn require_released_accounting(state: &Value) -> AnyResult<()> {
        require(
            state["stats"]["resident_bytes"] == 0
                && state["stats"]["quarantined_bytes"] == 0
                && state["stats"]["reserved_bytes"] == 0
                && state["stats"]["budgeter_reserved_bytes"] == 0
                && state["stats"]["accounting_equation_valid"] == true
                && state["allocations"].as_array().is_some_and(Vec::is_empty),
            "recovery did not remove the exact record and reservation",
        )
    }

    fn require_same_state(before: &Value, after: &Value, label: &str) -> AnyResult<()> {
        let mut before = before.clone();
        let mut after = after.clone();
        before["label"] = Value::Null;
        after["label"] = Value::Null;
        require(
            before == after,
            &format!("{label} changed registry, journal, accounting, or physical allocation state"),
        )
    }

    fn require_present(
        raw: &RawCudaBlockDeallocator,
        ptr: DevicePtr,
        expected_bytes: usize,
        label: &str,
    ) -> AnyResult<()> {
        match raw.allocation_state(ptr)? {
            DeviceAllocationState::Present { base, size_bytes }
                if base == ptr && size_bytes == expected_bytes =>
            {
                Ok(())
            }
            observed => {
                Err(format!("{label}: expected exact present allocation, got {observed:?}").into())
            }
        }
    }

    fn require_absent(raw: &RawCudaBlockDeallocator, ptr: DevicePtr, label: &str) -> AnyResult<()> {
        require(
            raw.allocation_state(ptr)? == DeviceAllocationState::Absent,
            &format!("{label}: CUDA pointer remained present"),
        )
    }

    fn write_transition(
        output_dir: &Path,
        file_name: &str,
        event: &str,
        before: &Value,
        action: Value,
        after: &Value,
    ) -> AnyResult<()> {
        let value = json!({
            "event": event,
            "before": before,
            "action": action,
            "after": after,
        });
        write_state(output_dir, file_name, &value)?;
        println!("{}", serde_json::to_string(&value)?);
        Ok(())
    }

    fn capture_nvidia_smi(output_dir: &Path) -> AnyResult<Value> {
        let output = Command::new("nvidia-smi.exe")
            .args([
                "--query-gpu=index,uuid,pci.bus_id,memory.used,memory.free,memory.total",
                "--format=csv,noheader,nounits",
            ])
            .output()?;
        require(output.status.success(), "nvidia-smi GPU query failed")?;
        require(output.stderr.is_empty(), "nvidia-smi wrote stderr")?;
        write_bytes(&output_dir.join("nvidia-smi-gpu.csv"), &output.stdout)?;
        Ok(json!({
            "sha256": hex_lower(&Sha256::digest(&output.stdout)),
            "bytes": output.stdout.len(),
            "text": String::from_utf8(output.stdout)?,
        }))
    }

    fn prepare_fresh_output(path: &Path) -> AnyResult<()> {
        if path.exists() {
            require(path.is_dir(), "output path exists but is not a directory")?;
            require(
                fs::read_dir(path)?.next().is_none(),
                "output directory must be empty; preserve existing evidence",
            )?;
        } else {
            fs::create_dir_all(path)?;
        }
        Ok(())
    }

    fn write_state(output_dir: &Path, file_name: &str, value: &Value) -> AnyResult<()> {
        let mut bytes = serde_json::to_vec_pretty(value)?;
        bytes.push(b'\n');
        write_bytes(&output_dir.join(file_name), &bytes)?;
        let readback: Value = serde_json::from_slice(&fs::read(output_dir.join(file_name))?)?;
        require(readback == *value, "persisted JSON readback mismatch")
    }

    fn write_bytes(path: &Path, bytes: &[u8]) -> AnyResult<()> {
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        require(fs::read(path)? == bytes, "persisted byte readback mismatch")
    }

    fn sorted_file_names(path: &Path) -> AnyResult<Vec<String>> {
        let mut files = fs::read_dir(path)?
            .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
            .collect::<Result<Vec<_>, _>>()?;
        files.sort();
        Ok(files)
    }

    fn error_value(error: &ForgeError) -> Value {
        json!({"code": error.code(), "detail": error.to_string()})
    }

    fn forge_code_from_error(error: &(dyn std::error::Error + 'static)) -> String {
        error.downcast_ref::<ForgeError>().map_or_else(
            || "NON_FORGE_ERROR".to_string(),
            |error| error.code().to_string(),
        )
    }

    fn driver_boundary_error(error: result::DriverError) -> ForgeError {
        ForgeError::RuntimeBoundary {
            code: "CALYX_FSV_CUDA_CONTEXT_BOUNDARY",
            detail: format!(
                "CUDA driver status={:?} numeric={}",
                error.0, error.0 as i32
            ),
            remediation: "restore and re-attest the exact pinned CUDA context before continuing",
        }
    }

    fn require(condition: bool, message: &str) -> AnyResult<()> {
        if condition {
            Ok(())
        } else {
            Err(message.to_string().into())
        }
    }

    fn hex_lower(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        output
    }
}

#[cfg(feature = "cuda")]
fn main() {
    if let Err(error) = enabled::run() {
        eprintln!("CALYX_FORGE_GPU_ALLOCATION_FSV_FAILED: {error}");
        std::process::exit(1);
    }
}
