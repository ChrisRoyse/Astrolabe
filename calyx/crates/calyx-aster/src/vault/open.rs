use super::*;

impl<C> AsterVault<C>
where
    C: Clock,
{
    /// Opens a durable vault with an injected clock.
    pub fn open_with_clock(
        vault_dir: impl AsRef<Path>,
        vault_id: VaultId,
        vault_salt: impl Into<Vec<u8>>,
        options: VaultOptions,
        clock: C,
    ) -> Result<Self> {
        let total_started = std::time::Instant::now();
        let total_usage_before = current_process_usage()?;
        // Startup guard (#276): refuse to open a durable vault if crash-injection
        // failpoints are armed in an optimized, non-test build. No-op in normal
        // and debug/test builds.
        crate::vault::failpoints::guard_against_production_failpoints()?;
        DurableVault::validate_options(&options)?;
        let clock = std::sync::Arc::new(clock);
        let vault_root = vault_dir.as_ref().to_path_buf();
        let read_snapshot_lock_started = std::time::Instant::now();
        let read_snapshot_lock_usage_before = current_process_usage()?;
        let read_snapshot_guard = if options.read_only {
            Some(crate::file_lock::FileLockGuard::acquire_shared_existing(
                &vault_root.join("locks").join("durable.commit.lock"),
            )?)
        } else {
            None
        };
        let read_snapshot_lock_us = elapsed_us(read_snapshot_lock_started);
        let read_snapshot_lock_usage =
            current_process_usage()?.phase_since(read_snapshot_lock_usage_before);
        let recovery_started = std::time::Instant::now();
        let recovery_usage_before = current_process_usage()?;
        let recovery = DurableVault::recover_batches(vault_dir.as_ref(), &options)?;
        let recovery_us = elapsed_us(recovery_started);
        let recovery_usage = current_process_usage()?.phase_since(recovery_usage_before);
        let ledger_hook_started = std::time::Instant::now();
        let ledger_hook_usage_before = current_process_usage()?;
        let ledger_hook = if options.restore_ledger_hook {
            Some(ledger_hook::recover_hook_from_vault_dir(
                vault_dir.as_ref(),
                &recovery,
                options.ledger_checkpoint.clone(),
                options.tiering_policy.as_ref(),
                std::sync::Arc::clone(&clock),
            )?)
        } else {
            None
        };
        let ledger_hook_us = elapsed_us(ledger_hook_started);
        let ledger_hook_usage = current_process_usage()?.phase_since(ledger_hook_usage_before);
        let recovery_report = VaultRecoveryReport {
            last_recovered_seq: recovery.last_recovered_seq,
            torn_tail: recovery.torn_tail.clone(),
        };
        let router_started = std::time::Instant::now();
        let router_usage_before = current_process_usage()?;
        let mut router = match &options.selected_cfs {
            Some(cfs) if options.read_only => CfRouter::open_selected_existing_cfs(
                vault_dir.as_ref(),
                options.memtable_byte_cap,
                cfs.iter().copied(),
            )?,
            Some(cfs) => CfRouter::open_selected_cfs(
                vault_dir.as_ref(),
                options.memtable_byte_cap,
                cfs.iter().copied(),
            )?,
            None if options.read_only && recovery.mode == durable::RecoveryMode::LatestRouter => {
                CfRouter::open_existing_latest(vault_dir.as_ref(), options.memtable_byte_cap)?
            }
            None if options.read_only => {
                CfRouter::open_existing(vault_dir.as_ref(), options.memtable_byte_cap)?
            }
            None if recovery.mode == durable::RecoveryMode::LatestRouter => {
                CfRouter::open_with_tiering_latest(
                    vault_dir.as_ref(),
                    options.memtable_byte_cap,
                    options.tiering_policy.clone(),
                )?
            }
            None => CfRouter::open_with_tiering(
                vault_dir.as_ref(),
                options.memtable_byte_cap,
                options.tiering_policy.clone(),
            )?,
        };
        if recovery.mode == durable::RecoveryMode::LatestRouter {
            router.replay_latest_rows(recovery.batches.iter().flat_map(|batch| {
                batch
                    .rows
                    .iter()
                    .map(move |row| (batch.seq, row.cf, row.key.as_slice(), row.value.as_slice()))
            }))?;
        }
        let router_us = elapsed_us(router_started);
        let router_usage = current_process_usage()?.phase_since(router_usage_before);
        let rows = if recovery.mode == durable::RecoveryMode::LatestRouter {
            VersionedCfStore::new_with_router_latest_readback(recovery.last_recovered_seq, router)
        } else {
            VersionedCfStore::new_with_router(recovery.last_recovered_seq, router)
        };
        // Derived-content watermark (issue #1100): the manifest floor vouches
        // for checkpointed seqs; replayed batches below re-derive the rest
        // from their CFs.
        rows.advance_derived_content_seq_to_at_least(recovery.derived_content_floor_seq);
        // WAL-tail batches have no durable-batch SSTs yet; write-capable
        // handles must re-stage them so no later manifest advance can strand
        // them behind the WAL replay floor (issue #1132).
        let wal_tail_batches: Vec<(u64, Vec<encode::WriteRow>)> = if options.read_only {
            Vec::new()
        } else {
            recovery
                .batches
                .iter()
                .filter(|batch| batch.seq > recovery.wal_replay_floor_seq)
                .map(|batch| (batch.seq, batch.rows.clone()))
                .collect()
        };
        for batch in recovery.batches {
            match recovery.mode {
                durable::RecoveryMode::FullMvcc => {
                    let rows_at_seq = batch
                        .rows
                        .into_iter()
                        .map(|row| (row.cf, row.key, row.value));
                    rows.restore_mvcc_batch(batch.seq, rows_at_seq)?;
                }
                durable::RecoveryMode::LatestRouter => {
                    if batch
                        .rows
                        .iter()
                        .any(|row| row.cf.feeds_derived_search_content())
                    {
                        rows.advance_derived_content_seq_to_at_least(batch.seq);
                    }
                }
            }
        }
        rows.set_start_seq(recovery.last_recovered_seq)?;
        if recovery.mode == durable::RecoveryMode::FullMvcc {
            // Full-restore contract (issue #1132): every row physically held
            // in Router-class SSTs must be visible to the restored MVCC state,
            // otherwise snapshot reads on this handle silently miss it.
            let violations = durable::router_coverage::router_only_rows(
                vault_dir.as_ref(),
                options.tiering_policy.as_ref(),
                |cf, key| rows.has_any_version(cf, key),
            )?;
            if !violations.is_empty() {
                return Err(durable::router_coverage::router_only_rows_error(
                    &violations,
                ));
            }
        }
        let mut durable_options = options.clone();
        durable_options.temporal_policy = recovery.temporal_policy;
        durable_options.dedup_policy = recovery.dedup_policy;
        durable_options.retention_horizon = recovery.retention_horizon.clone();
        let dedup_policy = durable_options.dedup_policy.clone().unwrap_or_default();
        let retention_horizon = durable_options.retention_horizon.clone();
        let durable = if options.read_only {
            None
        } else {
            let durable = DurableVault::open_after(
                vault_dir.as_ref(),
                &durable_options,
                recovery.wal_replay_floor_seq,
            )?;
            durable.stage_recovered_wal_batches(wal_tail_batches)?;
            Some(durable)
        };
        // Data residency (PRD 30 §4): a caller-supplied pin is enforced against
        // tiering and persisted (conflict-checked, immutable); on reopen the
        // on-disk pin is authoritative and re-enforced against tiering.
        if let Some(pin) = &options.residency {
            if let Some(tiering) = &options.tiering_policy {
                pin.enforce_tier_roots(&tiering.tier_roots())?;
            }
            pin.persist(&vault_root)?;
        }
        let residency = crate::residency::Residency::load(&vault_root)?;
        if options.residency.is_none()
            && let (Some(pin), Some(tiering)) = (&residency, &options.tiering_policy)
        {
            pin.enforce_tier_roots(&tiering.tier_roots())?;
        }
        let open_diagnostics = VaultOpenDiagnostics {
            read_snapshot_lock_us,
            read_snapshot_lock_usage,
            recovery_us,
            recovery_usage,
            ledger_hook_us,
            ledger_hook_usage,
            router_us,
            router_usage,
            total_us: elapsed_us(total_started),
            total_usage: current_process_usage()?.phase_since(total_usage_before),
        };
        Ok(Self {
            vault_id,
            vault_salt: vault_salt.into(),
            clock,
            rows,
            durable,
            durable_root: Some(vault_root),
            durable_tiering_policy: options.tiering_policy.clone(),
            dedup_policy,
            retention_horizon: Mutex::new(retention_horizon),
            ledger_hook,
            read_only: options.read_only,
            recurrence_write_lock: Mutex::new(()),
            recovery_report,
            residency,
            _read_snapshot_guard: read_snapshot_guard,
            open_diagnostics,
        })
    }
}

fn elapsed_us(started: std::time::Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}

pub(super) fn current_process_usage() -> Result<VaultProcessUsage> {
    use windows_sys::Win32::Foundation::{FILETIME, GetLastError};
    use windows_sys::Win32::System::ProcessStatus::{
        K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetProcessIoCounters, GetProcessTimes, IO_COUNTERS,
    };

    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    let mut io = IO_COUNTERS::default();
    let mut memory: PROCESS_MEMORY_COUNTERS = unsafe { std::mem::zeroed() };
    let process = unsafe { GetCurrentProcess() };
    // SAFETY: the pseudo-handle is valid in this process and every pointer
    // names a correctly sized writable Windows POD.
    unsafe {
        if GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user) == 0 {
            return Err(process_usage_error("GetProcessTimes", GetLastError()));
        }
        if GetProcessIoCounters(process, &mut io) == 0 {
            return Err(process_usage_error("GetProcessIoCounters", GetLastError()));
        }
        if K32GetProcessMemoryInfo(
            process,
            &raw mut memory,
            std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        ) == 0
        {
            return Err(process_usage_error(
                "K32GetProcessMemoryInfo",
                GetLastError(),
            ));
        }
    }
    Ok(VaultProcessUsage {
        kernel_time_100ns: filetime_value(kernel),
        user_time_100ns: filetime_value(user),
        read_operations: io.ReadOperationCount,
        read_bytes: io.ReadTransferCount,
        write_operations: io.WriteOperationCount,
        write_bytes: io.WriteTransferCount,
        page_faults: u64::from(memory.PageFaultCount),
        working_set_bytes: memory.WorkingSetSize as u64,
        peak_working_set_bytes: memory.PeakWorkingSetSize as u64,
        private_bytes: memory.PagefileUsage as u64,
        peak_private_bytes: memory.PeakPagefileUsage as u64,
    })
}

fn filetime_value(value: windows_sys::Win32::Foundation::FILETIME) -> u64 {
    (u64::from(value.dwHighDateTime) << 32) | u64::from(value.dwLowDateTime)
}

fn process_usage_error(operation: &str, os_code: u32) -> CalyxError {
    CalyxError {
        code: "CALYX_VAULT_OPEN_PROCESS_METRICS",
        message: format!("{operation} failed with Win32 error {os_code}"),
        remediation: "inspect the native process-query failure; durable open phase diagnostics are mandatory",
    }
}
