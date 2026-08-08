use super::{AsterVault, VaultOpenDiagnostics, VaultRecoveryReport};
use crate::cf::CfRouter;
use crate::dedup::DedupPolicy;
use crate::mvcc::{Freshness, LatestOnlyReadbackStatus, Snapshot, VersionedCfStore};
use crate::sst::SstSummary;
use crate::timetravel::RetentionHorizon;
use calyx_core::{Clock, Result, Seq};

impl<C> AsterVault<C>
where
    C: Clock,
{
    pub fn with_clock_and_router(
        vault_id: calyx_core::VaultId,
        vault_salt: impl Into<Vec<u8>>,
        clock: C,
        router: CfRouter,
    ) -> Self {
        Self {
            vault_id,
            vault_salt: vault_salt.into(),
            clock: std::sync::Arc::new(clock),
            rows: VersionedCfStore::new_with_router(0, router),
            durable: None,
            durable_root: None,
            durable_tiering_policy: None,
            dedup_policy: DedupPolicy::default(),
            retention_horizon: std::sync::Mutex::new(RetentionHorizon::default()),
            ledger_hook: None,
            read_only: false,
            recurrence_write_lock: std::sync::Mutex::new(()),
            recovery_report: VaultRecoveryReport {
                last_recovered_seq: 0,
                torn_tail: None,
            },
            residency: None,
            _read_snapshot_guard: None,
            open_diagnostics: VaultOpenDiagnostics::default(),
        }
    }

    pub fn pin_stale_snapshot(&self, max_lag: Seq) -> Snapshot {
        self.rows.pin_snapshot(
            Freshness::StaleOk { max_lag },
            &self.clock,
            crate::knobs::SNAPSHOT_PIN_STALL_WINDOW_MS.default,
        )
    }

    pub fn flush_all_cfs(&self) -> Result<Vec<SstSummary>> {
        self.rows.flush_all_cfs()
    }

    /// Exact latest-only/overlay/memtable state used to admit bounded scans.
    pub fn latest_only_readback_status(&self) -> LatestOnlyReadbackStatus {
        self.rows.latest_only_readback_status()
    }
}
