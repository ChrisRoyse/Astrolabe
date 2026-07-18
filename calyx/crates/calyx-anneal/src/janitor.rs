//! Anneal-managed operational janitor for bounded hotpool buildup.

mod fs_ops;
mod types;

pub use types::{
    CALYX_IO_ERROR, CALYX_JANITOR_ROTATION_ERROR, DatasetManifest, GcResult, JanitorConfig,
    JanitorErrorReadback, JanitorMetrics, JanitorReadback, MAX_JANITOR_BYTES_PER_TICK,
    ROTATION_STREAM_CHUNK_BYTES,
};

use calyx_aster::pressure::DiskPressureGuard;
use calyx_core::{CalyxError, Clock, Result, Ts};
use fs_ops::{
    CleanupKind, age_ms, collect_files, decode_digest, dir_size, duration_ms, ensure_inside_dataset,
    file_len, hash_path, hex, immediate_dirs, io_error, is_rotation_temp, is_zst, modified_ms,
    rotation_error, source_digest, starts_with_canonical, temp_dirs, verified_publish, zst_path,
};
use serde::Serialize;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct Janitor {
    config: JanitorConfig,
    clock: Arc<dyn Clock>,
    home: PathBuf,
    current_exe: Option<PathBuf>,
    dataset_manifest: Option<DatasetManifest>,
    counters: Arc<Mutex<JanitorMetrics>>,
}

impl Janitor {
    pub fn new(config: JanitorConfig, clock: Arc<dyn Clock>) -> Self {
        let home = env::var_os("CALYX_HOME").map_or_else(|| PathBuf::from("."), PathBuf::from);
        Self::with_home(config, clock, home)
    }

    pub fn with_home(
        config: JanitorConfig,
        clock: Arc<dyn Clock>,
        home: impl Into<PathBuf>,
    ) -> Self {
        Self {
            config,
            clock,
            home: home.into(),
            current_exe: env::current_exe().ok(),
            dataset_manifest: None,
            counters: Arc::new(Mutex::new(JanitorMetrics::default())),
        }
    }

    pub fn with_current_exe(mut self, current_exe: impl Into<PathBuf>) -> Self {
        self.current_exe = Some(current_exe.into());
        self
    }

    pub fn with_dataset_manifest(mut self, manifest: DatasetManifest) -> Self {
        self.dataset_manifest = Some(manifest);
        self
    }

    pub fn metrics(&self) -> JanitorMetrics {
        self.counters
            .lock()
            .expect("janitor counters poisoned")
            .clone()
    }

    pub fn readback(&self) -> JanitorReadback {
        JanitorReadback {
            home: self.home.clone(),
            ledger_path: self.ledger_path(),
            metrics: self.metrics(),
        }
    }

    pub fn prometheus_text(&self, vault: &str) -> String {
        self.metrics().prometheus_text(vault)
    }

    pub fn prune_logs(&self) -> Result<GcResult> {
        let mut result = GcResult::default();
        let logs = self.home.join("logs");
        if !logs.exists() {
            return Ok(result);
        }
        let now = self.clock.now();
        // Reconcile rotation temp files abandoned by a crash between temp creation
        // and publication before doing anything else. The source is always intact
        // in that window, so reclaiming the temp loses nothing.
        self.reconcile_rotation_temps(&logs, now, &mut result)?;
        for path in collect_files(&logs)? {
            if is_zst(&path) && age_ms(&path, now)? >= duration_ms(self.config.log_ttl) {
                self.delete_file(&path, CleanupKind::Log, "log_ttl_delete", &mut result)?;
            }
        }
        for path in collect_files(&logs)? {
            if is_rotation_temp(&path) {
                continue;
            }
            if !is_zst(&path) && age_ms(&path, now)? >= duration_ms(self.config.log_rotation_age) {
                self.compress_log(&path, &mut result)?;
            }
        }
        self.enforce_log_cap(&logs, &mut result)?;
        self.record_metrics(&result);
        Ok(result)
    }

    pub fn prune_build_artifacts(&self) -> Result<GcResult> {
        let mut result = GcResult::default();
        let target = self.home.join("target");
        if !target.exists() {
            return Ok(result);
        }
        let mut dirs = immediate_dirs(&target)?;
        dirs.sort_by_key(|path| modified_ms(path).unwrap_or(0));
        dirs.reverse();
        let current = self
            .current_exe
            .as_ref()
            .and_then(|path| path.canonicalize().ok());
        for (idx, dir) in dirs.into_iter().enumerate() {
            if idx < self.config.build_artifact_keep_releases {
                continue;
            }
            if current
                .as_ref()
                .is_some_and(|exe| starts_with_canonical(exe, &dir))
            {
                continue;
            }
            let bytes = dir_size(&dir)?;
            fs::remove_dir_all(&dir)
                .map_err(|error| io_error(format!("remove {}: {error}", dir.display())))?;
            result.bytes_freed = result.bytes_freed.saturating_add(bytes);
            result.artifact_bytes_freed = result.artifact_bytes_freed.saturating_add(bytes);
            result.artifact_dirs_deleted += 1;
            self.ledger_event("artifact_pruned", &dir, bytes)?;
            result.ledger_events += 1;
            result.rate_limited |= result.bytes_freed >= self.config.max_bytes_per_tick;
            if result.rate_limited {
                break;
            }
        }
        self.record_metrics(&result);
        Ok(result)
    }

    pub fn prune_temp_files(&self) -> Result<GcResult> {
        let mut result = GcResult::default();
        let now = self.clock.now();
        for temp_dir in temp_dirs(&self.home)? {
            let Some(dataset_root) = temp_dir.parent() else {
                continue;
            };
            for path in collect_files(&temp_dir)? {
                ensure_inside_dataset(dataset_root, &path)?;
                if age_ms(&path, now)? >= duration_ms(self.config.temp_ttl) {
                    self.delete_file(&path, CleanupKind::Temp, "temp_ttl_delete", &mut result)?;
                }
            }
        }
        self.record_metrics(&result);
        Ok(result)
    }

    pub fn prune_datasets(&self, manifest: &DatasetManifest) -> Result<GcResult> {
        let mut result = GcResult::default();
        if !self.config.dataset_prune_by_manifest || !manifest.datasets_dir.exists() {
            return Ok(result);
        }
        for dir in immediate_dirs(&manifest.datasets_dir)? {
            let name = dir
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default();
            if manifest.keep.contains(name) || dir.join(".calyx-active").exists() {
                continue;
            }
            let bytes = dir_size(&dir)?;
            fs::remove_dir_all(&dir)
                .map_err(|error| io_error(format!("remove {}: {error}", dir.display())))?;
            result.bytes_freed = result.bytes_freed.saturating_add(bytes);
            result.dataset_bytes_freed = result.dataset_bytes_freed.saturating_add(bytes);
            result.dataset_dirs_deleted += 1;
            self.ledger_event("dataset_pruned", &dir, bytes)?;
            result.ledger_events += 1;
        }
        self.record_metrics(&result);
        Ok(result)
    }

    pub fn run_tick(&self, disk_pressure: &DiskPressureGuard) -> Result<GcResult> {
        let mut result = GcResult {
            disk_pressure_before: disk_pressure.check().is_err(),
            ..GcResult::default()
        };
        if result.disk_pressure_before {
            disk_pressure.request_spill();
        }
        result.merge(self.prune_temp_files()?);
        result.merge(self.prune_logs()?);
        result.merge(self.prune_build_artifacts()?);
        if let Some(manifest) = &self.dataset_manifest {
            result.merge(self.prune_datasets(manifest)?);
        }
        result.disk_pressure_after = disk_pressure.check().is_err();
        if result.disk_pressure_after {
            disk_pressure.request_spill();
        }
        Ok(result)
    }

    /// Rotate a plaintext log into a verified zstd artifact. The source is deleted
    /// only after the compressed replacement has been fsynced, independently
    /// decoded, and proven byte-exact (length + BLAKE3) against the source. Any
    /// failure leaves the source completely untouched and is recorded both in the
    /// result readback and as a `log_rotation_error` ledger diagnostic — recording
    /// an error and returning success is never done.
    fn compress_log(&self, path: &Path, result: &mut GcResult) -> Result<()> {
        let before = file_len(path)?;
        // Declared input bound: refuse an oversize source with the source untouched.
        if before > self.config.log_rotation_max_bytes {
            let error = rotation_error(
                "prepared",
                format!(
                    "source {} is {before} bytes, above the declared {}-byte rotation bound; \
                     the source was not touched",
                    path.display(),
                    self.config.log_rotation_max_bytes
                ),
            );
            return self.refuse_rotation(path, error, result);
        }

        let output = zst_path(path)?;
        if output.exists() {
            // A prior rotation may have published then crashed before deleting the
            // source, or the destination is a foreign/corrupt file. Prove it decodes
            // to the current source before deleting anything.
            return self.reconcile_existing_destination(path, &output, before, result);
        }

        let stats = match verified_publish(path, &output, self.config.log_rotation_time_budget) {
            Ok(stats) => stats,
            Err(error) => return self.refuse_rotation(path, error, result),
        };

        // Concurrent-append guard: re-read the source identity immediately before
        // deletion so an append that landed during compression cannot be lost.
        let current = source_digest(path)?;
        if current.len != stats.src_len || current.hash != stats.src_hash {
            let _ = fs::remove_file(&output);
            let error = rotation_error(
                "published",
                format!(
                    "source {} changed during rotation (len {} -> {}, hash {} -> {}); \
                     deletion refused and the stale artifact was removed",
                    path.display(),
                    stats.src_len,
                    current.len,
                    hex(&stats.src_hash),
                    hex(&current.hash)
                ),
            );
            return self.refuse_rotation(path, error, result);
        }

        // Proven equal: now — and only now — is deletion of the source safe.
        fs::remove_file(path)
            .map_err(|error| io_error(format!("remove {}: {error}", path.display())))?;
        self.record_rotation(path, before, stats.compressed_len, result)
    }

    /// Complete or refuse a rotation whose destination already exists on disk.
    fn reconcile_existing_destination(
        &self,
        source: &Path,
        output: &Path,
        before: u64,
        result: &mut GcResult,
    ) -> Result<()> {
        let src = source_digest(source)?;
        let digest = match decode_digest(output) {
            Ok(digest) => digest,
            Err(error) => return self.refuse_rotation(source, error, result),
        };
        if digest.len != src.len || digest.hash != src.hash {
            let error = rotation_error(
                "published",
                format!(
                    "existing destination {} does not decode to source {} \
                     (destination len {} hash {}, source len {} hash {}); refusing to delete source",
                    output.display(),
                    source.display(),
                    digest.len,
                    hex(&digest.hash),
                    src.len,
                    hex(&src.hash)
                ),
            );
            return self.refuse_rotation(source, error, result);
        }
        let after = file_len(output).unwrap_or(0);
        fs::remove_file(source)
            .map_err(|error| io_error(format!("remove {}: {error}", source.display())))?;
        self.record_rotation(source, before, after, result)
    }

    /// Reclaim rotation temp files older than the rotation time budget: past that
    /// bound no live rotation can still be writing them, and the source is intact.
    fn reconcile_rotation_temps(
        &self,
        logs: &Path,
        now: Ts,
        result: &mut GcResult,
    ) -> Result<()> {
        let budget_ms = duration_ms(self.config.log_rotation_time_budget);
        for path in collect_files(logs)? {
            if !is_rotation_temp(&path) {
                continue;
            }
            if age_ms(&path, now)? < budget_ms {
                continue;
            }
            match fs::remove_file(&path) {
                Ok(()) => {
                    self.ledger_event("log_rotation_temp_reclaimed", &path, 0)?;
                    result.ledger_events += 1;
                }
                Err(error) => result.record_error(
                    hash_path(&path),
                    io_error(format!("remove stale rotation temp {}: {error}", path.display())),
                ),
            }
        }
        Ok(())
    }

    fn record_rotation(
        &self,
        source: &Path,
        before: u64,
        compressed_len: u64,
        result: &mut GcResult,
    ) -> Result<()> {
        let freed = before.saturating_sub(compressed_len);
        result.bytes_freed = result.bytes_freed.saturating_add(freed);
        result.log_bytes_freed = result.log_bytes_freed.saturating_add(freed);
        result.logs_compressed += 1;
        self.ledger_event("log_compressed", source, freed)?;
        result.ledger_events += 1;
        Ok(())
    }

    /// Record a fail-closed rotation refusal in both the result readback and the
    /// ledger, then return `Ok(())` so a single bad log does not abort cleanup of
    /// the remaining logs. The source is left untouched by every caller.
    fn refuse_rotation(
        &self,
        source: &Path,
        error: CalyxError,
        result: &mut GcResult,
    ) -> Result<()> {
        self.ledger_rotation_error(source, &error)?;
        result.record_error(hash_path(source), error);
        Ok(())
    }

    fn enforce_log_cap(&self, logs: &Path, result: &mut GcResult) -> Result<()> {
        let mut files = Vec::new();
        for path in collect_files(logs)? {
            if is_rotation_temp(&path) {
                continue;
            }
            files.push((modified_ms(&path)?, file_len(&path)?, path));
        }
        let mut total = files.iter().map(|(_, len, _)| *len).sum::<u64>();
        files.sort_by_key(|(modified, _, _)| *modified);
        for (_, len, path) in files {
            if total <= self.config.log_max_bytes {
                break;
            }
            self.delete_file(&path, CleanupKind::Log, "log_cap_delete", result)?;
            total = total.saturating_sub(len);
        }
        Ok(())
    }

    fn delete_file(
        &self,
        path: &Path,
        kind: CleanupKind,
        action: &'static str,
        result: &mut GcResult,
    ) -> Result<()> {
        let bytes = file_len(path)?;
        fs::remove_file(path)
            .map_err(|error| io_error(format!("remove {}: {error}", path.display())))?;
        result.bytes_freed = result.bytes_freed.saturating_add(bytes);
        match kind {
            CleanupKind::Log => {
                result.log_bytes_freed = result.log_bytes_freed.saturating_add(bytes);
                result.log_files_deleted += 1;
            }
            CleanupKind::Temp => {
                result.temp_bytes_freed = result.temp_bytes_freed.saturating_add(bytes);
                result.temp_files_deleted += 1;
            }
        }
        self.ledger_event(action, path, bytes)?;
        result.ledger_events += 1;
        Ok(())
    }

    fn ledger_event(&self, action: &str, path: &Path, bytes: u64) -> Result<()> {
        #[derive(Serialize)]
        struct Event<'a> {
            ts: Ts,
            action: &'a str,
            path_hash: String,
            bytes: u64,
        }

        self.append_ledger_line(&Event {
            ts: self.clock.now(),
            action,
            path_hash: hash_path(path),
            bytes,
        })
    }

    /// Append a structured `log_rotation_error` diagnostic carrying the fail-closed
    /// error's code and message so refusals are auditable from the ledger alone.
    fn ledger_rotation_error(&self, path: &Path, error: &CalyxError) -> Result<()> {
        #[derive(Serialize)]
        struct Diagnostic<'a> {
            ts: Ts,
            action: &'a str,
            path_hash: String,
            code: &'a str,
            message: &'a str,
            remediation: &'a str,
        }

        self.append_ledger_line(&Diagnostic {
            ts: self.clock.now(),
            action: "log_rotation_error",
            path_hash: hash_path(path),
            code: error.code,
            message: &error.message,
            remediation: error.remediation,
        })
    }

    fn append_ledger_line<T: Serialize>(&self, value: &T) -> Result<()> {
        let ledger = self.ledger_path();
        if let Some(parent) = ledger.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| io_error(format!("create {}: {error}", parent.display())))?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&ledger)
            .map_err(|error| io_error(format!("open {}: {error}", ledger.display())))?;
        let line = serde_json::to_vec(value)
            .map_err(|error| io_error(format!("encode janitor ledger event: {error}")))?;
        file.write_all(&line)
            .and_then(|_| file.write_all(b"\n"))
            .map_err(|error| io_error(format!("append {}: {error}", ledger.display())))
    }

    fn ledger_path(&self) -> PathBuf {
        self.home.join("ledger").join("janitor.jsonl")
    }

    fn record_metrics(&self, result: &GcResult) {
        self.counters
            .lock()
            .expect("janitor counters poisoned")
            .record(result);
    }
}
