use super::*;
use crate::path_identity::vault_template_source;

const RESIDENT_CPU_LENS_REFUSED: &str = "CALYX_PANEL_RESIDENT_CPU_LENS_REFUSED";
const RESIDENT_UNMANAGED_RUNTIME: &str = "CALYX_PANEL_RESIDENT_UNMANAGED_RUNTIME";
const RESIDENT_EXECUTION_UNATTESTED: &str = "CALYX_PANEL_RESIDENT_EXECUTION_UNATTESTED";
const ONNX_CPU_FALLBACK_AUDIT_ENV: &str = "CALYX_ONNX_CPU_FALLBACK_AUDIT";
const ONNX_MAX_CPU_NODE_FRACTION_ENV: &str = "CALYX_ONNX_MAX_CPU_NODE_FRACTION";

pub(in crate::panel_commands) struct ResidentWarmOptions {
    pub(in crate::panel_commands) home: PathBuf,
    pub(in crate::panel_commands) template: Option<String>,
    pub(in crate::panel_commands) vault: Option<PathBuf>,
    pub(in crate::panel_commands) slots: Vec<SlotId>,
    pub(in crate::panel_commands) modality: Option<Modality>,
    pub(in crate::panel_commands) ready_out: Option<PathBuf>,
    pub(in crate::panel_commands) max_resident_vram_mib: u64,
    pub(in crate::panel_commands) resident_overhead_multiplier_milli: u64,
    pub(in crate::panel_commands) max_load_secs: u64,
    pub(in crate::panel_commands) load_parallelism: Option<usize>,
    pub(in crate::panel_commands) progress_out: Option<PathBuf>,
}

pub(in crate::panel_commands) struct ResidentWarmState {
    pub(in crate::panel_commands) build: SavedTemplatePanelBuild,
    pub(in crate::panel_commands) home: PathBuf,
    pub(in crate::panel_commands) template_selector: String,
    pub(in crate::panel_commands) template_source: String,
    pub(in crate::panel_commands) source_of_truth: String,
    pub(in crate::panel_commands) slot_scope: Vec<SlotId>,
    pub(in crate::panel_commands) ready_out: Option<PathBuf>,
    pub(in crate::panel_commands) max_resident_vram_mib: u64,
    pub(in crate::panel_commands) declared_template_vram_mib: u64,
    pub(in crate::panel_commands) resident_overhead_multiplier: f32,
    pub(in crate::panel_commands) estimated_resident_vram_mib: u64,
    pub(in crate::panel_commands) max_load_secs: u64,
    pub(in crate::panel_commands) load_parallelism: usize,
    pub(in crate::panel_commands) load_ms: u128,
    pub(in crate::panel_commands) probe_ms: u128,
    pub(in crate::panel_commands) warmed_lens_count: usize,
    pub(in crate::panel_commands) warmed_lens_scope: &'static str,
    pub(in crate::panel_commands) lens_attestations: Vec<ResidentLensAttestation>,
    pub(in crate::panel_commands) content_lens_count: usize,
    pub(in crate::panel_commands) gpu_content_lens_count: usize,
    _worker_shutdown: MultimodalGpuWorkerShutdownGuard,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(in crate::panel_commands) struct ResidentLensAttestation {
    pub(in crate::panel_commands) slot: u16,
    pub(in crate::panel_commands) key: String,
    pub(in crate::panel_commands) lens_id: String,
    pub(in crate::panel_commands) runtime: String,
    pub(in crate::panel_commands) runtime_detail: String,
    pub(in crate::panel_commands) modality: Modality,
    pub(in crate::panel_commands) placement: Placement,
    pub(in crate::panel_commands) declared_device: Option<String>,
    pub(in crate::panel_commands) declared_dtype: Option<String>,
    pub(in crate::panel_commands) declared_provider: Option<String>,
    pub(in crate::panel_commands) execution: RuntimeExecutionAttestation,
}

pub(in crate::panel_commands) fn load_resident_warm_state(
    options: ResidentWarmOptions,
) -> CliResult<ResidentWarmState> {
    if options.template.is_some() == options.vault.is_some() {
        return Err(CliError::usage(
            "resident warm state requires exactly one of template or vault",
        ));
    }
    configure_resident_runtime_audits();
    if let Some(vault) = options.vault.clone() {
        return load_vault_resident_warm_state(options, vault);
    }
    let template = options
        .template
        .clone()
        .ok_or_else(|| CliError::usage("resident warm state missing template"))?;
    let worker_shutdown = MultimodalGpuWorkerShutdownGuard;
    let progress_log = options
        .progress_out
        .clone()
        .map(WarmProgressLog::create)
        .transpose()?;
    let shared_progress_log = progress_log
        .as_ref()
        .map(|log| Arc::new(Mutex::new(log.clone())));
    if let Some(log) = &progress_log {
        log.append(&run_progress_record(&template, "resident_run_start"))?;
    }
    require_managed_resident_template_runtimes(&options.home, &template, progress_log.as_ref())?;
    require_gpu_content_lenses(&options.home, &template, progress_log.as_ref())?;
    let preflight = warm_preflight(
        &options.home,
        &template,
        options.max_resident_vram_mib,
        options.resident_overhead_multiplier_milli,
        progress_log.as_ref(),
    )?;
    let load_parallelism = options
        .load_parallelism
        .unwrap_or_else(|| default_load_parallelism(preflight.lens_count));
    let load_limit = WarmLoadLimit::new(options.max_load_secs);
    let load_started = Instant::now();
    let build = build_warm_template_panel(
        &options.home,
        &template,
        now_ms(),
        &shared_progress_log,
        &load_limit,
        load_parallelism,
    )?;
    let load_ms = load_started.elapsed().as_millis();
    let probe_started = Instant::now();
    let probes = probe_panel(&build, progress_log.as_ref(), &template)?;
    let probe_ms = probe_started.elapsed().as_millis();
    let lens_attestations = resident_lens_attestations(&build)?;
    ensure_resident_count_parity(&build, probes.len(), lens_attestations.len())?;
    let content_lens_count = content_slots(&build).count();
    let gpu_content_lens_count = content_slots(&build)
        .filter(|slot| slot.resource.placement == Placement::Gpu)
        .count();
    Ok(ResidentWarmState {
        source_of_truth: source_of_truth(&options.home, &build.template_id),
        template_source: format!("saved:{}:{}", build.template_name, build.template_id),
        slot_scope: Vec::new(),
        build,
        home: options.home,
        template_selector: template,
        ready_out: options.ready_out,
        max_resident_vram_mib: options.max_resident_vram_mib,
        declared_template_vram_mib: preflight.declared_template_vram_mib,
        resident_overhead_multiplier: multiplier_to_f32(options.resident_overhead_multiplier_milli),
        estimated_resident_vram_mib: preflight.estimated_resident_vram_mib,
        max_load_secs: options.max_load_secs,
        load_parallelism,
        load_ms,
        probe_ms,
        warmed_lens_count: probes.len(),
        warmed_lens_scope: "unique_active_registered_lenses",
        lens_attestations,
        content_lens_count,
        gpu_content_lens_count,
        _worker_shutdown: worker_shutdown,
    })
}

fn load_vault_resident_warm_state(
    options: ResidentWarmOptions,
    vault: PathBuf,
) -> CliResult<ResidentWarmState> {
    let worker_shutdown = MultimodalGpuWorkerShutdownGuard;
    let selector = vault_template_source(&vault)?;
    let progress_log = options
        .progress_out
        .clone()
        .map(WarmProgressLog::create)
        .transpose()?;
    if let Some(log) = &progress_log {
        log.append(&run_progress_record(&selector, "resident_run_start"))?;
    }
    let slot_scope = normalized_slot_scope(&selector, options.slots)?;
    let load_started = Instant::now();
    let state = load_vault_panel_state(&vault)?;
    let mut panel = state.panel;
    apply_resident_slot_scope(&selector, &mut panel, &slot_scope, options.modality)?;
    if let Some(modality) = options.modality {
        panel.slots.retain(|slot| {
            slot.state != SlotState::Active
                || slot.modality == modality
                || slot.slot_key.key().starts_with("E")
        });
    }
    if let Some(log) = &progress_log
        && !slot_scope.is_empty()
    {
        let mut record = run_progress_record(&selector, "resident_slot_scope_selected");
        record.lens_count = Some(slot_scope.len());
        log.append(&record)?;
    }
    require_gpu_content_slots(&selector, &panel.slots)?;
    let build = SavedTemplatePanelBuild {
        template_id: format!("vault:{}", vault.display()),
        template_name: vault
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("vault")
            .to_string(),
        content_lens_count: panel
            .slots
            .iter()
            .filter(|slot| {
                slot.state == SlotState::Active && !slot.retrieval_only && !slot.excluded_from_dedup
            })
            .count(),
        panel,
        registry: state.registry,
        a37_gate_eligible: false,
        a37_status: "vault_source".to_string(),
        registered_lenses_added: 0,
    };
    require_managed_resident_runtimes(&selector, &build, progress_log.as_ref())?;
    let load_ms = load_started.elapsed().as_millis();
    let probe_started = Instant::now();
    let probes = probe_panel(&build, progress_log.as_ref(), &selector)?;
    let probe_ms = probe_started.elapsed().as_millis();
    let lens_attestations = resident_lens_attestations(&build)?;
    ensure_resident_count_parity(&build, probes.len(), lens_attestations.len())?;
    let content_lens_count = content_slots(&build).count();
    let gpu_content_lens_count = content_slots(&build)
        .filter(|slot| slot.resource.placement == Placement::Gpu)
        .count();
    Ok(ResidentWarmState {
        source_of_truth: vault_source_of_truth(&selector),
        template_source: selector.clone(),
        slot_scope,
        build,
        home: options.home,
        template_selector: selector,
        ready_out: options.ready_out,
        max_resident_vram_mib: options.max_resident_vram_mib,
        declared_template_vram_mib: 0,
        resident_overhead_multiplier: multiplier_to_f32(options.resident_overhead_multiplier_milli),
        estimated_resident_vram_mib: 0,
        max_load_secs: options.max_load_secs,
        load_parallelism: 1,
        load_ms,
        probe_ms,
        warmed_lens_count: probes.len(),
        warmed_lens_scope: "unique_active_registered_lenses",
        lens_attestations,
        content_lens_count,
        gpu_content_lens_count,
        _worker_shutdown: worker_shutdown,
    })
}

fn resident_lens_attestations(
    build: &SavedTemplatePanelBuild,
) -> CliResult<Vec<ResidentLensAttestation>> {
    let mut seen = BTreeSet::new();
    active_registered_slots(build)
        .filter(|slot| seen.insert(slot.lens_id))
        .map(|slot| {
            let spec = build.registry.lens_spec(slot.lens_id).ok_or_else(|| {
                CliError::from(CalyxError::registry_unavailable(format!(
                    "resident attestation slot={} key={} lens={} has no LensSpec in registry",
                    slot.slot_id.get(),
                    slot.slot_key.key(),
                    slot.lens_id
                )))
            })?;
            let (declared_device, declared_dtype, declared_provider) =
                declared_runtime_execution(&spec.runtime);
            let execution = build
                .registry
                .execution_attestation(slot.lens_id)?
                .ok_or_else(|| {
                    resident_execution_error(
                        slot,
                        &spec.runtime,
                        "runtime returned no post-measurement execution evidence",
                    )
                })?;
            validate_resident_execution(slot, &spec.runtime, &execution)?;
            Ok(ResidentLensAttestation {
                slot: slot.slot_id.get(),
                key: slot.slot_key.key().to_string(),
                lens_id: slot.lens_id.to_string(),
                runtime: runtime_name(&spec.runtime).to_string(),
                runtime_detail: runtime_detail(&spec.runtime),
                modality: slot.modality,
                placement: slot.resource.placement,
                declared_device,
                declared_dtype,
                declared_provider,
                execution,
            })
        })
        .collect()
}

fn configure_resident_runtime_audits() {
    // Residency runs only in a fresh, private native-Windows worker before any
    // model-load threads start. Force the existing ORT profiler to prove that
    // every GPU-policy compute node stayed off CPU.
    unsafe {
        env::set_var(ONNX_CPU_FALLBACK_AUDIT_ENV, "fail");
        env::set_var(ONNX_MAX_CPU_NODE_FRACTION_ENV, "0");
    }
}

fn ensure_resident_count_parity(
    build: &SavedTemplatePanelBuild,
    probe_count: usize,
    attestation_count: usize,
) -> CliResult {
    let active_lens_count = build
        .panel
        .slots
        .iter()
        .filter(|slot| slot.state == SlotState::Active)
        .map(|slot| slot.lens_id)
        .collect::<BTreeSet<_>>()
        .len();
    if active_lens_count == probe_count && probe_count == attestation_count {
        return Ok(());
    }
    Err(CliError::from(CalyxError {
        code: RESIDENT_EXECUTION_UNATTESTED,
        message: format!(
            "resident warm count mismatch: active_unique={active_lens_count} probed={probe_count} attested={attestation_count}"
        ),
        remediation: "register, probe, and execution-attest every unique active panel lens before declaring the resident worker warm",
    }))
}

fn validate_resident_execution(
    slot: &Slot,
    runtime: &LensRuntime,
    execution: &RuntimeExecutionAttestation,
) -> CliResult {
    let (declared_device, declared_dtype, _) = declared_runtime_execution(runtime);
    if let Some(declared_device) = declared_device
        && declared_device != execution.device
    {
        return Err(resident_execution_error(
            slot,
            runtime,
            &format!(
                "declared device {declared_device} != observed device {}",
                execution.device
            ),
        ));
    }
    if let Some(declared_dtype) = declared_dtype {
        let Some(loader_dtype) = execution.loader_dtype.as_deref() else {
            return Err(resident_execution_error(
                slot,
                runtime,
                &format!("declared dtype {declared_dtype} has no observed loader dtype"),
            ));
        };
        let Some(compute_dtype) = execution.compute_dtype.as_deref() else {
            return Err(resident_execution_error(
                slot,
                runtime,
                &format!("declared dtype {declared_dtype} has no observed compute dtype"),
            ));
        };
        if !declared_dtype.eq_ignore_ascii_case(loader_dtype)
            || !declared_dtype.eq_ignore_ascii_case(compute_dtype)
        {
            return Err(resident_execution_error(
                slot,
                runtime,
                &format!(
                    "declared dtype {declared_dtype} != loader {loader_dtype} / compute {compute_dtype}"
                ),
            ));
        }
    }
    if slot.resource.placement == Placement::Gpu {
        if execution.device != "cuda" && !execution.device.starts_with("cuda:") {
            return Err(resident_execution_error(
                slot,
                runtime,
                &format!(
                    "GPU slot executed on device {} with provider {}",
                    execution.device, execution.provider
                ),
            ));
        }
        if execution.cpu_compute_nodes.is_some_and(|count| count != 0) {
            return Err(resident_execution_error(
                slot,
                runtime,
                &format!(
                    "GPU slot observed {:?}/{:?} CPU compute nodes via {}",
                    execution.cpu_compute_nodes, execution.total_compute_nodes, execution.provider
                ),
            ));
        }
    } else if execution.device != "cpu" {
        return Err(resident_execution_error(
            slot,
            runtime,
            &format!(
                "CPU/non-GPU slot executed on unexpected device {}",
                execution.device
            ),
        ));
    }
    if matches!(
        runtime,
        LensRuntime::Onnx { .. } | LensRuntime::OnnxColbert { .. }
    ) {
        let Some(total_nodes) = execution.total_compute_nodes.filter(|count| *count > 0) else {
            return Err(resident_execution_error(
                slot,
                runtime,
                "ONNX runtime did not retain a non-empty total node count",
            ));
        };
        let Some(cpu_nodes) = execution.cpu_compute_nodes else {
            return Err(resident_execution_error(
                slot,
                runtime,
                "ONNX runtime did not retain a CPU node count",
            ));
        };
        let providers = execution.provider.to_ascii_uppercase();
        let placement_matches = match slot.resource.placement {
            Placement::Gpu => providers.contains("CUDA") && cpu_nodes == 0,
            Placement::Cpu => providers.contains("CPU") && cpu_nodes == total_nodes,
        };
        if !placement_matches {
            return Err(resident_execution_error(
                slot,
                runtime,
                &format!(
                    "ONNX provider placement does not match {:?}: provider={} cpu_nodes={cpu_nodes} total_nodes={total_nodes}",
                    slot.resource.placement, execution.provider
                ),
            ));
        }
    }
    Ok(())
}

fn resident_execution_error(slot: &Slot, runtime: &LensRuntime, detail: &str) -> CliError {
    CliError::from(CalyxError {
        code: RESIDENT_EXECUTION_UNATTESTED,
        message: format!(
            "resident execution attestation failed slot={} key={} lens={} runtime={} runtime_detail={}: {detail}",
            slot.slot_id.get(),
            slot.slot_key.key(),
            slot.lens_id,
            runtime_name(runtime),
            runtime_detail(runtime)
        ),
        remediation: "use a Calyx-owned runtime that retains actual post-measurement provider/device/dtype evidence; do not substitute LensSpec declarations",
    })
}

fn declared_runtime_execution(
    runtime: &LensRuntime,
) -> (Option<String>, Option<String>, Option<String>) {
    match runtime {
        LensRuntime::CandleLocal { device, dtype, .. }
        | LensRuntime::FastembedQwen3 { device, dtype, .. } => {
            (Some(device.clone()), Some(dtype.clone()), None)
        }
        LensRuntime::Algorithmic { .. }
        | LensRuntime::TeiHttp { .. }
        | LensRuntime::Onnx { .. }
        | LensRuntime::OnnxColbert { .. }
        | LensRuntime::FastembedSparse { .. }
        | LensRuntime::FastembedBgem3 { .. }
        | LensRuntime::FastembedReranker { .. }
        | LensRuntime::StaticLookup { .. }
        | LensRuntime::MultimodalAdapter { .. }
        | LensRuntime::ExternalCmd { .. } => (None, None, None),
    }
}

fn require_managed_resident_template_runtimes(
    home: &Path,
    selector: &str,
    progress_log: Option<&WarmProgressLog>,
) -> CliResult {
    let store = template_store::TemplateStore::open(home);
    let template = store.load(selector)?;
    template.validate()?;
    let unmanaged = template
        .lenses
        .iter()
        .enumerate()
        .map(|(slot, lens)| {
            let spec = lens_spec_from_manifest_path(Path::new(&lens.manifest))?;
            Ok((slot, lens, spec))
        })
        .collect::<CliResult<Vec<_>>>()?
        .into_iter()
        .filter_map(|(slot, lens, spec)| {
            is_unmanaged_resident_runtime(&spec.runtime).then(|| {
                format!(
                    "slot={slot} key={} lens={} runtime={} runtime_detail={}",
                    lens.slot_key,
                    lens.lens_id,
                    runtime_name(&spec.runtime),
                    runtime_detail(&spec.runtime)
                )
            })
        })
        .collect::<Vec<_>>();
    reject_unmanaged_resident_runtimes(selector, unmanaged, progress_log)
}

fn require_managed_resident_runtimes(
    selector: &str,
    build: &SavedTemplatePanelBuild,
    progress_log: Option<&WarmProgressLog>,
) -> CliResult {
    let mut seen = BTreeSet::new();
    let unmanaged = active_registered_slots(build)
        .filter(|slot| seen.insert(slot.lens_id))
        .filter_map(|slot| {
            let spec = build.registry.lens_spec(slot.lens_id)?;
            is_unmanaged_resident_runtime(&spec.runtime).then(|| {
                format!(
                    "slot={} key={} lens={} runtime={} runtime_detail={}",
                    slot.slot_id.get(),
                    slot.slot_key.key(),
                    slot.lens_id,
                    runtime_name(&spec.runtime),
                    runtime_detail(&spec.runtime)
                )
            })
        })
        .collect::<Vec<_>>();
    reject_unmanaged_resident_runtimes(selector, unmanaged, progress_log)
}

fn is_unmanaged_resident_runtime(runtime: &LensRuntime) -> bool {
    matches!(
        runtime,
        LensRuntime::TeiHttp { .. }
            | LensRuntime::ExternalCmd { .. }
            | LensRuntime::FastembedSparse { .. }
            | LensRuntime::FastembedBgem3 { .. }
            | LensRuntime::FastembedReranker { .. }
            | LensRuntime::MultimodalAdapter { .. }
    )
}

fn reject_unmanaged_resident_runtimes(
    selector: &str,
    unmanaged: Vec<String>,
    progress_log: Option<&WarmProgressLog>,
) -> CliResult {
    if unmanaged.is_empty() {
        return Ok(());
    }
    let message = format!(
        "resident panel {selector} refuses {} unmanaged or unattested runtimes without both an owned lifetime and post-measurement execution evidence: {}",
        unmanaged.len(),
        unmanaged.join(", ")
    );
    let remediation = "commission/select a Calyx-owned runtime that retains actual provider/device/dtype evidence, or implement an owned process adapter that attests PID identity and health and guarantees stop";
    if let Some(log) = progress_log {
        let mut record = run_progress_record(selector, "resident_unmanaged_runtime_error");
        record.lens_count = Some(unmanaged.len());
        record.error_code = Some(RESIDENT_UNMANAGED_RUNTIME.to_string());
        record.error_message = Some(message.clone());
        record.remediation = Some(remediation.to_string());
        log.append(&record)?;
    }
    Err(CliError::from(CalyxError {
        code: RESIDENT_UNMANAGED_RUNTIME,
        message,
        remediation,
    }))
}

fn vault_source_of_truth(vault_source: &str) -> String {
    format!("vault MANIFEST panel_ref registry_ref:{vault_source}")
}

fn normalized_slot_scope(selector: &str, slots: Vec<SlotId>) -> CliResult<Vec<SlotId>> {
    let mut seen = BTreeSet::new();
    let mut normalized = Vec::with_capacity(slots.len());
    for slot_id in slots {
        if !seen.insert(slot_id) {
            return Err(resident_slot_scope_error(
                selector,
                format!("duplicate --slot {}", slot_id.get()),
            ));
        }
        normalized.push(slot_id);
    }
    Ok(normalized)
}

fn apply_resident_slot_scope(
    selector: &str,
    panel: &mut Panel,
    slot_scope: &[SlotId],
    modality: Option<Modality>,
) -> CliResult {
    if slot_scope.is_empty() {
        return Ok(());
    }
    let requested = slot_scope.iter().copied().collect::<BTreeSet<_>>();
    let mut scoped_lenses = Vec::with_capacity(slot_scope.len());
    for slot_id in slot_scope {
        let slot = panel
            .slots
            .iter()
            .find(|candidate| candidate.slot_id == *slot_id)
            .ok_or_else(|| {
                resident_slot_scope_error(
                    selector,
                    format!("--slot {} is not present", slot_id.get()),
                )
            })?;
        if slot.state != SlotState::Active {
            return Err(resident_slot_scope_error(
                selector,
                format!(
                    "--slot {} is {:?}, expected Active",
                    slot_id.get(),
                    slot.state
                ),
            ));
        }
        if slot.retrieval_only || slot.excluded_from_dedup {
            return Err(resident_slot_scope_error(
                selector,
                format!(
                    "--slot {} is not a content lens retrieval_only={} excluded_from_dedup={}",
                    slot_id.get(),
                    slot.retrieval_only,
                    slot.excluded_from_dedup
                ),
            ));
        }
        if let Some(modality) = modality
            && slot.modality != modality
        {
            return Err(resident_slot_scope_error(
                selector,
                format!(
                    "--slot {} modality {:?} does not match --modality {:?}",
                    slot_id.get(),
                    slot.modality,
                    modality
                ),
            ));
        }
        if slot.resource.placement != Placement::Gpu {
            scoped_lenses.push(format!(
                "slot={} key={} lens={} placement={:?}",
                slot.slot_id.get(),
                slot.slot_key.key(),
                slot.lens_id,
                slot.resource.placement
            ));
        }
    }
    if !scoped_lenses.is_empty() {
        return Err(CliError::from(CalyxError {
            code: RESIDENT_CPU_LENS_REFUSED,
            message: format!(
                "resident vault {selector} refuses {} selected CPU/non-GPU content lenses: {}",
                scoped_lenses.len(),
                scoped_lenses.join(", ")
            ),
            remediation: "choose only GPU resident slots or replace the selected content lenses with GPU resident runtimes",
        }));
    }
    panel.slots.retain(|slot| requested.contains(&slot.slot_id));
    Ok(())
}

fn resident_slot_scope_error(selector: &str, detail: String) -> CliError {
    CliError::from(CalyxError {
        code: "CALYX_PANEL_RESIDENT_SLOT_SCOPE_INVALID",
        message: format!("resident vault {selector} has invalid slot scope: {detail}"),
        remediation: "pass --slot only for active GPU content slots present in the vault panel",
    })
}

fn require_gpu_content_slots(selector: &str, slots: &[Slot]) -> CliResult {
    let cpu_lenses = slots
        .iter()
        .filter(|slot| {
            slot.state == SlotState::Active
                && !slot.retrieval_only
                && !slot.excluded_from_dedup
                && slot.resource.placement != Placement::Gpu
        })
        .map(|slot| {
            format!(
                "slot={} key={} lens={} placement={:?}",
                slot.slot_id.get(),
                slot.slot_key.key(),
                slot.lens_id,
                slot.resource.placement
            )
        })
        .collect::<Vec<_>>();
    if cpu_lenses.is_empty() {
        return Ok(());
    }
    Err(CliError::from(CalyxError {
        code: RESIDENT_CPU_LENS_REFUSED,
        message: format!(
            "resident vault {selector} refuses {} CPU/non-GPU content lenses: {}",
            cpu_lenses.len(),
            cpu_lenses.join(", ")
        ),
        remediation: "pass --modality to select a GPU-only modality or replace every content lens with a GPU resident runtime",
    }))
}

fn require_gpu_content_lenses(
    home: &Path,
    selector: &str,
    progress_log: Option<&WarmProgressLog>,
) -> CliResult {
    let store = template_store::TemplateStore::open(home);
    let template = store.load(selector)?;
    template.validate()?;
    let cpu_lenses = template
        .lenses
        .iter()
        .filter(|lens| lens.counts_toward_a35 && lens.placement != Placement::Gpu)
        .map(|lens| {
            format!(
                "{}:{}:{:?}:{}",
                lens.slot_key, lens.lens_id, lens.placement, lens.manifest
            )
        })
        .collect::<Vec<_>>();
    if cpu_lenses.is_empty() {
        return Ok(());
    }
    let message = format!(
        "resident panel {selector} refuses {} CPU/non-GPU content lenses: {}",
        cpu_lenses.len(),
        cpu_lenses.join(", ")
    );
    if let Some(log) = progress_log {
        let mut record = run_progress_record(selector, "resident_gpu_placement_error");
        record.lens_count = Some(template.lenses.len());
        record.error_code = Some(RESIDENT_CPU_LENS_REFUSED.to_string());
        record.error_message = Some(message.clone());
        record.remediation = Some(
            "replace every content lens with a GPU resident runtime before starting the service"
                .to_string(),
        );
        log.append(&record)?;
    }
    Err(CliError::from(CalyxError {
        code: RESIDENT_CPU_LENS_REFUSED,
        message,
        remediation: "replace every content lens with a GPU resident runtime before starting the service",
    }))
}
