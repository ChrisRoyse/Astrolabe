use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use calyx_mcp::McpServer;
use calyxd::config::CalyxConfig;
use calyxd::cuda_probe;
use calyxd::error::DaemonError;
use calyxd::health::{run_healthcheck, write_health_result, write_shutdown_status};
use calyxd::learner_origin::LearnerOriginService;
use calyxd::mcp_server::CalyxMcpServer;
use calyxd::metrics::{CalyxMetrics, ChainVerifyMetrics};
use calyxd::server::MetricsServer;
use calyxd::verify::{VerifyRestoreReport, verify_restore};
use calyxd::vram::{self, NvmlVramUsage};
use tokio_util::sync::CancellationToken;

use crate::verify_loop::{TargetKind, VerifyTarget, run_cycle, spawn_loop};
use crate::{refresh_zfs_metrics, spawn_zfs_metrics_loop};

const VERIFY_INTERVAL_SECS: u64 = 60;
const LISTENER_MONITOR_INTERVAL: Duration = Duration::from_millis(10);

pub(crate) async fn run_server(config_path: &Path, once: bool, audit_vram: bool) -> ExitCode {
    let cfg = match CalyxConfig::from_file(config_path) {
        Ok(cfg) => cfg,
        Err(error) => return fatal(error),
    };
    let device = match cuda_probe::probe_cuda_device() {
        Ok(device) => device,
        Err(error) => return fatal(error),
    };
    let budget = match build_vram_budget(&cfg, &device) {
        Ok(budget) => budget,
        Err(error) => return fatal(error),
    };
    let audit = match budget.startup_vram_audit() {
        Ok(audit) => audit,
        Err(error) => return fatal(error),
    };

    if audit_vram {
        match serde_json::to_string_pretty(&audit) {
            Ok(json) => println!("{json}"),
            Err(error) => {
                return fatal(DaemonError::health_failed(format!(
                    "serialize VRAM audit: {error}"
                )));
            }
        }
        return ExitCode::SUCCESS;
    }

    let vault_path = cfg.vault_path_resolved();
    let restore_report = match verify_vault_for_startup(&vault_path) {
        Ok(report) => report,
        Err(error) => return fatal(error),
    };

    let target = VerifyTarget {
        kind: TargetKind::Vault,
        path: vault_path.clone(),
    };
    let labels = vec![target.label()];
    let chain = Arc::new(ChainVerifyMetrics::new(&labels));
    run_cycle(std::slice::from_ref(&target), &chain);
    let surface = Arc::new(CalyxMetrics::new(Arc::clone(&chain), &labels));
    let vault_label = target.label();
    surface.record_vram_budget_audit(&vault_label, "runtime", &audit);
    surface.record_verify_restore(&vault_label, &restore_report, unix_now_secs());
    refresh_zfs_metrics(&surface);
    // #1934: surface the configured VRAM budget ceiling on /metrics. The limit is
    // the static configured ceiling from calyx.toml (always known, independent of
    // GPU mode), sourced from the real startup VRAM audit. calyxd runs CPU-only and
    // reserves no VRAM of its own budget, so used is 0 — an honest reading; the
    // device-wide TEI footprint is a separate concern, not Calyx budget consumption.
    surface.set_vram_budget(0, i64::from(audit.calyx_budget_mib));
    let origin = match cfg.learner_origin.as_ref() {
        Some(origin_cfg) => match LearnerOriginService::from_config(origin_cfg) {
            Ok(service) => Some(Arc::new(service)),
            Err(error) => return fatal(error),
        },
        None => None,
    };

    if once {
        return print_once(&surface, origin.as_deref());
    }

    let server = match &origin {
        Some(origin) => {
            MetricsServer::bind_with_origin(cfg.bind_addr, Arc::clone(&surface), Arc::clone(origin))
        }
        None => MetricsServer::bind(cfg.bind_addr, Arc::clone(&surface)),
    };
    let server = match server {
        Ok(server) => server,
        Err(error) => return fatal(error),
    };
    let mcp_server = match build_mcp_server(&cfg) {
        Ok(server) => server,
        Err(error) => return fatal(error),
    };
    let metrics_addr = match server.local_addr() {
        Ok(addr) => addr,
        Err(error) => return fatal(error),
    };
    let mcp_addr = match mcp_server.as_ref() {
        Some(server) => match server.local_addr() {
            Ok(addr) => Some(addr.to_string()),
            Err(error) => return fatal(error),
        },
        None => None,
    };
    let cancel_token = CancellationToken::new();
    if let Err(error) = install_signal_handlers(cancel_token.clone()) {
        return fatal(error);
    }

    let health = run_healthcheck(&cfg);
    if let Err(error) = write_health_result(&health, &cfg.health_log_path) {
        return fatal(error);
    }
    if !health.is_pass() {
        eprintln!(
            "calyxd: CALYX_DAEMON_HEALTH_FAIL: startup healthcheck failed; listener will not accept"
        );
        return ExitCode::from(1);
    }

    println!(
        "INFO calyxd {} starting device=\"{}\" vram_budget={}MiB metrics_bind={} mcp_bind={} vault={} learner_origin={}",
        env!("CARGO_PKG_VERSION"),
        device.device_name,
        cfg.vram_budget_mib,
        metrics_addr,
        mcp_addr.as_deref().unwrap_or("disabled"),
        vault_path.display(),
        origin.is_some()
    );
    spawn_loop(
        vec![target],
        chain,
        Duration::from_secs(VERIFY_INTERVAL_SECS),
    );
    spawn_zfs_metrics_loop(
        Arc::clone(&surface),
        Duration::from_secs(VERIFY_INTERVAL_SECS),
    );

    match run_servers(server, mcp_server, cancel_token) {
        Ok(()) => match write_shutdown_status(&cfg.health_log_path) {
            Ok(record) => {
                println!(
                    "INFO calyxd shutdown status={} timestamp_utc={}",
                    record.status, record.timestamp_utc
                );
                ExitCode::SUCCESS
            }
            Err(error) => fatal(error),
        },
        Err(error) => fatal(error),
    }
}

fn build_mcp_server(cfg: &CalyxConfig) -> Result<Option<CalyxMcpServer>, DaemonError> {
    match (cfg.mcp_bind_addr, cfg.mcp_mtls.as_ref()) {
        (None, None) => return Ok(None),
        (None, Some(_)) => {
            return Err(DaemonError::config_invalid(
                "mcp_mtls is configured but mcp_bind_addr is missing; calyxd will not start MCP without an explicit loopback bind",
            ));
        }
        (Some(_), None) => {
            return Err(DaemonError::tls_config_invalid(
                "mcp_bind_addr is configured but mcp_mtls is missing; calyxd MCP requires mTLS",
            ));
        }
        (Some(_), Some(_)) => {}
    }
    let dispatcher = production_mcp_dispatcher()?;
    CalyxMcpServer::from_config(cfg, dispatcher).map(Some)
}

fn production_mcp_dispatcher() -> Result<Arc<McpServer>, DaemonError> {
    let mut dispatcher = McpServer::new();
    calyx_mcp::tools::register_all(&mut dispatcher).map_err(|error| {
        DaemonError::config_invalid(format!(
            "register production MCP tools: {}: {} (remediation: {})",
            error.code, error.message, error.remediation
        ))
    })?;
    Ok(Arc::new(dispatcher))
}

fn run_servers(
    metrics: MetricsServer,
    mcp: Option<CalyxMcpServer>,
    cancel_token: CancellationToken,
) -> Result<(), DaemonError> {
    let Some(mcp) = mcp else {
        return metrics.run(cancel_token);
    };
    let mcp_addr = mcp.local_addr()?;
    let mcp_shutdown = mcp.shutdown_handle()?;
    let metrics_token = cancel_token.clone();
    let metrics_join = spawn_listener("calyxd-metrics", move || metrics.run(metrics_token))?;
    let mcp_join = spawn_listener("calyxd-mcp", move || {
        println!("INFO calyxd MCP serving on {mcp_addr}");
        mcp.run()
    })?;

    loop {
        if cancel_token.is_cancelled() || metrics_join.is_finished() || mcp_join.is_finished() {
            break;
        }
        thread::sleep(LISTENER_MONITOR_INTERVAL);
    }
    cancel_token.cancel();
    mcp_shutdown.shutdown();

    join_listener("metrics", metrics_join)??;
    join_listener("mcp", mcp_join)??;
    Ok(())
}

fn spawn_listener<F>(name: &str, run: F) -> Result<JoinHandle<Result<(), DaemonError>>, DaemonError>
where
    F: FnOnce() -> Result<(), DaemonError> + Send + 'static,
{
    thread::Builder::new()
        .name(name.to_string())
        .spawn(run)
        .map_err(|error| DaemonError::health_failed(format!("spawn {name} listener: {error}")))
}

fn join_listener(
    name: &str,
    join: JoinHandle<Result<(), DaemonError>>,
) -> Result<Result<(), DaemonError>, DaemonError> {
    join.join()
        .map_err(|_| DaemonError::health_failed(format!("{name} listener thread panicked")))
}

pub(crate) fn validate_config(path: Option<&Path>) -> ExitCode {
    let Some(path) = path else {
        return fatal(DaemonError::config_invalid(
            "--validate-config requires --config <path>",
        ));
    };
    match CalyxConfig::from_file(path) {
        Ok(config) => {
            println!("calyxd: config {} OK", path.display());
            println!("{config:#?}");
            println!(
                "calyxd: vault_path_resolved = {}",
                config.vault_path_resolved().display()
            );
            ExitCode::SUCCESS
        }
        Err(error) => fatal(error),
    }
}

fn build_vram_budget(
    cfg: &CalyxConfig,
    device: &cuda_probe::CudaDeviceInfo,
) -> Result<vram::VramBudget<NvmlVramUsage>, DaemonError> {
    let nvml = NvmlVramUsage::init()?;
    vram::VramBudget::from_config(cfg.vram_budget_mib, device, nvml)
}

fn verify_vault_for_startup(path: &Path) -> Result<VerifyRestoreReport, DaemonError> {
    verify_restore(path).and_then(|report| {
        if report.success() {
            Ok(report)
        } else {
            Err(DaemonError::health_failed(format!(
                "vault {} startup read-back unverified: {}",
                path.display(),
                report.failure_reasons().join("; ")
            )))
        }
    })
}

fn unix_now_secs() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(elapsed) => i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX),
        Err(error) => {
            eprintln!("calyxd: system clock before unix epoch: {error}");
            0
        }
    }
}

fn print_once(surface: &CalyxMetrics, origin: Option<&LearnerOriginService>) -> ExitCode {
    match surface.encode_text() {
        Ok(mut text) => {
            if let Some(origin) = origin {
                match origin.metrics().encode_text() {
                    Ok(origin_text) => text.push_str(&origin_text),
                    Err(error) => return fatal(DaemonError::config_invalid(error)),
                }
            }
            print!("{text}");
            ExitCode::SUCCESS
        }
        Err(error) => fatal(DaemonError::config_invalid(error)),
    }
}

fn install_signal_handlers(cancel_token: CancellationToken) -> Result<(), DaemonError> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigint = signal(SignalKind::interrupt()).map_err(|error| {
            DaemonError::config_invalid(format!("install SIGINT handler: {error}"))
        })?;
        let mut sigterm = signal(SignalKind::terminate()).map_err(|error| {
            DaemonError::config_invalid(format!("install SIGTERM handler: {error}"))
        })?;
        tokio::spawn(async move {
            tokio::select! {
                _ = sigint.recv() => {}
                _ = sigterm.recv() => {}
            }
            cancel_token.cancel();
        });
    }

    #[cfg(not(unix))]
    {
        tokio::spawn(async move {
            if let Err(error) = tokio::signal::ctrl_c().await {
                eprintln!("calyxd: install Ctrl-C handler failed: {error}");
            }
            cancel_token.cancel();
        });
    }

    Ok(())
}

fn fatal(error: DaemonError) -> ExitCode {
    eprintln!("calyxd: {error}");
    ExitCode::from(1)
}

