use std::collections::BTreeMap;
use std::io::{self, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use bincode::config;
use calyx_core::{AbsentReason, CalyxError, Input, LensId, Modality, SlotState, SlotVector};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

mod discovery;
mod flags;
mod protocol;

pub(crate) use discovery::{ResidentDiscovery, read_resident_discovery, resident_discovery_path};

use flags::{
    ServeFlags, calyx_home, ensure_loopback, parse_addr, parse_client_flags, parse_serve_flags,
};
use protocol::{
    ClientMeasureInput, MEASURE_BATCH_SCHEMA, MEASURE_SCHEMA, MeasureResponse, READY_SCHEMA,
    RESIDENT_BINARY_PROTOCOL_VERSION, ReadyResponse, ResidentMeasureBatchBinaryRequest,
    ResidentMeasureBatchStreamEnd, ResidentMeasureBatchStreamFrame,
    ResidentMeasureBatchStreamHeader, ResidentRequest, ResidentSlotContract, hex_decode,
};
pub(crate) use protocol::{
    MeasureBatchAtResponse, MeasureBatchResponse, MeasureBatchSummaryResponse,
    ResidentMeasuredInput, ResidentSlotMeasure,
};

use super::warm::resident_support::{
    ResidentWarmOptions, ResidentWarmState, load_resident_warm_state,
};
use crate::error::{CliError, CliResult};
use crate::output::print_json;

const DEFAULT_BIND: &str = "127.0.0.1:8787";
const DEFAULT_MAX_RESIDENT_VRAM_MIB: u64 = 22 * 1024;
const DEFAULT_RESIDENT_OVERHEAD_MULTIPLIER_MILLI: u64 = 2100;
const DEFAULT_MAX_LOAD_SECS: u64 = 60;
const DEFAULT_MAX_REQUEST_SECS: u64 = 600;
const CLIENT_CONTROL_TIMEOUT_SECS: u64 = 30;
const CLIENT_PRODUCTIVE_MARGIN_SECS: u64 = 30;
const CLIENT_TIMEOUT_REMEDIATION: &str =
    "start `calyx panel resident serve` on the requested loopback address";
const RESIDENT_BINARY_MAGIC: &[u8] = b"CALYX_PANEL_RESIDENT_BIN1\n";
const MAX_RESIDENT_JSON_LINE_BYTES: usize = 16 * 1024 * 1024;
const MAX_RESIDENT_SERVICE_FRAME_BYTES: usize = 2 * 1024 * 1024 * 1024;
const PRIVATE_WORKER_BACK_PRESSURE: &str = "CALYX_PANEL_RESIDENT_WORKER_BACK_PRESSURE";

mod client;
mod codec;
mod deadline;
mod dispatch;
#[cfg(windows)]
mod job;
mod lifecycle;
mod parallel;
mod server;
mod source;
mod stream;
#[cfg(windows)]
mod supervisor;
#[cfg(windows)]
mod worker;

pub(crate) use client::{measure_batch_at, ready_value_at};
#[cfg(windows)]
pub(crate) fn run_worker(args: &[String]) -> CliResult {
    server::serve_worker(args)
}

pub(crate) fn run(args: &[String]) -> CliResult {
    let Some(command) = args.first().map(String::as_str) else {
        return Err(CliError::usage(
            "calyx panel resident requires serve, ready, measure, measure-batch, or stop",
        ));
    };
    match command {
        "serve" => server::serve(&args[1..]),
        "ready" => client::client_command(&args[1..], "ready"),
        "measure" => client::client_command(&args[1..], "measure"),
        "measure-batch" => client::client_command(&args[1..], "measure-batch"),
        "stop" => client::client_command(&args[1..], "shutdown"),
        other => Err(CliError::usage(format!(
            "unknown panel resident subcommand {other}; expected serve, ready, measure, measure-batch, or stop"
        ))),
    }
}

fn write_json_file(path: PathBuf, value: &impl Serialize) -> CliResult {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| CliError::runtime(format!("serialize {}: {error}", path.display())))?;
    bytes.push(b'\n');
    crate::durable_write::write_bytes_atomic(&path, &bytes, "resident JSON output")
}

fn cli_error_value(error: &CliError) -> Value {
    error_value(error.code(), error.message(), error.remediation())
}

fn error_value(
    code: impl Into<String>,
    message: impl Into<String>,
    remediation: impl Into<String>,
) -> Value {
    json!({
        "ok": false,
        "code": code.into(),
        "message": message.into(),
        "remediation": remediation.into(),
    })
}
