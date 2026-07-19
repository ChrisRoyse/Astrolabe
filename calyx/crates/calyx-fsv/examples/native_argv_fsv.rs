//! Native Windows argv observation artifact for manual Full State Verification.
//!
//! This is not a test or a gate. It reports the arguments the real process
//! received from Windows as UTF-16 code units, so operators can independently
//! compare process reality with the durable `native-fsv-run.ps1` record.

#[cfg(not(windows))]
compile_error!("native_argv_fsv is a Windows-only FSV artifact");

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

fn utf16_hex(value: &OsStr) -> String {
    value
        .encode_wide()
        .map(|unit| format!("{unit:04x}"))
        .collect::<Vec<_>>()
        .join("")
}

fn main() {
    let mut process_arguments = std::env::args_os();
    let executable = process_arguments.next().unwrap_or_default();
    let arguments = process_arguments
        .map(|argument| utf16_hex(&argument))
        .collect::<Vec<_>>();
    let encoded_arguments = arguments
        .iter()
        .map(|argument| format!("\"{argument}\""))
        .collect::<Vec<_>>()
        .join(",");

    println!(
        concat!(
            "{{",
            "\"schema\":\"astrolabe.native-argv-fsv.v1\",",
            "\"process_id\":{},",
            "\"executable_utf16_hex\":\"{}\",",
            "\"argument_count\":{},",
            "\"arguments_utf16_hex\":[{}]",
            "}}"
        ),
        std::process::id(),
        utf16_hex(&executable),
        arguments.len(),
        encoded_arguments,
    );
}
