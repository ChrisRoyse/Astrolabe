//! Canonical stdout emitters shared by every subcommand.
//!
//! Three shapes cover the CLI's output needs:
//! * [`print_json`] — machine-parseable single value for pipelines/automation.
//! * [`print_table`] — aligned human-readable columns for interactive use.
//! * [`print_hex_dump`] — byte-exact rows in `xxd -g 1` layout so an FSV reader
//!   can cross-verify the raw bytes residing in the vault against `xxd` output.
//!
//! All three write to stdout; errors are the sole concern of [`crate::error`]
//! on stderr. Keeping success output and error output on separate streams is
//! the dual-consumer contract: a pipe captures clean data on stdout while an
//! operator/agent reads the structured envelope on stderr.
//!
//! Each emitter is a thin stdout-writer wrapper over a pure line-builder
//! (`json_line`, `table_lines`, `hex_dump_lines`) so the exact bytes written
//! can be asserted directly in tests without capturing stdout.

use std::io::{self, Write};

use serde::Serialize;

use crate::error::{CliError, CliResult};

/// Bytes per hex-dump row (matches `xxd` default width).
const HEX_ROW: usize = 16;
/// Full-row hex-column width: 16 bytes × 2 hex chars + 15 single-space seps.
const HEX_WIDTH: usize = HEX_ROW * 2 + (HEX_ROW - 1);

/// Renders a value to its compact JSON line. Returns the serializer error
/// verbatim rather than hiding a regression behind empty output.
fn json_line<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    serde_json::to_string(value)
}

/// Prints a single value as compact JSON on stdout.
pub(crate) fn print_json<T: Serialize>(value: &T) -> CliResult {
    let json = json_line(value)
        .map_err(|error| CliError::runtime(format!("serialize CLI JSON output: {error}")))?;
    print_line(&json)
}

/// Builds the aligned table lines (header first) for `headers`/`rows`. Column
/// widths are the max cell width per column. Ragged rows are tolerated (missing
/// cells render empty); extra cells beyond the header count are still printed.
fn table_lines(headers: &[&str], rows: &[Vec<String>]) -> Vec<String> {
    let columns = headers
        .len()
        .max(rows.iter().map(Vec::len).max().unwrap_or(0));
    let mut widths = vec![0usize; columns];
    for (col, header) in headers.iter().enumerate() {
        widths[col] = widths[col].max(header.len());
    }
    for row in rows {
        for (col, cell) in row.iter().enumerate() {
            widths[col] = widths[col].max(cell.len());
        }
    }

    let render = |cells: &[String]| -> String {
        (0..columns)
            .map(|col| {
                let cell = cells.get(col).map(String::as_str).unwrap_or("");
                format!("{cell:<width$}", width = widths[col])
            })
            .collect::<Vec<_>>()
            .join("  ")
            .trim_end()
            .to_string()
    };

    let header_cells: Vec<String> = headers.iter().map(|h| (*h).to_string()).collect();
    let mut lines = Vec::with_capacity(rows.len() + 1);
    lines.push(render(&header_cells));
    lines.extend(rows.iter().map(|row| render(row)));
    lines
}

/// Prints `rows` as a left-aligned table under `headers`.
pub(crate) fn print_table(headers: &[&str], rows: &[Vec<String>]) -> CliResult {
    print_lines(&table_lines(headers, rows)).map(|_| ())
}

/// Builds hex-dump lines in `xxd -g 1` layout starting at `offset`:
/// `{offset:08x}  {byte byte …}  |{ascii}|`, 16 bytes per row, hex column
/// padded so the ASCII gutter aligns across partial rows. A zero-length slice
/// yields no lines. Non-printable bytes render as `.` in the ASCII gutter.
fn hex_dump_lines(offset: u64, bytes: &[u8]) -> Vec<String> {
    bytes
        .chunks(HEX_ROW)
        .enumerate()
        .map(|(row_index, chunk)| {
            let row_offset = offset + (row_index * HEX_ROW) as u64;
            let hex = chunk
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join(" ");
            let ascii: String = chunk
                .iter()
                .map(|&byte| {
                    if (0x20..=0x7e).contains(&byte) {
                        byte as char
                    } else {
                        '.'
                    }
                })
                .collect();
            format!("{row_offset:08x}  {hex:<HEX_WIDTH$}  |{ascii}|")
        })
        .collect()
}

/// Prints `bytes` as a hex dump (see [`hex_dump_lines`]).
pub(crate) fn print_hex_dump(offset: u64, bytes: &[u8]) -> CliResult<WriteLineResult> {
    print_lines(&hex_dump_lines(offset, bytes))
}

/// Prints one line to stdout. A closed downstream pipe is a normal CLI
/// termination condition; other write failures remain structured errors.
pub(crate) fn print_line(text: &str) -> CliResult {
    print_line_result(text).map(|_| ())
}

/// Prints one line to stdout and reports whether the downstream pipe closed.
pub(crate) fn print_line_result(text: &str) -> CliResult<WriteLineResult> {
    let stdout = io::stdout();
    let mut lock = stdout.lock();
    write_line_allow_broken_pipe(&mut lock, text)
}

/// Prints several lines with one stdout lock. Stops at the first closed pipe.
pub(crate) fn print_lines(lines: &[String]) -> CliResult<WriteLineResult> {
    let stdout = io::stdout();
    let mut lock = stdout.lock();
    for line in lines {
        if write_line_allow_broken_pipe(&mut lock, line)? == WriteLineResult::ClosedPipe {
            return Ok(WriteLineResult::ClosedPipe);
        }
    }
    Ok(WriteLineResult::Written)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WriteLineResult {
    Written,
    ClosedPipe,
}

pub(crate) fn write_line_allow_broken_pipe<W: Write>(
    writer: &mut W,
    text: &str,
) -> CliResult<WriteLineResult> {
    match writer.write_all(text.as_bytes()) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {
            return Ok(WriteLineResult::ClosedPipe);
        }
        Err(error) => return Err(CliError::io(format!("write stdout: {error}"))),
    }
    match writer.write_all(b"\n") {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {
            return Ok(WriteLineResult::ClosedPipe);
        }
        Err(error) => return Err(CliError::io(format!("write stdout: {error}"))),
    }
    match writer.flush() {
        Ok(()) => Ok(WriteLineResult::Written),
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(WriteLineResult::ClosedPipe),
        Err(error) => Err(CliError::io(format!("flush stdout: {error}"))),
    }
}

