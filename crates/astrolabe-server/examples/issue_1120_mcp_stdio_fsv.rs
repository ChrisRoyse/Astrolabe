//! Manual Full State Verification for #1073/#1120's MCP wire contract.
//!
//! This executable feeds a real newline-delimited JSON-RPC transcript through
//! the production `serve_jsonrpc` transport and native CBM tool runner. It is a
//! manual reality probe, not a test or an alternate dispatcher.

use std::error::Error;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::PathBuf;
use std::thread;

use astrolabe_bridge::CbmToolRunner;

type AnyResult<T> = Result<T, Box<dyn Error + Send + Sync + 'static>>;

fn run(transcript_path: PathBuf) -> AnyResult<()> {
    let transcript = File::open(&transcript_path)?;
    let runner = CbmToolRunner::new_default()?;
    let stdout = std::io::stdout();
    astrolabe_server::serve_jsonrpc(
        &runner,
        BufReader::new(transcript),
        BufWriter::new(stdout.lock()),
    )
}

fn main() -> AnyResult<()> {
    let mut args = std::env::args_os().skip(1);
    let transcript_path = PathBuf::from(
        args.next()
            .ok_or("usage: issue_1120_mcp_stdio_fsv <transcript.ndjson>")?,
    );
    if args.next().is_some() {
        return Err("unexpected extra argument".into());
    }
    let outcome = thread::Builder::new()
        .name("issue-1120-mcp-fsv".to_string())
        .stack_size(astrolabe_server::cbm_pipeline_host_stack_bytes())
        .spawn(move || run(transcript_path))?
        .join();
    match outcome {
        Ok(result) => result,
        Err(_) => Err("manual MCP FSV host thread panicked".into()),
    }
}
