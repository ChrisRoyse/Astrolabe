#![forbid(unsafe_code)]

fn main() {
    // #730: this shim — not `astrolabe` — is the binary the installed MCP server
    // and every CLI driver execute, so it must enter the CBM pipeline through the
    // same registry-sized host thread. Calling `run_from_env` directly here left
    // the pipeline on the undersized process main thread, where the predump
    // configlink frame faulted in its `___chkstk_ms` prologue and killed the
    // worker with a diagnostic-free 0xC00000FD before any log line or database.
    std::process::exit(astrolabe_server::run_from_env_on_sized_host_thread());
}
