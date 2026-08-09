#![forbid(unsafe_code)]

const NATIVE_REPRODUCIBILITY_CONTRACT: &str = "astrolabe.native-reproducibility.v1";

fn main() {
    let mut arguments = std::env::args_os();
    let _executable = arguments.next();
    if matches!(
        (arguments.next(), arguments.next()),
        (Some(argument), None) if argument == std::ffi::OsStr::new("--version")
    ) {
        println!(
            "codebase-memory-mcp {} (native-reproducibility={NATIVE_REPRODUCIBILITY_CONTRACT})",
            env!("CARGO_PKG_VERSION")
        );
        return;
    }

    // #730: this shim — not `astrolabe` — is the binary the installed MCP server
    // and every CLI driver execute, so it must enter the CBM pipeline through the
    // same registry-sized host thread. Calling `run_from_env` directly here left
    // the pipeline on the undersized process main thread, where the predump
    // configlink frame faulted in its `___chkstk_ms` prologue and killed the
    // worker with a diagnostic-free 0xC00000FD before any log line or database.
    //
    // #1059: the shared bootstrap also applies the external-termination sentinel
    // guard, so this binary can never self-exit -1 (0xFFFFFFFF).
    std::process::exit(astrolabe_server::run_from_env_on_sized_host_thread());
}
