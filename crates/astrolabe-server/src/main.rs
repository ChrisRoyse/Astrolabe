#![forbid(unsafe_code)]

fn main() {
    // #364/#730: every dispatch mode (`cli <tool>`, the stdio server loop, and
    // hook-augment) can enter the in-process CBM pipeline on THIS thread, and
    // the pipeline consumes several MiB of stack before its first log line — the
    // process main-thread reserve is fixed by the PE header and overflows with a
    // diagnostic-free STATUS_STACK_OVERFLOW (0xC00000FD). The single shared
    // bootstrap runs the whole entrypoint on a host thread sized from the
    // registry-declared knob; no binary re-implements it.
    //
    // #1059: that same bootstrap applies the external-termination sentinel
    // guard, so no entrypoint here can ever self-exit -1 (0xFFFFFFFF) — the
    // signature TerminateProcess(handle, -1) leaves behind.
    std::process::exit(astrolabe_server::run_from_env_on_sized_host_thread());
}
