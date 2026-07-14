#![forbid(unsafe_code)]

fn main() {
    // #364: every dispatch mode (`cli <tool>`, the stdio server loop, and
    // hook-augment) can enter the in-process CBM pipeline on THIS thread, and
    // the pipeline consumes >2 MiB of stack before its first log line — the
    // process main-thread default reserve overflows with a diagnostic-free
    // STATUS_STACK_OVERFLOW (0xC00000FD). The main thread's stack cannot be
    // resized after start, so run the whole entrypoint on an explicitly sized
    // host thread from the registry-declared knob. Threads created inside
    // (e.g. the incremental watcher) size their own stacks from the same knob.
    let host = std::thread::Builder::new()
        .name("astrolabe-cbm-host".to_string())
        .stack_size(astrolabe_server::cbm_pipeline_host_stack_bytes())
        .spawn(astrolabe_server::run_from_env)
        .expect("spawn sized CBM host thread");
    let code = match host.join() {
        Ok(code) => code,
        Err(_) => {
            eprintln!("astrolabe: CBM host thread panicked");
            1
        }
    };
    std::process::exit(code);
}
