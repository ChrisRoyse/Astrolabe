use astrolabe_bridge::{
    CbmToolRunner, cbm_project_name_from_path, initialize_cbm_host_process, set_cbm_cache_dir,
};
use cbm_sys::{
    CBMFileResult, CBMResolvedCall, cbm_arena_destroy, cbm_arena_init, cbm_arena_strdup,
    cbm_pxc_canonicalize_appended_results, cbm_resolvedcall_push,
    initialize_allocator_bindings_first,
};
use serde_json::{Value, json};
use std::ffi::{CStr, CString, c_char};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::ptr;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject,
};
use windows_sys::Win32::System::ProcessStatus::{
    K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

const ALLOCATION_ROWS: usize = 100_000;
const ALLOCATION_HEADROOM: usize = 2 * 1024 * 1024;

fn fail(code: &str, message: impl std::fmt::Display, remediation: &str) -> ! {
    eprintln!("code={code} message={message} remediation={remediation}");
    std::process::exit(1);
}

fn write_exact(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap_or_else(|error| {
        fail(
            "ISSUE_1099_FSV_WRITE_FAILED",
            format!("path={} error={error}", path.display()),
            "repair the staged payload path and retry the complete manual FSV",
        )
    });
    let readback = fs::read(path).unwrap_or_else(|error| {
        fail(
            "ISSUE_1099_FSV_READBACK_FAILED",
            format!("path={} error={error}", path.display()),
            "preserve the staged session and inspect the physical payload file",
        )
    });
    if readback != bytes {
        fail(
            "ISSUE_1099_FSV_READBACK_MISMATCH",
            path.display(),
            "preserve the staged session and repair the physical write/read boundary",
        );
    }
}

fn next_path_arg(args: &mut impl Iterator<Item = std::ffi::OsString>, name: &str) -> PathBuf {
    args.next().map(PathBuf::from).unwrap_or_else(|| {
        fail(
            "ISSUE_1099_FSV_INDEX_CHILD_ARGUMENT_REQUIRED",
            name,
            "pass repo, cache, MCP output, payload output, and report output paths",
        )
    })
}

unsafe fn c_text(value: *const c_char) -> String {
    if value.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(value) }
        .to_string_lossy()
        .into_owned()
}

unsafe fn arena_text(result: &mut CBMFileResult, value: &str) -> *const c_char {
    let value = CString::new(value).unwrap_or_else(|error| {
        fail(
            "ISSUE_1099_FSV_STRING_INVALID",
            error,
            "use NUL-free synthetic resolved-call fields",
        )
    });
    let copied = unsafe { cbm_arena_strdup(&mut result.arena, value.as_ptr()) };
    if copied.is_null() {
        fail(
            "ISSUE_1099_FSV_ARENA_COPY_FAILED",
            value.to_string_lossy(),
            "inspect native allocator diagnostics before retrying",
        );
    }
    copied
}

unsafe fn push_call(
    result: &mut CBMFileResult,
    caller: Option<&str>,
    callee: &str,
    context: Option<&str>,
    strategy: &str,
    confidence: f32,
) {
    let caller_qn = match caller {
        Some(value) => unsafe { arena_text(result, value) },
        None => ptr::null(),
    };
    let callee_qn = unsafe { arena_text(result, callee) };
    let strategy = unsafe { arena_text(result, strategy) };
    let reason = unsafe { arena_text(result, "manual-fsv-known-identity") };
    let preprocess_context_id = match context {
        Some(value) => unsafe { arena_text(result, value) },
        None => ptr::null(),
    };
    let call = CBMResolvedCall {
        caller_qn,
        callee_qn,
        strategy,
        confidence,
        reason,
        preprocess_context_id,
    };
    if !unsafe { cbm_resolvedcall_push(&mut result.resolved_calls, &mut result.arena, call) } {
        fail(
            "ISSUE_1099_FSV_CALL_PUSH_FAILED",
            format!("caller={caller:?} callee={callee} context={context:?}"),
            "inspect native allocator diagnostics before retrying",
        );
    }
}

unsafe fn new_result() -> CBMFileResult {
    let mut result = CBMFileResult::default();
    unsafe { cbm_arena_init(&mut result.arena) };
    result
}

unsafe fn row_contexts(result: &CBMFileResult) -> Vec<String> {
    if result.resolved_calls.count <= 0 {
        return Vec::new();
    }
    let rows = unsafe {
        std::slice::from_raw_parts(
            result.resolved_calls.items,
            result.resolved_calls.count as usize,
        )
    };
    rows.iter()
        .map(|row| unsafe { c_text(row.preprocess_context_id) })
        .collect()
}

unsafe fn retained_rows(result: &CBMFileResult) -> Vec<(String, f32, bool)> {
    if result.resolved_calls.count <= 0 {
        return Vec::new();
    }
    let rows = unsafe {
        std::slice::from_raw_parts(
            result.resolved_calls.items,
            result.resolved_calls.count as usize,
        )
    };
    rows.iter()
        .map(|row| {
            (
                unsafe { c_text(row.strategy) },
                row.confidence,
                row.preprocess_context_id.is_null(),
            )
        })
        .collect()
}

unsafe fn direct_cases() -> Value {
    let mut happy = unsafe { new_result() };
    unsafe {
        push_call(
            &mut happy,
            Some("fixture.caller"),
            "fixture.target",
            None,
            "seed-lower-confidence",
            0.50,
        );
        push_call(
            &mut happy,
            Some("fixture.caller"),
            "fixture.target",
            Some(""),
            "cross-higher-confidence",
            0.95,
        );
        push_call(
            &mut happy,
            Some("fixture.caller"),
            "fixture.target",
            Some("ctx-B"),
            "cross-distinct-context",
            0.75,
        );
    }
    println!(
        "FSV_1099 happy before count={} accounted={}",
        happy.resolved_calls.count, happy.cross_lsp_accounting_present
    );
    if !unsafe { cbm_pxc_canonicalize_appended_results(&mut happy, 1) } {
        fail(
            "ISSUE_1099_FSV_HAPPY_MERGE_FAILED",
            unsafe { c_text(happy.error.code) },
            "inspect the canonical merge diagnostic and repair the production boundary",
        );
    }
    let happy_contexts = unsafe { row_contexts(&happy) };
    let happy_rows = unsafe { retained_rows(&happy) };
    println!(
        "FSV_1099 happy after count={} seeded={} source={} duplicate={} appended={} contexts={:?} rows={:?}",
        happy.resolved_calls.count,
        happy.cross_lsp_seeded_rows,
        happy.cross_lsp_source_rows,
        happy.cross_lsp_duplicate_rows,
        happy.cross_lsp_appended_rows,
        happy_contexts,
        happy_rows
    );
    if happy.resolved_calls.count != 2
        || happy.cross_lsp_seeded_rows != 1
        || happy.cross_lsp_source_rows != 2
        || happy.cross_lsp_duplicate_rows != 1
        || happy.cross_lsp_appended_rows != 1
        || happy_contexts != ["", "ctx-B"]
        || happy_rows
            != [
                ("cross-higher-confidence".to_owned(), 0.95, true),
                ("cross-distinct-context".to_owned(), 0.75, false),
            ]
    {
        fail(
            "ISSUE_1099_FSV_HAPPY_STATE_MISMATCH",
            "expected stable first-row position, canonical null context, higher-confidence payload, and one distinct context",
            "preserve the staged session and inspect the physical resolved-call array",
        );
    }
    let happy_json = json!({
        "before": {"count": 3, "accounting_present": false},
        "after": {
            "count": happy.resolved_calls.count,
            "accounting_present": happy.cross_lsp_accounting_present,
            "seeded": happy.cross_lsp_seeded_rows,
            "source": happy.cross_lsp_source_rows,
            "duplicate": happy.cross_lsp_duplicate_rows,
            "appended": happy.cross_lsp_appended_rows,
            "contexts": happy_contexts,
            "rows": happy_rows.iter().map(|(strategy, confidence, context_is_null)| json!({
                "strategy": strategy,
                "confidence": confidence,
                "context_is_null": context_is_null,
            })).collect::<Vec<_>>(),
        }
    });
    unsafe { cbm_arena_destroy(&mut happy.arena) };

    let mut empty = unsafe { new_result() };
    println!(
        "FSV_1099 empty before count={} accounted={}",
        empty.resolved_calls.count, empty.cross_lsp_accounting_present
    );
    if !unsafe { cbm_pxc_canonicalize_appended_results(&mut empty, 0) }
        || empty.resolved_calls.count != 0
        || !empty.cross_lsp_accounting_present
        || empty.cross_lsp_seeded_rows != 0
        || empty.cross_lsp_source_rows != 0
        || empty.cross_lsp_duplicate_rows != 0
        || empty.cross_lsp_appended_rows != 0
    {
        fail(
            "ISSUE_1099_FSV_EMPTY_STATE_MISMATCH",
            unsafe { c_text(empty.error.code) },
            "inspect zero-row canonicalization and its committed receipt",
        );
    }
    println!(
        "FSV_1099 empty after count={} accounted={}",
        empty.resolved_calls.count, empty.cross_lsp_accounting_present
    );
    let empty_json = json!({
        "before": {"count": 0, "accounting_present": false},
        "after": {"count": 0, "accounting_present": true, "seeded": 0, "source": 0,
            "duplicate": 0, "appended": 0}
    });
    unsafe { cbm_arena_destroy(&mut empty.arena) };

    let mut malformed = unsafe { new_result() };
    unsafe {
        push_call(
            &mut malformed,
            Some("fixture.caller"),
            "fixture.target",
            None,
            "valid-seed",
            1.0,
        );
        push_call(
            &mut malformed,
            None,
            "fixture.target",
            None,
            "invalid-source",
            1.0,
        );
    }
    println!(
        "FSV_1099 malformed before count={} has_error={}",
        malformed.resolved_calls.count, malformed.has_error
    );
    let malformed_status = unsafe { cbm_pxc_canonicalize_appended_results(&mut malformed, 1) };
    let malformed_code = unsafe { c_text(malformed.error.code) };
    println!(
        "FSV_1099 malformed after status={} count={} has_error={} code={}",
        malformed_status, malformed.resolved_calls.count, malformed.has_error, malformed_code
    );
    if malformed_status
        || !malformed.has_error
        || malformed.resolved_calls.count != 0
        || malformed.cross_lsp_accounting_present
        || malformed_code != "CBM_LSP_DEDUP_IDENTITY_INVALID"
    {
        fail(
            "ISSUE_1099_FSV_MALFORMED_STATE_MISMATCH",
            malformed_code,
            "repair the terminal malformed-identity refusal and discarded-array state",
        );
    }
    let malformed_json = json!({
        "before": {"count": 2, "has_error": false},
        "after": {"status": malformed_status, "count": malformed.resolved_calls.count,
            "has_error": malformed.has_error, "accounting_present": false,
            "code": malformed_code}
    });
    unsafe { cbm_arena_destroy(&mut malformed.arena) };

    json!({"happy": happy_json, "empty": empty_json, "malformed": malformed_json})
}

unsafe fn private_usage() -> usize {
    let mut counters = PROCESS_MEMORY_COUNTERS_EX::default();
    counters.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32;
    let ok = unsafe {
        K32GetProcessMemoryInfo(
            GetCurrentProcess(),
            &mut counters as *mut PROCESS_MEMORY_COUNTERS_EX as *mut PROCESS_MEMORY_COUNTERS,
            counters.cb,
        )
    };
    if ok == 0 {
        fail(
            "ISSUE_1099_FSV_MEMORY_READ_FAILED",
            unsafe { GetLastError() },
            "repair the native Windows process-memory read before retrying the allocation edge",
        );
    }
    counters.PrivateUsage
}

unsafe fn allocation_child(output: &Path) {
    initialize_allocator_bindings_first().unwrap_or_else(|error| {
        fail(
            "ISSUE_1099_FSV_ALLOCATOR_INIT_FAILED",
            error,
            "rebuild libcbm and Rust with the pinned native GNU toolchain",
        )
    });
    let mut result = unsafe { new_result() };
    let caller_qn = unsafe { arena_text(&mut result, "fixture.allocation_caller") };
    let callee_qn = unsafe { arena_text(&mut result, "fixture.allocation_target") };
    let strategy = unsafe { arena_text(&mut result, "issue-1099-synthetic") };
    let reason = unsafe { arena_text(&mut result, "manual-fsv-known-identity") };
    for _ in 0..ALLOCATION_ROWS {
        let call = CBMResolvedCall {
            caller_qn,
            callee_qn,
            strategy,
            confidence: 1.0,
            reason,
            preprocess_context_id: ptr::null(),
        };
        if !unsafe { cbm_resolvedcall_push(&mut result.resolved_calls, &mut result.arena, call) } {
            fail(
                "ISSUE_1099_FSV_ALLOCATION_SETUP_FAILED",
                result.resolved_calls.count,
                "repair the pre-limit synthetic array setup before retrying",
            );
        }
    }
    let before_private = unsafe { private_usage() };
    let process_limit = before_private
        .checked_add(ALLOCATION_HEADROOM)
        .unwrap_or_else(|| {
            fail(
                "ISSUE_1099_FSV_MEMORY_LIMIT_OVERFLOW",
                before_private,
                "run the allocation edge in a process whose committed bytes fit usize",
            )
        });
    println!(
        "FSV_1099 allocation before count={} private_bytes={} limit_bytes={}",
        result.resolved_calls.count, before_private, process_limit
    );

    let job = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
    if job.is_null() {
        fail(
            "ISSUE_1099_FSV_JOB_CREATE_FAILED",
            unsafe { GetLastError() },
            "repair nested Windows Job creation before retrying the real allocation refusal",
        );
    }
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    limits.ProcessMemoryLimit = process_limit;
    let configured = unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION as *const _,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    if configured == 0 {
        let error = unsafe { GetLastError() };
        unsafe { CloseHandle(job) };
        fail(
            "ISSUE_1099_FSV_JOB_LIMIT_FAILED",
            error,
            "repair the process-memory Job limit before retrying the real allocation refusal",
        );
    }
    if unsafe { AssignProcessToJobObject(job, GetCurrentProcess()) } == 0 {
        let error = unsafe { GetLastError() };
        unsafe { CloseHandle(job) };
        fail(
            "ISSUE_1099_FSV_JOB_ASSIGN_FAILED",
            error,
            "repair nested Job admission; do not replace the real allocation refusal with a mock",
        );
    }

    let status = unsafe { cbm_pxc_canonicalize_appended_results(&mut result, 0) };
    let code = unsafe { c_text(result.error.code) };
    let after_private = unsafe { private_usage() };
    unsafe { CloseHandle(job) };
    println!(
        "FSV_1099 allocation after status={} count={} has_error={} code={} private_bytes={}",
        status, result.resolved_calls.count, result.has_error, code, after_private
    );
    if status
        || !result.has_error
        || result.resolved_calls.count != 0
        || result.cross_lsp_accounting_present
        || !(code.contains("ALLOC") || code.contains("CAPACITY"))
    {
        fail(
            "ISSUE_1099_FSV_ALLOCATION_STATE_MISMATCH",
            code,
            "repair the typed terminal allocation boundary before accepting the implementation",
        );
    }
    let report = json!({
        "before": {"count": ALLOCATION_ROWS, "private_bytes": before_private,
            "process_memory_limit_bytes": process_limit},
        "after": {"status": status, "count": result.resolved_calls.count,
            "has_error": result.has_error, "accounting_present": false,
            "code": code, "private_bytes": after_private}
    });
    let bytes = serde_json::to_vec(&report).unwrap_or_else(|error| {
        fail(
            "ISSUE_1099_FSV_ALLOCATION_JSON_FAILED",
            error,
            "repair allocation-edge report serialization",
        )
    });
    write_exact(output, &bytes);
    unsafe { cbm_arena_destroy(&mut result.arena) };
}

fn write_fixture(repo: &Path) {
    fs::create_dir(repo).unwrap_or_else(|error| {
        fail(
            "ISSUE_1099_FSV_REPO_CREATE_FAILED",
            format!("path={} error={error}", repo.display()),
            "use one absent staged fixture repository",
        )
    });
    write_exact(
        &repo.join("local.py"),
        b"def target(value):\n    return value + 1\n\ndef caller():\n    return target(41)\n",
    );
    write_exact(
        &repo.join("provider.py"),
        b"def remote(value):\n    return value * 2\n",
    );
    write_exact(
        &repo.join("consumer.py"),
        b"from provider import remote\n\ndef consume():\n    return remote(21)\n",
    );
    write_exact(
        &repo.join("Helper.java"),
        b"package demo;\n\nfinal class Helper {\n    static int twice(int value) { return value * 2; }\n}\n",
    );
    write_exact(
        &repo.join("Caller.java"),
        b"package demo;\n\nfinal class Caller {\n    int local(int value) { return value + 1; }\n    int invoke() { return local(1) + Helper.twice(2); }\n}\n",
    );
}

fn run_index_child(
    repo: &Path,
    cache: &Path,
    mcp_output: &Path,
    payload_output: &Path,
    report_output: &Path,
) {
    fs::create_dir(cache).unwrap_or_else(|error| {
        fail(
            "ISSUE_1099_FSV_CACHE_CREATE_FAILED",
            format!("path={} error={error}", cache.display()),
            "use one absent payload-local cache for each real index child",
        )
    });
    let cache_readback = set_cbm_cache_dir(cache).unwrap_or_else(|error| {
        fail(
            "ISSUE_1099_FSV_CACHE_BIND_FAILED",
            error,
            "inspect the native cache resolver diagnostic; do not substitute an environment-only override",
        )
    });
    if cache_readback != cache {
        fail(
            "ISSUE_1099_FSV_CACHE_READBACK_MISMATCH",
            format!(
                "requested={} observed={}",
                cache.display(),
                cache_readback.display()
            ),
            "preserve both paths and repair the native cache resolver before indexing",
        );
    }
    let executable = std::env::current_exe().unwrap_or_else(|error| {
        fail(
            "ISSUE_1099_FSV_EXE_PATH_FAILED",
            error,
            "repair current executable discovery before production host initialization",
        )
    });
    let executable_text = executable.to_str().unwrap_or_else(|| {
        fail(
            "ISSUE_1099_FSV_EXE_PATH_INVALID",
            executable.display(),
            "run the staged FSV artifact from a UTF-8 workspace path",
        )
    });
    initialize_cbm_host_process(Some(executable_text)).unwrap_or_else(|error| {
        fail(
            "ISSUE_1099_FSV_HOST_INIT_FAILED",
            error,
            "repair the production host initialization boundary before indexing real data",
        )
    });
    let repo_text = repo.to_str().unwrap_or_else(|| {
        fail(
            "ISSUE_1099_FSV_REPO_PATH_INVALID",
            repo.display(),
            "use one UTF-8 staged repository path",
        )
    });
    let project = cbm_project_name_from_path(repo_text).unwrap_or_else(|error| {
        fail(
            "ISSUE_1099_FSV_PROJECT_DERIVATION_FAILED",
            error,
            "repair canonical repository identity derivation before indexing",
        )
    });
    let database = cache.join(format!("{project}.db"));
    if database.exists() {
        fail(
            "ISSUE_1099_FSV_DATABASE_PREEXISTS",
            database.display(),
            "use a fresh absent staged database for each deterministic run",
        );
    }
    println!(
        "FSV_1099 index before database={} exists={}",
        database.display(),
        database.exists()
    );
    let runner = CbmToolRunner::new_default().unwrap_or_else(|error| {
        fail(
            "ISSUE_1099_FSV_RUNNER_CREATE_FAILED",
            error,
            "inspect native MCP server initialization and retry",
        )
    });
    let args = json!({"repo_path": repo, "mode": "full", "calyx": "off"}).to_string();
    let raw = astrolabe_server::migration::handle_tool_raw(&runner, "index_repository", &args)
        .unwrap_or_else(|error| {
            fail(
                "ISSUE_1099_FSV_INDEX_CALL_FAILED",
                error,
                "inspect the native index diagnostic and repair the production path",
            )
        });
    drop(runner);
    write_exact(mcp_output, raw.as_bytes());
    let envelope: Value = serde_json::from_str(&raw).unwrap_or_else(|error| {
        fail(
            "ISSUE_1099_FSV_INDEX_JSON_INVALID",
            error,
            "inspect the exact native index response bytes",
        )
    });
    let content = envelope
        .get("content")
        .and_then(Value::as_array)
        .filter(|content| content.len() == 1)
        .and_then(|content| content.first())
        .filter(|content| content.get("type") == Some(&Value::String("text".to_string())))
        .and_then(|content| content.get("text"))
        .and_then(Value::as_str)
        .unwrap_or_else(|| {
            fail(
                "ISSUE_1099_FSV_MCP_CONTENT_INVALID",
                &raw,
                "repair the MCP result envelope so it contains exactly one text payload",
            )
        });
    let payload: Value = serde_json::from_str(content).unwrap_or_else(|error| {
        fail(
            "ISSUE_1099_FSV_MCP_CONTENT_JSON_INVALID",
            error,
            "preserve the exact MCP envelope and repair its text-payload serializer",
        )
    });
    let structured = envelope.get("structuredContent").unwrap_or_else(|| {
        fail(
            "ISSUE_1099_FSV_MCP_STRUCTURED_CONTENT_MISSING",
            &raw,
            "repair the MCP result envelope so structuredContent mirrors content[0].text",
        )
    });
    if structured != &payload {
        fail(
            "ISSUE_1099_FSV_MCP_MIRROR_MISMATCH",
            &raw,
            "preserve both MCP representations and repair the producer before retrying",
        );
    }
    write_exact(payload_output, content.as_bytes());
    let accounting = &payload["parallel_resolver_accounting"];
    if envelope.get("isError") != Some(&Value::Bool(false))
        || payload.get("code").is_some()
        || payload.get("status") != Some(&Value::String("indexed".to_string()))
        || payload.get("project") != Some(&Value::String(project.clone()))
        || accounting["state"] != "measured"
        || accounting["cross_lsp_units"] != accounting["cross_lsp_accounted_units"]
        || accounting["cross_lsp_seen_rows"]
            != accounting["cross_lsp_seeded_rows"].as_u64().unwrap_or(0)
                + accounting["cross_lsp_source_rows"].as_u64().unwrap_or(0)
        || accounting["cross_lsp_source_rows"]
            != accounting["cross_lsp_duplicate_rows"].as_u64().unwrap_or(0)
                + accounting["cross_lsp_appended_rows"].as_u64().unwrap_or(0)
    {
        fail(
            "ISSUE_1099_FSV_INDEX_ACCOUNTING_INVALID",
            raw,
            "repair the native MCP accounting producer/consumer contract",
        );
    }
    if !database.is_file() || database.with_extension("db-wal").exists() {
        fail(
            "ISSUE_1099_FSV_DATABASE_PUBLICATION_INVALID",
            format!(
                "database={} exists={} wal_exists={}",
                database.display(),
                database.is_file(),
                database.with_extension("db-wal").exists()
            ),
            "preserve the cache and repair the physical SQLite publication boundary",
        );
    }
    println!(
        "FSV_1099 index after database={} exists={} accounting={}",
        database.display(),
        database.exists(),
        accounting
    );
    let report = json!({
        "schema": "astrolabe.issue-1099.index-child.v1",
        "project": project,
        "cache_requested": cache,
        "cache_readback": cache_readback,
        "database": database,
        "mcp_output": mcp_output,
        "payload_output": payload_output,
        "accounting": accounting,
    });
    let report_bytes = serde_json::to_vec(&report).unwrap_or_else(|error| {
        fail(
            "ISSUE_1099_FSV_INDEX_REPORT_JSON_FAILED",
            error,
            "repair index-child receipt serialization",
        )
    });
    write_exact(report_output, &report_bytes);
}

fn spawn_index_child(repo: &Path, cache: &Path, prefix: &Path) -> Value {
    let mcp_output = prefix.with_extension("mcp.json");
    let payload_output = prefix.with_extension("index.json");
    let report_output = prefix.with_extension("child.json");
    let status = Command::new(std::env::current_exe().unwrap_or_else(|error| {
        fail(
            "ISSUE_1099_FSV_EXE_PATH_FAILED",
            error,
            "repair current executable discovery before the index child",
        )
    }))
    .arg("--index-child")
    .arg(repo)
    .arg(cache)
    .arg(&mcp_output)
    .arg(&payload_output)
    .arg(&report_output)
    .status()
    .unwrap_or_else(|error| {
        fail(
            "ISSUE_1099_FSV_INDEX_CHILD_START_FAILED",
            error,
            "repair real child-process launch; do not substitute an in-process cache switch",
        )
    });
    if !status.success() {
        fail(
            "ISSUE_1099_FSV_INDEX_CHILD_FAILED",
            status,
            "inspect the child diagnostic and preserve its isolated cache",
        );
    }
    serde_json::from_slice(&fs::read(&report_output).unwrap_or_else(|error| {
        fail(
            "ISSUE_1099_FSV_INDEX_REPORT_READ_FAILED",
            error,
            "preserve the index-child report and inspect its physical bytes",
        )
    }))
    .unwrap_or_else(|error| {
        fail(
            "ISSUE_1099_FSV_INDEX_REPORT_JSON_INVALID",
            error,
            "inspect the physical index-child report bytes",
        )
    })
}

fn main() {
    let process_args = std::env::args_os().collect::<Vec<_>>();
    if process_args
        .get(1)
        .is_some_and(|argument| argument == "cli")
    {
        std::process::exit(astrolabe_server::run_from_env_on_sized_host_thread());
    }
    let mut args = process_args.into_iter().skip(1);
    let first = args.next().unwrap_or_else(|| {
        fail(
            "ISSUE_1099_FSV_PAYLOAD_REQUIRED",
            "payload directory is required",
            "run this committed example through native-fsv-run",
        )
    });
    if first == "--allocation-child" {
        let output = args.next().map(PathBuf::from).unwrap_or_else(|| {
            fail(
                "ISSUE_1099_FSV_ALLOCATION_OUTPUT_REQUIRED",
                "allocation child output path is required",
                "pass one staged allocation report path",
            )
        });
        if args.next().is_some() {
            fail(
                "ISSUE_1099_FSV_ARGUMENT_COUNT_INVALID",
                "unexpected allocation child argument",
                "pass only --allocation-child and its output path",
            );
        }
        unsafe { allocation_child(&output) };
        return;
    }
    if first == "--index-child" {
        let repo = next_path_arg(&mut args, "repo");
        let cache = next_path_arg(&mut args, "cache");
        let mcp_output = next_path_arg(&mut args, "mcp_output");
        let payload_output = next_path_arg(&mut args, "payload_output");
        let report_output = next_path_arg(&mut args, "report_output");
        if args.next().is_some() {
            fail(
                "ISSUE_1099_FSV_ARGUMENT_COUNT_INVALID",
                "unexpected index child argument",
                "pass only the five required index-child paths",
            );
        }
        run_index_child(&repo, &cache, &mcp_output, &payload_output, &report_output);
        return;
    }

    let payload = PathBuf::from(first);
    if args.next().is_some() {
        fail(
            "ISSUE_1099_FSV_ARGUMENT_COUNT_INVALID",
            "unexpected argument after payload path",
            "pass exactly one fresh staged payload directory",
        );
    }
    fs::create_dir(&payload).unwrap_or_else(|error| {
        fail(
            "ISSUE_1099_FSV_PAYLOAD_CREATE_FAILED",
            format!("path={} error={error}", payload.display()),
            "use one absent direct payload child of the staged session",
        )
    });
    let executable = std::env::current_exe().unwrap_or_else(|error| {
        fail(
            "ISSUE_1099_FSV_EXE_PATH_FAILED",
            error,
            "repair current executable discovery before production host initialization",
        )
    });
    let executable = executable.to_str().unwrap_or_else(|| {
        fail(
            "ISSUE_1099_FSV_EXE_PATH_INVALID",
            executable.display(),
            "run the staged FSV artifact from a UTF-8 workspace path",
        )
    });
    initialize_cbm_host_process(Some(executable)).unwrap_or_else(|error| {
        fail(
            "ISSUE_1099_FSV_HOST_INIT_FAILED",
            error,
            "repair the production host initialization boundary before indexing real data",
        )
    });

    let direct = unsafe { direct_cases() };
    let direct_bytes = serde_json::to_vec(&direct).unwrap_or_else(|error| {
        fail(
            "ISSUE_1099_FSV_DIRECT_JSON_FAILED",
            error,
            "repair direct receipt serialization",
        )
    });
    write_exact(&payload.join("direct.json"), &direct_bytes);

    let allocation_path = payload.join("allocation.json");
    let status = Command::new(std::env::current_exe().unwrap_or_else(|error| {
        fail(
            "ISSUE_1099_FSV_EXE_PATH_FAILED",
            error,
            "repair current executable discovery before the allocation edge",
        )
    }))
    .arg("--allocation-child")
    .arg(&allocation_path)
    .status()
    .unwrap_or_else(|error| {
        fail(
            "ISSUE_1099_FSV_ALLOCATION_CHILD_START_FAILED",
            error,
            "repair real child-process launch; do not substitute a mocked allocation failure",
        )
    });
    if !status.success() {
        fail(
            "ISSUE_1099_FSV_ALLOCATION_CHILD_FAILED",
            status,
            "inspect the child diagnostic and repair the real OS-enforced allocation boundary",
        );
    }
    let allocation: Value =
        serde_json::from_slice(&fs::read(&allocation_path).unwrap_or_else(|error| {
            fail(
                "ISSUE_1099_FSV_ALLOCATION_READ_FAILED",
                error,
                "preserve the allocation child report and inspect its physical bytes",
            )
        }))
        .unwrap_or_else(|error| {
            fail(
                "ISSUE_1099_FSV_ALLOCATION_JSON_INVALID",
                error,
                "inspect the physical allocation report bytes",
            )
        });

    let repo = payload.join("repo");
    write_fixture(&repo);
    let first_index =
        spawn_index_child(&repo, &payload.join("first-store"), &payload.join("first"));
    let second_index = spawn_index_child(
        &repo,
        &payload.join("second-store"),
        &payload.join("second"),
    );
    let report = json!({
        "schema": "astrolabe.issue-1099.cross-lsp-fsv.v2",
        "direct": direct,
        "allocation": allocation,
        "first_index": first_index,
        "second_index": second_index,
    });
    let report_bytes = serde_json::to_vec(&report).unwrap_or_else(|error| {
        fail(
            "ISSUE_1099_FSV_REPORT_JSON_FAILED",
            error,
            "repair final report serialization",
        )
    });
    write_exact(&payload.join("report.json"), &report_bytes);
}
