use astrolabe_bridge::{CbmToolRunner, initialize_cbm_host_process};
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
}

fn run_index(repo: &Path, database: &Path, output: &Path) -> Value {
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
    let runner = CbmToolRunner::new(database.to_str().unwrap_or_else(|| {
        fail(
            "ISSUE_1099_FSV_DATABASE_PATH_INVALID",
            database.display(),
            "use a UTF-8 staged database path",
        )
    }))
    .unwrap_or_else(|error| {
        fail(
            "ISSUE_1099_FSV_RUNNER_CREATE_FAILED",
            error,
            "inspect native MCP server initialization and retry",
        )
    });
    let args = json!({"repo_path": repo, "mode": "full"}).to_string();
    let raw = runner
        .handle_tool_raw("index_repository", &args)
        .unwrap_or_else(|error| {
            fail(
                "ISSUE_1099_FSV_INDEX_CALL_FAILED",
                error,
                "inspect the native index diagnostic and repair the production path",
            )
        });
    drop(runner);
    write_exact(output, raw.as_bytes());
    let value: Value = serde_json::from_str(&raw).unwrap_or_else(|error| {
        fail(
            "ISSUE_1099_FSV_INDEX_JSON_INVALID",
            error,
            "inspect the exact native index response bytes",
        )
    });
    let accounting = &value["parallel_resolver_accounting"];
    if value.get("code").is_some()
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
    println!(
        "FSV_1099 index after database={} exists={} accounting={}",
        database.display(),
        database.exists(),
        accounting
    );
    value
}

fn main() {
    let mut args = std::env::args_os().skip(1);
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
    initialize_cbm_host_process(None).unwrap_or_else(|error| {
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
    let first_index = run_index(
        &repo,
        &payload.join("first.db"),
        &payload.join("first-index.json"),
    );
    let second_index = run_index(
        &repo,
        &payload.join("second.db"),
        &payload.join("second-index.json"),
    );
    let report = json!({
        "schema": "astrolabe.issue-1099.cross-lsp-fsv.v1",
        "direct": direct,
        "allocation": allocation,
        "first_accounting": first_index["parallel_resolver_accounting"],
        "second_accounting": second_index["parallel_resolver_accounting"],
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
