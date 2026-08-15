use cbm_sys::{
    CBM_STORE_CLOSE_OK, cbm_edge_t, cbm_index_capability_t, cbm_index_mode_t_CBM_MODE_FAST,
    cbm_node_t, cbm_semantic_state_t_CBM_SEMANTIC_UNAVAILABLE_MODE, cbm_store_begin,
    cbm_store_close, cbm_store_close_result_t, cbm_store_commit, cbm_store_count_edges,
    cbm_store_count_nodes, cbm_store_insert_edge, cbm_store_open_path, cbm_store_t,
    cbm_store_upsert_node, cbm_store_upsert_project, initialize_allocator_bindings_first,
};
use sha2::{Digest, Sha256};
use std::ffi::{CStr, CString, c_char, c_int};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::ptr;

const PROJECT: &str = "issue-671-layout";
const HAPPY_NODES: i32 = 300;
const HAPPY_EDGES: i32 = 299;

#[repr(C)]
struct LayoutNode {
    id: i64,
    x: f32,
    y: f32,
    z: f32,
    label: *const c_char,
    name: *const c_char,
    qualified_name: *const c_char,
    file_path: *const c_char,
    start_line: c_int,
    end_line: c_int,
    color: u32,
    size: f32,
    in_calls: c_int,
    status: *const c_char,
}

#[repr(C)]
struct LayoutEdge {
    source: i64,
    target: i64,
    type_: *const c_char,
}

#[repr(C)]
struct LayoutResult {
    nodes: *mut LayoutNode,
    node_count: c_int,
    edges: *mut LayoutEdge,
    edge_count: c_int,
    total_nodes: c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct LayoutError {
    code: [c_char; 64],
    operation: [c_char; 64],
    message: [c_char; 512],
    remediation: [c_char; 256],
    store_error_code: c_int,
}

impl Default for LayoutError {
    fn default() -> Self {
        Self {
            code: [0; 64],
            operation: [0; 64],
            message: [0; 512],
            remediation: [0; 256],
            store_error_code: 0,
        }
    }
}

unsafe extern "C" {
    fn cbm_layout_compute(
        store: *mut cbm_store_t,
        project: *const c_char,
        level: c_int,
        center_node: *const c_char,
        radius: c_int,
        max_nodes: c_int,
        error: *mut LayoutError,
    ) -> *mut LayoutResult;
    fn cbm_layout_free(result: *mut LayoutResult);
    fn cbm_layout_to_json(result: *const LayoutResult, error: *mut LayoutError) -> *mut c_char;
    fn cbm_free_string(value: *mut c_char);
}

fn c_text<const N: usize>(value: &[c_char; N]) -> String {
    unsafe { CStr::from_ptr(value.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

fn fail(code: &str, message: impl std::fmt::Display, remediation: &str) -> ! {
    eprintln!("code={code} message={message} remediation={remediation}");
    std::process::exit(1);
}

fn cstring(value: &str, field: &str) -> CString {
    CString::new(value).unwrap_or_else(|error| {
        fail(
            "ISSUE_671_FSV_STRING_INVALID",
            format!("{field} contains NUL: {error}"),
            "use exact NUL-free fixture values",
        )
    })
}

fn hash_frame(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value);
}

fn canonical_atom_id(name: &str, qualified_name: &str, line: i32) -> String {
    let mut hasher = Sha256::new();
    for part in [
        "astrolabe.cbm.atom.v2",
        PROJECT,
        "Function",
        name,
        qualified_name,
        "src/layout_fixture.c",
    ] {
        hash_frame(&mut hasher, part.as_bytes());
    }
    hash_frame(&mut hasher, &[0]);
    hash_frame(&mut hasher, &[]);
    hasher.update((line as i64 as u64).to_le_bytes());
    hasher.update((line as i64 as u64).to_le_bytes());
    hasher.update(0_u64.to_le_bytes());
    hasher.update(0_u64.to_le_bytes());
    let digest = hasher.finalize();
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        if write!(&mut output, "{byte:02x}").is_err() {
            fail(
                "ISSUE_671_FSV_ATOM_ENCODING_FAILED",
                "canonical atom digest could not be encoded",
                "inspect the Rust formatter implementation before creating fixture state",
            );
        }
    }
    output
}

unsafe fn close_store(store: &mut *mut cbm_store_t, operation: &str) {
    let mut result = cbm_store_close_result_t::default();
    let status = unsafe { cbm_store_close(store, &mut result) };
    if status != CBM_STORE_CLOSE_OK || !store.is_null() {
        fail(
            "ISSUE_671_FSV_STORE_CLOSE_FAILED",
            format!(
                "operation={operation} status={status} sqlite_error={} connection_destroyed={}",
                result.sqlite_close_code, result.connection_destroyed
            ),
            "preserve the fixture store and resolve the reported live SQLite owner",
        );
    }
}

unsafe fn create_fixture(path: &Path, nodes: i32, edges: i32) -> *mut cbm_store_t {
    let path_c = cstring(
        path.to_str().unwrap_or_else(|| {
            fail(
                "ISSUE_671_FSV_PATH_INVALID",
                path.display(),
                "use a UTF-8 workspace-local payload path",
            )
        }),
        "database path",
    );
    let store = unsafe { cbm_store_open_path(path_c.as_ptr()) };
    if store.is_null() {
        fail(
            "ISSUE_671_FSV_STORE_OPEN_FAILED",
            path.display(),
            "inspect the native store diagnostic and retry with a fresh absent path",
        );
    }
    if unsafe { cbm_store_begin(store) } != 0 {
        fail(
            "ISSUE_671_FSV_BEGIN_FAILED",
            path.display(),
            "inspect the store diagnostic and retry with a fresh fixture database",
        );
    }
    let project = cstring(PROJECT, "project");
    let root = cstring("C:/synthetic/issue-671", "root");
    let capability = cbm_index_capability_t {
        index_mode: cbm_index_mode_t_CBM_MODE_FAST,
        semantic_state: cbm_semantic_state_t_CBM_SEMANTIC_UNAVAILABLE_MODE,
        vector_dimension: 768,
        eligible_node_count: -1,
        node_vector_count: 0,
        token_vector_count: 0,
    };
    if unsafe { cbm_store_upsert_project(store, project.as_ptr(), root.as_ptr(), &capability) } != 0
    {
        fail(
            "ISSUE_671_FSV_PROJECT_WRITE_FAILED",
            path.display(),
            "inspect the store diagnostic and repair project persistence",
        );
    }

    let label = cstring("Function", "label");
    let file_path = cstring("src/layout_fixture.c", "file path");
    let properties = cstring("{}", "node properties");
    let mut ids = Vec::with_capacity(nodes as usize);
    for index in 0..nodes {
        let name_text = format!("node_{index:03}");
        let qn_text = format!("fixture.node_{index:03}");
        let line = index + 1;
        let name = cstring(&name_text, "node name");
        let qn = cstring(&qn_text, "qualified name");
        let atom = cstring(&canonical_atom_id(&name_text, &qn_text, line), "atom id");
        let node = cbm_node_t {
            id: 0,
            project: project.as_ptr(),
            label: label.as_ptr(),
            name: name.as_ptr(),
            atom_id: atom.as_ptr(),
            qualified_name: qn.as_ptr(),
            file_path: file_path.as_ptr(),
            start_line: line,
            end_line: line,
            source_present: false,
            source_bytes: ptr::null(),
            source_len: 0,
            source_sha256: ptr::null(),
            start_byte: 0,
            end_byte: 0,
            properties_json: properties.as_ptr(),
        };
        let id = unsafe { cbm_store_upsert_node(store, &node) };
        if id <= 0 {
            fail(
                "ISSUE_671_FSV_NODE_WRITE_FAILED",
                format!("path={} node={index}", path.display()),
                "inspect the store diagnostic and repair node persistence",
            );
        }
        ids.push(id);
    }

    let edge_type = cstring("CALLS", "edge type");
    let edge_properties = cstring("{}", "edge properties");
    for index in 0..edges {
        let edge = cbm_edge_t {
            id: 0,
            project: project.as_ptr(),
            source_id: ids[index as usize],
            target_id: ids[index as usize + 1],
            type_: edge_type.as_ptr(),
            properties_json: edge_properties.as_ptr(),
        };
        if unsafe { cbm_store_insert_edge(store, &edge) } <= 0 {
            fail(
                "ISSUE_671_FSV_EDGE_WRITE_FAILED",
                format!("path={} edge={index}", path.display()),
                "inspect the store diagnostic and repair edge persistence",
            );
        }
    }
    if unsafe { cbm_store_commit(store) } != 0 {
        fail(
            "ISSUE_671_FSV_COMMIT_FAILED",
            path.display(),
            "inspect the store diagnostic and complete the fixture transaction",
        );
    }
    store
}

unsafe fn compute_json(
    store: *mut cbm_store_t,
    project: &CString,
    max_nodes: i32,
    expected_nodes: i32,
    expected_edges: i32,
    output: &Path,
) {
    let mut error = LayoutError::default();
    let result = unsafe {
        cbm_layout_compute(
            store,
            project.as_ptr(),
            0,
            ptr::null(),
            0,
            max_nodes,
            &mut error,
        )
    };
    if result.is_null() {
        fail(
            "ISSUE_671_FSV_LAYOUT_FAILED",
            format!(
                "code={} operation={} message={}",
                c_text(&error.code),
                c_text(&error.operation),
                c_text(&error.message)
            ),
            &c_text(&error.remediation),
        );
    }
    let observed = unsafe { &*result };
    if observed.node_count != expected_nodes || observed.edge_count != expected_edges {
        let observed_nodes = observed.node_count;
        let observed_edges = observed.edge_count;
        unsafe { cbm_layout_free(result) };
        fail(
            "ISSUE_671_FSV_LAYOUT_COUNTS_MISMATCH",
            format!(
                "expected_nodes={expected_nodes} observed_nodes={} expected_edges={expected_edges} observed_edges={}",
                observed_nodes, observed_edges
            ),
            "inspect persisted nodes and edges plus the layout filter before accepting the result",
        );
    }
    let json = unsafe { cbm_layout_to_json(result, &mut error) };
    if json.is_null() {
        unsafe { cbm_layout_free(result) };
        fail(
            "ISSUE_671_FSV_LAYOUT_JSON_FAILED",
            format!(
                "code={} operation={} message={}",
                c_text(&error.code),
                c_text(&error.operation),
                c_text(&error.message)
            ),
            &c_text(&error.remediation),
        );
    }
    let bytes = unsafe { CStr::from_ptr(json) }.to_bytes();
    fs::write(output, bytes).unwrap_or_else(|error| {
        fail(
            "ISSUE_671_FSV_LAYOUT_JSON_WRITE_FAILED",
            format!("path={} error={error}", output.display()),
            "repair the staged payload path and retry",
        )
    });
    unsafe {
        cbm_free_string(json);
        cbm_layout_free(result);
    }
}

unsafe fn counts(store: *mut cbm_store_t, project: &CString) -> (i32, i32) {
    let nodes = unsafe { cbm_store_count_nodes(store, project.as_ptr()) };
    let edges = unsafe { cbm_store_count_edges(store, project.as_ptr()) };
    if nodes < 0 || edges < 0 {
        fail(
            "ISSUE_671_FSV_COUNT_READBACK_FAILED",
            format!("nodes={nodes} edges={edges}"),
            "inspect the store diagnostic and repair the exact fixture before continuing",
        );
    }
    (nodes, edges)
}

fn json_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

fn main() {
    initialize_allocator_bindings_first().unwrap_or_else(|error| {
        fail(
            "ISSUE_671_FSV_ALLOCATOR_INIT_FAILED",
            error,
            "rebuild libcbm and Rust with the pinned native GNU toolchain",
        )
    });
    let mut arguments = std::env::args_os().skip(1);
    let payload = arguments.next().map(PathBuf::from).unwrap_or_else(|| {
        fail(
            "ISSUE_671_FSV_PAYLOAD_REQUIRED",
            "payload directory and sqlite3 executable arguments are required",
            "run through native-fsv-run with one fresh payload path and the exact sqlite3.exe path",
        )
    });
    let sqlite = arguments.next().map(PathBuf::from).unwrap_or_else(|| {
        fail(
            "ISSUE_671_FSV_SQLITE_REQUIRED",
            "sqlite3 executable argument is required",
            "pass the exact installed sqlite3.exe path as the second argument",
        )
    });
    if arguments.next().is_some() {
        fail(
            "ISSUE_671_FSV_ARGUMENT_COUNT_INVALID",
            "unexpected argument after the sqlite3 executable path",
            "pass exactly the payload directory and sqlite3 executable path",
        );
    }
    if !sqlite.is_file() {
        fail(
            "ISSUE_671_FSV_SQLITE_MISSING",
            format!("path={}", sqlite.display()),
            "install sqlite3.exe or pass its exact existing executable path",
        );
    }
    fs::create_dir(&payload).unwrap_or_else(|error| {
        fail(
            "ISSUE_671_FSV_PAYLOAD_CREATE_FAILED",
            format!("path={} error={error}", payload.display()),
            "use one absent direct payload child of the staged session",
        )
    });

    let project = cstring(PROJECT, "project");
    let empty_project = project.clone();
    let invalid_project = cstring("", "invalid project");
    let happy_db = payload.join("happy.db");
    let empty_db = payload.join("empty.db");
    let corrupt_db = payload.join("corrupt.db");

    unsafe {
        let mut happy_store = create_fixture(&happy_db, HAPPY_NODES, HAPPY_EDGES);
        let happy_before = counts(happy_store, &project);
        println!(
            "FSV_EDGE happy before nodes={} edges={}",
            happy_before.0, happy_before.1
        );
        compute_json(
            happy_store,
            &project,
            HAPPY_NODES,
            HAPPY_NODES,
            HAPPY_EDGES,
            &payload.join("happy-layout.json"),
        );
        let happy_after = counts(happy_store, &project);
        println!(
            "FSV_EDGE happy after nodes={} edges={}",
            happy_after.0, happy_after.1
        );

        let max_before = counts(happy_store, &project);
        println!(
            "FSV_EDGE max_one before nodes={} edges={}",
            max_before.0, max_before.1
        );
        compute_json(
            happy_store,
            &project,
            1,
            1,
            0,
            &payload.join("max-one-layout.json"),
        );
        let max_after = counts(happy_store, &project);
        println!(
            "FSV_EDGE max_one after nodes={} edges={}",
            max_after.0, max_after.1
        );

        let invalid_before = counts(happy_store, &project);
        println!(
            "FSV_EDGE invalid before nodes={} edges={}",
            invalid_before.0, invalid_before.1
        );
        let mut invalid_error = LayoutError::default();
        let invalid = cbm_layout_compute(
            happy_store,
            invalid_project.as_ptr(),
            0,
            ptr::null(),
            0,
            HAPPY_NODES,
            &mut invalid_error,
        );
        if !invalid.is_null() || c_text(&invalid_error.code) != "CBM_LAYOUT_INPUT_INVALID" {
            cbm_layout_free(invalid);
            fail(
                "ISSUE_671_FSV_INVALID_INPUT_ACCEPTED",
                format!("code={}", c_text(&invalid_error.code)),
                "empty project input must terminate before reading or mutating the store",
            );
        }
        let invalid_after = counts(happy_store, &project);
        println!(
            "FSV_EDGE invalid after nodes={} edges={} code={}",
            invalid_after.0,
            invalid_after.1,
            c_text(&invalid_error.code)
        );
        close_store(&mut happy_store, "happy.complete");

        let mut empty_store = create_fixture(&empty_db, 0, 0);
        let empty_before = counts(empty_store, &empty_project);
        println!(
            "FSV_EDGE empty before nodes={} edges={}",
            empty_before.0, empty_before.1
        );
        compute_json(
            empty_store,
            &empty_project,
            64,
            0,
            0,
            &payload.join("empty-layout.json"),
        );
        let empty_after = counts(empty_store, &empty_project);
        println!(
            "FSV_EDGE empty after nodes={} edges={}",
            empty_after.0, empty_after.1
        );
        close_store(&mut empty_store, "empty.complete");

        let mut corrupt_store = create_fixture(&corrupt_db, 2, 1);
        let drop_output = Command::new(&sqlite)
            .arg("-batch")
            .arg(&corrupt_db)
            .arg("DROP TABLE edges;")
            .output()
            .unwrap_or_else(|error| {
                fail(
                    "ISSUE_671_FSV_CORRUPTION_PROCESS_FAILED",
                    format!("sqlite={} error={error}", sqlite.display()),
                    "verify the exact sqlite3.exe path can start under the native launcher lease",
                )
            });
        if !drop_output.status.success() || !drop_output.stderr.is_empty() {
            fail(
                "ISSUE_671_FSV_CORRUPTION_SETUP_FAILED",
                format!(
                    "sqlite_status={} stdout={} stderr={}",
                    drop_output.status,
                    String::from_utf8_lossy(&drop_output.stdout),
                    String::from_utf8_lossy(&drop_output.stderr)
                ),
                "use a fresh fixture database and retry the exact DROP TABLE action",
            );
        }
        println!("FSV_EDGE corrupt before nodes=2 edge_table=absent");
        let mut corrupt_error = LayoutError::default();
        let corrupt = cbm_layout_compute(
            corrupt_store,
            project.as_ptr(),
            0,
            ptr::null(),
            0,
            64,
            &mut corrupt_error,
        );
        if !corrupt.is_null() || !c_text(&corrupt_error.code).starts_with("CBM_LAYOUT_") {
            cbm_layout_free(corrupt);
            fail(
                "ISSUE_671_FSV_CORRUPT_STORE_ACCEPTED",
                format!("code={}", c_text(&corrupt_error.code)),
                "a missing persisted edge table must terminate without a partial layout",
            );
        }
        let corrupt_code = c_text(&corrupt_error.code);
        let corrupt_operation = c_text(&corrupt_error.operation);
        let corrupt_nodes_after = cbm_store_count_nodes(corrupt_store, project.as_ptr());
        if corrupt_nodes_after != 2 {
            fail(
                "ISSUE_671_FSV_CORRUPT_STATE_CHANGED",
                format!("expected_nodes=2 observed_nodes={corrupt_nodes_after}"),
                "preserve the corrupt store and inspect why a read-only layout changed it",
            );
        }
        println!(
            "FSV_EDGE corrupt after nodes={} edge_table=absent code={}",
            corrupt_nodes_after, corrupt_code
        );
        close_store(&mut corrupt_store, "corrupt.complete");

        if happy_before != happy_after
            || happy_before != max_before
            || max_before != max_after
            || max_before != invalid_before
            || invalid_before != invalid_after
            || empty_before != empty_after
        {
            fail(
                "ISSUE_671_FSV_STATE_CHANGED",
                "a layout action changed its persisted fixture counts",
                "preserve every fixture and inspect the first before/after mismatch",
            );
        }

        let report = format!(
            "{{\"schema\":\"astrolabe.issue-671.layout-fsv.v1\",\"happy\":{{\"nodes\":{HAPPY_NODES},\"edges\":{HAPPY_EDGES},\"before\":[{},{}],\"after\":[{},{}]}},\"max_one\":{{\"nodes\":1,\"edges\":0,\"before\":[{},{}],\"after\":[{},{}]}},\"empty\":{{\"nodes\":0,\"edges\":0,\"before\":[{},{}],\"after\":[{},{}]}},\"invalid\":{{\"code\":\"CBM_LAYOUT_INPUT_INVALID\",\"before\":[{},{}],\"after\":[{},{}]}},\"corrupt\":{{\"code\":\"{}\",\"operation\":\"{}\",\"before_nodes\":2,\"after_nodes\":{}}}}}",
            happy_before.0,
            happy_before.1,
            happy_after.0,
            happy_after.1,
            max_before.0,
            max_before.1,
            max_after.0,
            max_after.1,
            empty_before.0,
            empty_before.1,
            empty_after.0,
            empty_after.1,
            invalid_before.0,
            invalid_before.1,
            invalid_after.0,
            invalid_after.1,
            json_escape(&corrupt_code),
            json_escape(&corrupt_operation),
            corrupt_nodes_after,
        );
        fs::write(payload.join("report.json"), report).unwrap_or_else(|error| {
            fail(
                "ISSUE_671_FSV_REPORT_WRITE_FAILED",
                error,
                "repair the staged payload path and retry",
            )
        });
    }

    println!(
        "ISSUE_671_FSV_COMPLETE happy_nodes={HAPPY_NODES} happy_edges={HAPPY_EDGES} edges_over_initial_capacity={} edge_cases=empty,max_one,invalid,corrupt",
        HAPPY_EDGES - 256
    );
}
