// Runs on every platform (#133): the real-CBM-C-store-opens-the-lowered-artifact
// claim must execute natively on the Windows dev machine, not only under a unix
// gate. cbm-sys links the native libcbm archive, so building this test needs the
// pinned GNU toolchain (make + GCC) — the same requirement as the shipped binary.

use std::fs;
use std::path::{Path, PathBuf};

use astrolabe_ingest::{SqliteImportOptions, import_sqlite_to_vault};
use astrolabe_lower::{LowerSqliteOptions, lower_cbm_sqlite};
use astrolabe_panel::FixtureSlotRuntime;
use calyx_aster::vault::AsterVault;
use calyx_core::{SystemClock, VaultId};
use rusqlite::{Connection, params};

#[test]
fn cbm_store_search_and_schema_open_lowered_artifact_unmodified() {
    let source = temp_path("cbm-source.db");
    let lowered = temp_path("cbm-lowered.db");
    fixture_sqlite(&source);

    let vault = vault();
    import_sqlite_to_vault(
        &source,
        &vault,
        &FixtureSlotRuntime,
        &SqliteImportOptions::new("demo", "commit-a", 1),
    )
    .expect("import source sqlite");
    lower_cbm_sqlite(&vault, &lowered, &LowerSqliteOptions::new("demo"))
        .expect("lower sqlite artifact");

    assert_cbm_store_queries(&lowered);

    cleanup(&source);
    cleanup(&lowered);
}

fn assert_cbm_store_queries(path: &Path) {
    let probe = cbm_sys::query_store_search_schema_counts(path, "demo", "Function")
        .expect("CBM store opened lowered artifact and returned schema counts");
    assert!(
        probe.search_count >= 2,
        "CBM search returned lowered Function nodes"
    );
    assert!(has_count(&probe.node_labels, "Function", 2));
    assert!(has_count(&probe.edge_types, "CALLS", 1));
    assert!(has_count(&probe.edge_types, "DEFINES", 1));
}

fn has_count(counts: &[cbm_sys::CbmStoreCount], name: &str, count: i32) -> bool {
    counts
        .iter()
        .any(|entry| entry.name == name && entry.count == count)
}

fn fixture_sqlite(path: &Path) {
    cleanup(path);
    let connection = Connection::open(path).expect("open fixture db");
    connection
        .execute_batch(
            "CREATE TABLE projects (
               name TEXT PRIMARY KEY,
               indexed_at TEXT NOT NULL,
               root_path TEXT NOT NULL
             );
             CREATE TABLE nodes (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               project TEXT NOT NULL,
               label TEXT NOT NULL,
               name TEXT NOT NULL,
               qualified_name TEXT NOT NULL,
               file_path TEXT DEFAULT '',
               start_line INTEGER DEFAULT 0,
               end_line INTEGER DEFAULT 0,
               properties TEXT DEFAULT '{}',
               UNIQUE(project, qualified_name)
             );
             CREATE TABLE edges (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               project TEXT NOT NULL,
               source_id INTEGER NOT NULL,
               target_id INTEGER NOT NULL,
               type TEXT NOT NULL,
               properties TEXT DEFAULT '{}',
               url_path_gen TEXT GENERATED ALWAYS AS (json_extract(properties,'$.url_path')),
               local_name_gen TEXT GENERATED ALWAYS AS (CASE WHEN type='IMPORTS'
                 THEN coalesce(json_extract(properties,'$.local_name'),'') ELSE '' END),
               UNIQUE(source_id, target_id, type, local_name_gen)
             );",
        )
        .expect("create fixture schema");
    connection
        .execute(
            "INSERT INTO projects(name, indexed_at, root_path) VALUES ('demo', '2026-03-14T00:00:00Z', '/repo')",
            [],
        )
        .expect("project");
    insert_node(
        &connection,
        &FixtureNode {
            label: "File",
            name: "__file__",
            qualified_name: "demo.src.main.__file__",
            file_path: "src/main.rs",
            start_line: 1,
            end_line: 30,
            properties: r#"{"language":"rust","source_snippet":"mod main","signature":"mod main"}"#,
        },
    );
    insert_node(
        &connection,
        &FixtureNode {
            label: "Function",
            name: "alpha",
            qualified_name: "demo.src.main.alpha",
            file_path: "src/main.rs",
            start_line: 3,
            end_line: 8,
            properties: r#"{"language":"rust","source_snippet":"fn alpha(){ beta(); }","signature":"fn alpha()"}"#,
        },
    );
    insert_node(
        &connection,
        &FixtureNode {
            label: "Function",
            name: "beta",
            qualified_name: "demo.src.main.beta",
            file_path: "src/main.rs",
            start_line: 10,
            end_line: 12,
            properties: r#"{"language":"rust","source_snippet":"fn beta() {}","signature":"fn beta()"}"#,
        },
    );
    connection
        .execute(
            "INSERT INTO edges(project, source_id, target_id, type, properties) VALUES ('demo', 1, 2, 'DEFINES', '{}')",
            [],
        )
        .expect("defines");
    connection
        .execute(
            "INSERT INTO edges(project, source_id, target_id, type, properties) VALUES ('demo', 2, 3, 'CALLS', '{\"callee\":\"beta\"}')",
            [],
        )
        .expect("calls");
}

struct FixtureNode<'a> {
    label: &'a str,
    name: &'a str,
    qualified_name: &'a str,
    file_path: &'a str,
    start_line: i64,
    end_line: i64,
    properties: &'a str,
}

fn insert_node(connection: &Connection, node: &FixtureNode<'_>) {
    connection
        .execute(
            "INSERT INTO nodes(project, label, name, qualified_name, file_path, start_line, end_line, properties)
             VALUES ('demo', ?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                node.label,
                node.name,
                node.qualified_name,
                node.file_path,
                node.start_line,
                node.end_line,
                node.properties,
            ],
        )
        .expect("insert node");
}

fn vault() -> AsterVault<SystemClock> {
    AsterVault::with_clock(
        "00000000000000000000000001"
            .parse::<VaultId>()
            .expect("vault id"),
        b"astrolabe-lower-cbm-store-test".to_vec(),
        SystemClock,
    )
}

fn temp_path(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("astrolabe-lower-{}-{name}", std::process::id()));
    path
}

fn cleanup(path: &Path) {
    let _ = fs::remove_file(path);
    let _ = fs::remove_file(sidecar_path(path, "-wal"));
    let _ = fs::remove_file(sidecar_path(path, "-shm"));
    let _ = fs::remove_file(sidecar_path(path, "-journal"));
}

fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut text = path.as_os_str().to_os_string();
    text.push(suffix);
    PathBuf::from(text)
}
