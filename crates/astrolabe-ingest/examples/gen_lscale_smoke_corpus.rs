//! Deterministic pinned smoke corpus generator for the L-scale ingest bench.
//!
//! Writes a small Codebase Memory MCP-shaped SQLite dump (projects, nodes,
//! edges, node_vectors) whose logical content is a pure function of the seed,
//! so `scripts/bench-ingest-lscale.sh --smoke` measures the real import path
//! against a reproducible corpus instead of skipping.
//!
//! Usage: `gen_lscale_smoke_corpus <out.db> [node-count] [seed]`
//!
//! On success prints one JSON line with the corpus parameters and a
//! `content_sha256` computed over the canonical logical rows (not the SQLite
//! file bytes, which are page-layout dependent), so callers can pin the corpus
//! identity across regenerations.

use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};

const DEFAULT_NODE_COUNT: usize = 400;
const DEFAULT_SEED: u64 = 20_260_711;
const PROJECT: &str = "astrolabe-lscale-smoke";
const VECTOR_DIMS: usize = 64;

/// SplitMix64: tiny, dependency-free, deterministic PRNG. Statistical quality
/// is irrelevant here; only cross-run/cross-platform byte determinism matters.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn next_range(&mut self, bound: usize) -> usize {
        (self.next_u64() % bound as u64) as usize
    }
}

struct NodeRow {
    id: i64,
    label: &'static str,
    name: String,
    qualified_name: String,
    file_path: String,
    start_line: i64,
    end_line: i64,
    properties: String,
    vector: Option<Vec<u8>>,
}

struct EdgeRow {
    source_id: i64,
    target_id: i64,
    kind: &'static str,
}

fn build_rows(node_count: usize, seed: u64) -> (Vec<NodeRow>, Vec<EdgeRow>) {
    let mut rng = SplitMix64(seed);
    let mut nodes = Vec::with_capacity(node_count);
    let folder_count = (node_count / 40).max(1);

    // Structural bucket: Folder nodes exercise the structural-only import path.
    for index in 0..folder_count {
        nodes.push(NodeRow {
            id: (index + 1) as i64,
            label: "Folder",
            name: format!("pkg{index}"),
            qualified_name: format!("{PROJECT}.pkg{index}"),
            file_path: format!("src/pkg{index}"),
            start_line: 0,
            end_line: 0,
            properties: "{}".to_string(),
            vector: None,
        });
    }

    // Constellation bucket: Function/Class symbols with deterministic snippets.
    for index in 0..node_count.saturating_sub(folder_count) {
        let id = (folder_count + index + 1) as i64;
        let folder = index % folder_count;
        let is_class = index % 7 == 0;
        let label = if is_class { "Class" } else { "Function" };
        let name = format!("sym_{index:04}");
        let body_lines = 3 + rng.next_range(24) as i64;
        let start_line = 1 + rng.next_range(400) as i64;
        let snippet = if is_class {
            format!(
                "class Sym{index:04}:\n    field_a = {}\n    field_b = {}\n",
                rng.next_u64() % 100,
                rng.next_u64() % 100
            )
        } else {
            format!(
                "def sym_{index:04}(a, b):\n    x = a * {} + b\n    if x > {}:\n        return x - {}\n    return x\n",
                rng.next_u64() % 97,
                rng.next_u64() % 1000,
                rng.next_u64() % 13,
            )
        };
        let vector = if index % 2 == 0 {
            let mut blob = Vec::with_capacity(VECTOR_DIMS * 4);
            for _ in 0..VECTOR_DIMS {
                // Deterministic pseudo-embedding in [-1, 1).
                let value = ((rng.next_u64() % 2_000_000) as f32 / 1_000_000.0) - 1.0;
                blob.extend_from_slice(&value.to_le_bytes());
            }
            Some(blob)
        } else {
            None
        };
        nodes.push(NodeRow {
            id,
            label,
            name: name.clone(),
            qualified_name: format!("{PROJECT}.pkg{folder}.{name}"),
            file_path: format!("src/pkg{folder}/mod_{:02}.py", index % 17),
            start_line,
            end_line: start_line + body_lines,
            properties: format!(
                r#"{{"source_snippet":{}}}"#,
                serde_json::to_string(&snippet).expect("snippet is valid JSON string input")
            ),
            vector,
        });
    }

    // Edges: CONTAINS from folders to symbols, CALLS among symbols.
    let mut edges = Vec::new();
    let first_symbol = folder_count as i64 + 1;
    let last_symbol = nodes.len() as i64;
    for node in &nodes[folder_count..] {
        let folder_id = 1 + ((node.id - first_symbol) as usize % folder_count) as i64;
        edges.push(EdgeRow {
            source_id: folder_id,
            target_id: node.id,
            kind: "CONTAINS",
        });
    }
    let symbol_span = (last_symbol - first_symbol + 1).max(1) as usize;
    let call_count = symbol_span * 2;
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..call_count {
        let source = first_symbol + rng.next_range(symbol_span) as i64;
        let target = first_symbol + rng.next_range(symbol_span) as i64;
        if source != target && seen.insert((source, target)) {
            edges.push(EdgeRow {
                source_id: source,
                target_id: target,
                kind: "CALLS",
            });
        }
    }
    (nodes, edges)
}

fn content_sha256(nodes: &[NodeRow], edges: &[EdgeRow]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"astrolabe-lscale-smoke-corpus-v1\n");
    for node in nodes {
        hasher.update(node.id.to_le_bytes());
        hasher.update(node.label.as_bytes());
        hasher.update([0]);
        hasher.update(node.qualified_name.as_bytes());
        hasher.update([0]);
        hasher.update(node.file_path.as_bytes());
        hasher.update([0]);
        hasher.update(node.start_line.to_le_bytes());
        hasher.update(node.end_line.to_le_bytes());
        hasher.update(node.properties.as_bytes());
        hasher.update([0]);
        match &node.vector {
            Some(blob) => {
                hasher.update([1]);
                hasher.update(blob);
            }
            None => hasher.update([0]),
        }
    }
    for edge in edges {
        hasher.update(edge.source_id.to_le_bytes());
        hasher.update(edge.target_id.to_le_bytes());
        hasher.update(edge.kind.as_bytes());
        hasher.update([0]);
    }
    let digest = hasher.finalize();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = env::args().collect::<Vec<_>>();
    if args.len() < 2 {
        eprintln!("usage: gen_lscale_smoke_corpus <out.db> [node-count] [seed]");
        std::process::exit(2);
    }
    let out = PathBuf::from(&args[1]);
    let node_count = args
        .get(2)
        .map(|value| value.parse::<usize>())
        .transpose()?
        .unwrap_or(DEFAULT_NODE_COUNT);
    let seed = args
        .get(3)
        .map(|value| value.parse::<u64>())
        .transpose()?
        .unwrap_or(DEFAULT_SEED);
    if node_count < 2 {
        return Err("node-count must be >= 2 (one folder plus one symbol)".into());
    }

    let (nodes, edges) = build_rows(node_count, seed);
    let hash = content_sha256(&nodes, &edges);

    if let Some(parent) = out.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::remove_file(&out).ok();
    let mut connection = Connection::open(&out)?;
    connection.execute_batch(
        "CREATE TABLE projects (
             name TEXT PRIMARY KEY,
             indexed_at TEXT NOT NULL,
             root_path TEXT NOT NULL
         );
         CREATE TABLE nodes (
             id INTEGER PRIMARY KEY,
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
         );
         CREATE TABLE node_vectors (
             node_id INTEGER PRIMARY KEY,
             project TEXT NOT NULL,
             vector BLOB NOT NULL
         );",
    )?;
    let tx = connection.transaction()?;
    tx.execute(
        "INSERT INTO projects(name, indexed_at, root_path) VALUES (?1, ?2, ?3)",
        params![PROJECT, "1970-01-01T00:00:00Z", "/pinned/lscale-smoke"],
    )?;
    for node in &nodes {
        tx.execute(
            "INSERT INTO nodes(id, project, label, name, qualified_name, file_path, start_line, end_line, properties)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                node.id,
                PROJECT,
                node.label,
                node.name,
                node.qualified_name,
                node.file_path,
                node.start_line,
                node.end_line,
                node.properties,
            ],
        )?;
        if let Some(vector) = &node.vector {
            tx.execute(
                "INSERT INTO node_vectors(node_id, project, vector) VALUES (?1, ?2, ?3)",
                params![node.id, PROJECT, vector],
            )?;
        }
    }
    for edge in &edges {
        tx.execute(
            "INSERT INTO edges(project, source_id, target_id, type, properties)
             VALUES (?1, ?2, ?3, ?4, '{}')",
            params![PROJECT, edge.source_id, edge.target_id, edge.kind],
        )?;
    }
    tx.commit()?;
    drop(connection);

    println!(
        "{}",
        serde_json::json!({
            "schema": "astrolabe-lscale-smoke-corpus-v1",
            "path": out.display().to_string(),
            "project": PROJECT,
            "node_count": nodes.len(),
            "edge_count": edges.len(),
            "vector_count": nodes.iter().filter(|node| node.vector.is_some()).count(),
            "seed": seed,
            "content_sha256": hash,
        })
    );
    Ok(())
}
