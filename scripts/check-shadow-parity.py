#!/usr/bin/env python3
import argparse
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROJECT = "astrolabe_shadow_parity"
WHITELIST = ROOT / "ci" / "shadow-parity-whitelist.json"
SHADOW_VAULT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"


def run(argv, *, env=None, cwd=ROOT, timeout=240):
    proc = subprocess.run(
        [str(arg) for arg in argv],
        cwd=cwd,
        env=env,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    if proc.returncode != 0:
        raise SystemExit(
            f"command failed ({proc.returncode}): {' '.join(map(str, argv))}\n"
            f"--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}"
        )
    return proc


def default_upstream():
    exe = ".exe" if os.name == "nt" else ""
    candidates = [
        ROOT / "target" / "cbm-parity" / f"codebase-memory-mcp{exe}",
        ROOT / "target" / "cbm-parity" / "codebase-memory-mcp",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def build_upstream():
    build_dir = ROOT / "target" / "cbm-parity"
    exe = ".exe" if os.name == "nt" else ""
    run(
        [
            "make",
            "-C",
            ROOT / "vendor" / "codebase-memory-mcp",
            "-f",
            ROOT / "patches" / "cbm" / "Makefile.cbm",
            f"BUILD_DIR={build_dir}",
            "cbm",
        ],
        timeout=300,
    )
    built = build_dir / f"codebase-memory-mcp{exe}"
    if not built.exists():
        built = build_dir / "codebase-memory-mcp"
    if not built.exists():
        raise SystemExit(f"upstream build did not produce {built}")
    return built


def default_astrolabe():
    exe = ".exe" if os.name == "nt" else ""
    candidates = [
        ROOT / "target" / "debug" / f"astrolabe{exe}",
        ROOT / "target" / "debug" / "astrolabe",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def build_astrolabe():
    exe = ".exe" if os.name == "nt" else ""
    run(["cargo", "build", "-p", "astrolabe-server", "--bin", "astrolabe"], timeout=300)
    built = ROOT / "target" / "debug" / f"astrolabe{exe}"
    if not built.exists():
        built = ROOT / "target" / "debug" / "astrolabe"
    if not built.exists():
        raise SystemExit(f"astrolabe build did not produce {built}")
    return built


def base_env(cache):
    env = dict(os.environ)
    env["CBM_CACHE_DIR"] = str(cache)
    env["CBM_LOG_LEVEL"] = "none"
    env["NO_COLOR"] = "1"
    return env


def write_fixture(repo):
    src = repo / "src"
    src.mkdir(parents=True)
    lines = ["static int f00(int x) { return x + 1; }\n"]
    for index in range(1, 24):
        prev = f"f{index - 1:02d}"
        name = f"f{index:02d}"
        lines.append(f"static int {name}(int x) {{ return {prev}(x) + 1; }}\n")
    lines.append("int main(void) { return f23(0); }\n")
    (src / "main.c").write_text("".join(lines), encoding="utf-8")


def cli_tool(binary, cache, tool, args):
    proc = run(
        [binary, "cli", "--json", tool, json.dumps(args, separators=(",", ":"))],
        env=base_env(cache),
        timeout=240,
    )
    payload = json.loads(proc.stdout)
    if payload.get("isError") is True:
        raise SystemExit(f"{tool} returned isError=true: {payload}")
    return payload


def structured(binary, cache, tool, args):
    return cli_tool(binary, cache, tool, args)["structuredContent"]


def sqlite_rows(path, sql, params=()):
    connection = sqlite3.connect(path)
    try:
        return list(connection.execute(sql, params))
    finally:
        connection.close()


def schema_rows(path):
    return sqlite_rows(
        path,
        "SELECT type, name, tbl_name, trim(sql) FROM sqlite_master "
        "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
    )


def node_rows(path):
    rows = sqlite_rows(
        path,
        "SELECT qualified_name, label, name, file_path, start_line, end_line, properties "
        "FROM nodes ORDER BY qualified_name",
    )
    return {
        row[0]: {
            "label": row[1],
            "name": row[2],
            "file_path": row[3],
            "start_line": row[4],
            "end_line": row[5],
            "properties": row[6],
        }
        for row in rows
    }


def edge_rows(path):
    return sqlite_rows(
        path,
        "SELECT e.type, s.qualified_name, t.qualified_name, e.properties, e.local_name_gen "
        "FROM edges e JOIN nodes s ON s.id=e.source_id JOIN nodes t ON t.id=e.target_id "
        "ORDER BY e.type, s.qualified_name, t.qualified_name, e.properties, e.local_name_gen",
    )


def fts_rows(path):
    return sqlite_rows(
        path,
        "SELECT n.qualified_name FROM nodes_fts f JOIN nodes n ON n.id=f.rowid "
        "WHERE nodes_fts MATCH 'f23' ORDER BY n.qualified_name",
    )


def load_whitelist(path):
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema") != "astrolabe-shadow-parity-whitelist-v1":
        raise SystemExit(f"unexpected whitelist schema in {path}")
    return payload.get("entries", [])


def is_whitelisted(divergence, entries):
    for entry in entries:
        if all(divergence.get(key) == value for key, value in entry.items()):
            return True
    return False


def compare_schema(native_db, shadow_db, divergences):
    left = schema_rows(native_db)
    right = schema_rows(shadow_db)
    if left != right:
        divergences.append({"kind": "schema", "field": "sqlite_master"})


def compare_nodes(native_db, shadow_db, divergences):
    native = node_rows(native_db)
    shadow = node_rows(shadow_db)
    for qn in sorted(set(native) - set(shadow)):
        divergences.append({"kind": "node_missing_shadow", "qn": qn})
    for qn in sorted(set(shadow) - set(native)):
        divergences.append({"kind": "node_extra_shadow", "qn": qn})
    for qn in sorted(set(native) & set(shadow)):
        for field in ["label", "name", "file_path", "start_line", "end_line", "properties"]:
            if native[qn][field] != shadow[qn][field]:
                divergences.append(
                    {
                        "kind": "node_field",
                        "qn": qn,
                        "field": field,
                        "native": native[qn][field],
                        "shadow": shadow[qn][field],
                    }
                )
    return len(native)


def compare_edges(native_db, shadow_db, divergences):
    native = edge_rows(native_db)
    shadow = edge_rows(shadow_db)
    if native != shadow:
        divergences.append({"kind": "edge_multiset", "field": "edges"})
    return len(native)


def compare_fts(native_db, shadow_db, divergences):
    native = fts_rows(native_db)
    shadow = fts_rows(shadow_db)
    if native != shadow:
        divergences.append({"kind": "fts", "field": "f23"})


def compare_search(upstream, astrolabe, native_cache, shadow_cache, divergences):
    args = {"project": PROJECT, "label": "Function", "name_pattern": "f23", "limit": 10}
    native = structured(upstream, native_cache, "search_graph", args)
    shadow = structured(astrolabe, shadow_cache, "search_graph", args)
    if native != shadow:
        divergences.append({"kind": "search_graph", "field": "Function:f23"})
    native_names = {name for row in native.get("results", []) if (name := search_result_name(row))}
    shadow_names = {name for row in shadow.get("results", []) if (name := search_result_name(row))}
    overlap = len(native_names & shadow_names)
    denom = max(1, min(len(native_names), len(shadow_names), 10))
    return overlap / denom


def search_result_name(row):
    if not isinstance(row, dict):
        return None
    node = row.get("node")
    if isinstance(node, dict):
        return node.get("name")
    return row.get("name")


def inject_sqlite_fault(path):
    connection = sqlite3.connect(path)
    try:
        qn = connection.execute(
            "SELECT qualified_name FROM nodes WHERE label='Function' ORDER BY qualified_name LIMIT 1"
        ).fetchone()[0]
        connection.execute(
            "UPDATE nodes SET properties = ? WHERE qualified_name = ?",
            ['{"astrolabe_shadow_fault":true}', qn],
        )
        connection.commit()
        return qn
    finally:
        connection.close()


def deep_verify(astrolabe, vault_dir, project):
    proc = run(
        [
            astrolabe,
            "verify",
            "--deep",
            "--json",
            "--vault",
            vault_dir,
            "--vault-id",
            SHADOW_VAULT_ID,
            "--vault-salt",
            f"astrolabe-shadow-v1:{project}",
        ],
        timeout=120,
    )
    return json.loads(proc.stdout)


def write_dashboard(path, dashboard):
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dashboard, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_summary(path, dashboard):
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"# Shadow Parity Dashboard: {dashboard['project']}",
        "",
        f"- schema: {dashboard['schema']}",
        f"- status: {dashboard['status']}",
        f"- nodes: {dashboard['nodes']}",
        f"- edges: {dashboard['edges']}",
        f"- search_overlap_at_10: {dashboard['search_overlap_at_10']:.3f}",
        f"- divergences: {len(dashboard['divergences'])}",
        f"- second_run_new_cx_ids: {dashboard['idempotency']['second']['new_cx_ids']}",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream", type=Path)
    parser.add_argument("--astrolabe", type=Path)
    parser.add_argument("--whitelist", type=Path, default=WHITELIST)
    parser.add_argument("--dashboard-out", type=Path)
    parser.add_argument("--summary-out", type=Path)
    parser.add_argument("--inject-fault", action="store_true")
    parser.add_argument("--expect-failure", action="store_true")
    parser.add_argument("--keep-temp", action="store_true")
    args = parser.parse_args()

    upstream = args.upstream or default_upstream() or build_upstream()
    astrolabe = args.astrolabe or default_astrolabe() or build_astrolabe()
    if not upstream.exists():
        raise SystemExit(f"missing upstream binary: {upstream}")
    if not astrolabe.exists():
        raise SystemExit(f"missing astrolabe binary: {astrolabe}")
    whitelist = load_whitelist(args.whitelist)

    tmp = Path(tempfile.mkdtemp(prefix="astrolabe-shadow-parity-"))
    try:
        repo = tmp / "repo"
        native_cache = tmp / "native-cache"
        shadow_cache = tmp / "shadow-cache"
        native_cache.mkdir()
        shadow_cache.mkdir()
        write_fixture(repo)

        structured(
            upstream,
            native_cache,
            "index_repository",
            {"repo_path": str(repo), "mode": "fast", "name": PROJECT},
        )
        first = structured(
            astrolabe,
            shadow_cache,
            "index_repository",
            {"repo_path": str(repo), "mode": "fast", "name": PROJECT, "calyx": "shadow"},
        )
        second = structured(
            astrolabe,
            shadow_cache,
            "index_repository",
            {"repo_path": str(repo), "mode": "fast", "name": PROJECT, "calyx": "shadow"},
        )

        native_db = native_cache / f"{PROJECT}.db"
        shadow_db = shadow_cache / f"{PROJECT}.db"
        if not native_db.exists() or not shadow_db.exists():
            raise SystemExit(f"missing parity DBs: {native_db} {shadow_db}")

        injected_qn = inject_sqlite_fault(shadow_db) if args.inject_fault else None

        divergences = []
        compare_schema(native_db, shadow_db, divergences)
        node_count = compare_nodes(native_db, shadow_db, divergences)
        edge_count = compare_edges(native_db, shadow_db, divergences)
        compare_fts(native_db, shadow_db, divergences)
        overlap = compare_search(upstream, astrolabe, native_cache, shadow_cache, divergences)

        unwhitelisted = [div for div in divergences if not is_whitelisted(div, whitelist)]
        first_grounding = first["grounding_summary"]
        second_grounding = second["grounding_summary"]
        first_idem = first_grounding["idempotency"]
        second_idem = second_grounding["idempotency"]
        if first_idem["new_cx_ids"] <= 0:
            unwhitelisted.append({"kind": "idempotency", "field": "first.new_cx_ids"})
        if second_idem["new_cx_ids"] != 0:
            unwhitelisted.append({"kind": "idempotency", "field": "second.new_cx_ids"})
        if second_idem["graph_rows_written"] != 0:
            unwhitelisted.append({"kind": "idempotency", "field": "second.graph_rows_written"})
        if second_idem["edge_rows_written"] != 0:
            unwhitelisted.append({"kind": "idempotency", "field": "second.edge_rows_written"})
        if first_idem["cx_id_set_sha256"] != second_idem["cx_id_set_sha256"]:
            unwhitelisted.append({"kind": "idempotency", "field": "cx_id_set_sha256"})

        vault_dir = Path(second_grounding["vault_dir"])
        deep = deep_verify(astrolabe, vault_dir, PROJECT)
        if deep["ledger_chain_status"] != "intact":
            unwhitelisted.append({"kind": "deep_verify", "field": "ledger_chain_status"})
        if deep["sqlite_constellation_rows"] != second_grounding["constellation_inputs"]:
            unwhitelisted.append({"kind": "deep_verify", "field": "sqlite_constellation_rows"})
        if deep["sqlite_edge_rows"] <= 0 or deep["sqlite_edge_rows"] > second_grounding["sqlite_edges"]:
            unwhitelisted.append({"kind": "deep_verify", "field": "sqlite_edge_rows"})

        status = "verified" if not unwhitelisted else "failed"
        dashboard = {
            "schema": "astrolabe-shadow-parity-dashboard-v1",
            "status": status,
            "project": PROJECT,
            "nodes": node_count,
            "edges": edge_count,
            "search_overlap_at_10": overlap,
            "divergences": divergences,
            "unwhitelisted": unwhitelisted,
            "injected_fault_qn": injected_qn,
            "idempotency": {"first": first_idem, "second": second_idem},
            "deep_verify": deep,
            "upstream": str(upstream),
            "astrolabe": str(astrolabe),
        }
        write_dashboard(args.dashboard_out, dashboard)
        write_summary(args.summary_out, dashboard)

        if args.expect_failure:
            if not unwhitelisted:
                raise SystemExit("expected parity failure, but harness passed")
            print(json.dumps(dashboard, sort_keys=True))
            return
        if unwhitelisted:
            print(json.dumps(dashboard, indent=2, sort_keys=True), file=sys.stderr)
            raise SystemExit(1)
        print(json.dumps(dashboard, sort_keys=True))
    finally:
        if args.keep_temp:
            print(f"kept temp dir: {tmp}", file=sys.stderr)
        else:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
