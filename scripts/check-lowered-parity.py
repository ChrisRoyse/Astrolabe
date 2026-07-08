#!/usr/bin/env python3
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROJECT = "astrolabe_lower_parity"


def run(argv, *, env=None, cwd=ROOT, timeout=180):
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
    build_dir = ROOT / "target" / "cbm-lowered-parity"
    exe = ".exe" if os.name == "nt" else ""
    run(
        [
            "make",
            "-C",
            ROOT / "vendor" / "codebase-memory-mcp",
            f"BUILD_DIR={build_dir}",
            "codebase-memory-mcp",
        ],
        timeout=240,
    )
    built = build_dir / f"codebase-memory-mcp{exe}"
    if not built.exists():
        built = build_dir / "codebase-memory-mcp"
    if not built.exists():
        raise SystemExit(f"upstream build did not produce {built}")
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
    return payload["structuredContent"]


def sqlite_rows(path, sql):
    import sqlite3

    connection = sqlite3.connect(path)
    try:
        return list(connection.execute(sql))
    finally:
        connection.close()


def schema_rows(path):
    return sqlite_rows(
        path,
        "SELECT type, name, tbl_name, trim(sql) FROM sqlite_master "
        "WHERE name NOT LIKE 'sqlite_%' AND name != 'astro_meta' "
        "ORDER BY type, name",
    )


def assert_equal(label, left, right):
    if left != right:
        print(f"ERROR: {label} mismatch", file=sys.stderr)
        print("--- native ---", file=sys.stderr)
        print(left, file=sys.stderr)
        print("--- lowered ---", file=sys.stderr)
        print(right, file=sys.stderr)
        raise SystemExit(1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream", type=Path)
    parser.add_argument("--keep-temp", action="store_true")
    args = parser.parse_args()

    upstream = args.upstream or default_upstream() or build_upstream()
    if not upstream.exists():
        raise SystemExit(f"missing upstream binary: {upstream}")

    tmp = Path(tempfile.mkdtemp(prefix="astrolabe-lowered-parity-"))
    try:
        repo = tmp / "repo"
        native_cache = tmp / "native-cache"
        lowered_cache = tmp / "lowered-cache"
        native_cache.mkdir()
        lowered_cache.mkdir()
        write_fixture(repo)

        cli_tool(
            upstream,
            native_cache,
            "index_repository",
            {"repo_path": str(repo), "mode": "fast", "name": PROJECT},
        )
        native_db = native_cache / f"{PROJECT}.db"
        lowered_db = lowered_cache / f"{PROJECT}.db"
        if not native_db.exists():
            raise SystemExit(f"native CBM DB missing: {native_db}")

        run(
            [
                "cargo",
                "run",
                "-q",
                "-p",
                "astrolabe-lower",
                "--example",
                "lower_cbm_sqlite",
                "--",
                native_db,
                PROJECT,
                lowered_db,
            ],
            timeout=240,
        )
        if not lowered_db.exists():
            raise SystemExit(f"lowered DB missing: {lowered_db}")

        assert_equal("schema", schema_rows(native_db), schema_rows(lowered_db))

        node_sql = (
            "SELECT label, name, qualified_name, file_path, start_line, end_line, properties "
            "FROM nodes ORDER BY qualified_name"
        )
        native_nodes = sqlite_rows(native_db, node_sql)
        lowered_nodes = sqlite_rows(lowered_db, node_sql)
        assert_equal("node rows by qualified_name", native_nodes, lowered_nodes)
        if len(native_nodes) < 20:
            raise SystemExit(f"fixture produced only {len(native_nodes)} nodes; expected >=20")

        edge_sql = (
            "SELECT e.type, s.qualified_name, t.qualified_name, e.properties, e.local_name_gen "
            "FROM edges e JOIN nodes s ON s.id=e.source_id JOIN nodes t ON t.id=e.target_id "
            "ORDER BY e.type, s.qualified_name, t.qualified_name, e.properties, e.local_name_gen"
        )
        assert_equal("edge multiset", sqlite_rows(native_db, edge_sql), sqlite_rows(lowered_db, edge_sql))

        fts_sql = (
            "SELECT n.qualified_name FROM nodes_fts f JOIN nodes n ON n.id=f.rowid "
            "WHERE nodes_fts MATCH 'f23' ORDER BY n.qualified_name"
        )
        assert_equal("FTS f23 query", sqlite_rows(native_db, fts_sql), sqlite_rows(lowered_db, fts_sql))

        search = cli_tool(
            upstream,
            lowered_cache,
            "search_graph",
            {"project": PROJECT, "label": "Function", "name_pattern": "f23", "limit": 5},
        )
        if search.get("total", 0) < 1 or not search.get("results"):
            raise SystemExit(f"search_graph found no f23 function in lowered DB: {search}")

        schema = cli_tool(upstream, lowered_cache, "get_graph_schema", {"project": PROJECT})
        labels = {row["label"]: row["count"] for row in schema.get("node_labels", [])}
        if labels.get("Function", 0) < 24:
            raise SystemExit(f"get_graph_schema Function count too low: {schema}")

        cypher = cli_tool(
            upstream,
            lowered_cache,
            "query_graph",
            {
                "project": PROJECT,
                "query": "MATCH (n:Function) RETURN n.name LIMIT 30",
                "max_rows": 30,
            },
        )
        returned = {row[0] for row in cypher.get("rows", [])}
        if "f23" not in returned or "main" not in returned:
            raise SystemExit(f"query_graph/Cypher missed expected functions: {cypher}")

        architecture = cli_tool(
            upstream,
            lowered_cache,
            "get_architecture",
            {"project": PROJECT, "aspects": ["structure"]},
        )
        if architecture.get("total_nodes", 0) != len(native_nodes):
            raise SystemExit(f"get_architecture total_nodes mismatch: {architecture}")

        print(
            json.dumps(
                {
                    "schema": "astrolabe-lowered-parity-v1",
                    "status": "verified",
                    "project": PROJECT,
                    "nodes": len(native_nodes),
                    "edges": len(sqlite_rows(native_db, edge_sql)),
                    "upstream": str(upstream),
                },
                sort_keys=True,
            )
        )
    finally:
        if args.keep_temp:
            print(f"kept temp dir: {tmp}", file=sys.stderr)
        else:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
