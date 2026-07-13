#!/usr/bin/env python3
import argparse
import ipaddress
import json
import math
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
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
    # #280: build via the shared cache helper. Its cache is keyed on the
    # committed source inputs (not the BUILD_DIR), so when check-mcp-parity.sh already
    # built+cached the CBM prod binary this run, this call is a byte-identical
    # cache restore instead of a second ~5-minute make. Fail-closed: an ambiguous
    # key runs the same full make. (default_upstream() still short-circuits to
    # check-mcp-parity.sh's target/cbm-parity output when present, so in the
    # default aggregate order this path is only reached standalone.)
    build_dir = ROOT / "target" / "cbm-lowered-parity"
    exe = ".exe" if os.name == "nt" else ""
    run(
        ["bash", str(ROOT / "scripts" / "cbm-prod-build.sh"), str(build_dir)],
        timeout=900,
    )
    built = build_dir / f"codebase-memory-mcp{exe}"
    if not built.exists():
        built = build_dir / "codebase-memory-mcp"
    if not built.exists():
        raise SystemExit(f"upstream build did not produce {built}")
    return built


def default_ui_binary():
    exe = ".exe" if os.name == "nt" else ""
    candidates = [
        ROOT / "target" / "cbm-ui-smoke" / f"codebase-memory-mcp{exe}",
        ROOT / "target" / "cbm-ui-smoke" / "codebase-memory-mcp",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def assert_vendor_clean(label):
    # FSV / #229 contract: a UI build must leave the owned CBM source subtree
    # byte-clean. `git status --porcelain` reports both modified tracked files
    # (e.g. graph-ui/tsconfig.tsbuildinfo) and untracked, non-ignored paths (e.g.
    # a stray src/ui/embedded_assets.c) — any such build-time write into the owned
    # source tree is a hygiene violation (#286: build artifacts belong under BUILD_DIR).
    proc = subprocess.run(
        ["git", "-C", str(ROOT), "status", "--porcelain", "--", "vendor/codebase-memory-mcp"],
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        raise SystemExit(
            f"git status failed while checking vendor cleanliness after {label}:\n{proc.stderr}"
        )
    dirty = proc.stdout.strip()
    if dirty:
        raise SystemExit(
            f"vendor/ subtree was modified during {label} — owned source must stay byte-clean. "
            "Every generated build artifact must stay under BUILD_DIR, never in vendor/.\n"
            f"--- git status --porcelain vendor/codebase-memory-mcp ---\n{dirty}"
        )


def build_ui_binary():
    # Build cbm-with-ui through the PATCHED Makefile (patches/cbm/Makefile.cbm),
    # exactly as build_upstream() builds `cbm`. Only the patched Makefile defines
    # ASTRO_PROD_DEFS (-DASTRO_UI_WERROR -DASTRO_WORKER_DIAG); the plain vendored
    # Makefile.cbm does not, so building through it would compile the owned sources
    # with the #229 -Werror root-cause guards (#ifdef ASTRO_UI_WERROR) disabled and
    # re-trip the GCC 14 -Werror diagnostics those guards exist to fix (#286 absorbed
    # the former apply_ui_werror_patch.py overlays into the owned sources as plain
    # ASTRO_UI_WERROR-guarded edits — see patches/cbm/README.md).
    build_dir = ROOT / "target" / "cbm-ui-smoke"
    exe = ".exe" if os.name == "nt" else ""
    # #274: build cbm-with-ui through the Astrolabe-owned patched Makefile — the
    # same drop-in build_upstream() uses for `cbm` — so both binaries resolve the
    # compiler family (and thus the GCC-only -Wno-* suppression set) through the
    # single deterministic, fail-closed probe. Using the vendored Makefile here
    # instead re-opened the exact cbm-vs-cbm-with-ui divergence #229 observed:
    # two Makefiles, two independent (formerly silent-flipping) IS_GCC probes.
    run(
        [
            "make",
            "-C",
            ROOT / "vendor" / "codebase-memory-mcp",
            "-f",
            ROOT / "patches" / "cbm" / "Makefile.cbm",
            f"BUILD_DIR={build_dir}",
            "cbm-with-ui",
        ],
        timeout=900,
    )
    # The UI build runs the frontend/embed toolchain (npm/vite/embed); assert it
    # left the pinned vendor subtree byte-clean before returning the binary.
    assert_vendor_clean("cbm-with-ui build")
    built = build_dir / f"codebase-memory-mcp{exe}"
    if not built.exists():
        built = build_dir / "codebase-memory-mcp"
    if not built.exists():
        raise SystemExit(f"UI build did not produce {built}")
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


def lower_cbm_sqlite(source, project, output, determinism_output=None):
    argv = [
        "cargo",
        "run",
        "-q",
        "-p",
        "astrolabe-lower",
        "--example",
        "lower_cbm_sqlite",
        "--",
        source,
        project,
        output,
    ]
    if determinism_output is not None:
        argv.append(determinism_output)
    proc = run(argv, timeout=900)
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"lower_cbm_sqlite example did not return JSON: {exc}\n{proc.stdout}")
    if payload.get("schema") != "astrolabe-lower-example-v1":
        raise SystemExit(f"lower_cbm_sqlite example schema drift: {payload}")
    return payload


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


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def http_get_text(url, timeout=2):
    req = urllib.request.Request(url, headers={"Host": "127.0.0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        if response.status != 200:
            raise RuntimeError(f"{url} returned HTTP {response.status}")
        return response.read().decode("utf-8", errors="replace")


def http_get_json(url, timeout=2):
    return json.loads(http_get_text(url, timeout=timeout))


def wait_for_http(proc, url, parser):
    deadline = time.monotonic() + 20
    last_error = None
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise SystemExit(f"UI server exited early with code {proc.returncode}")
        try:
            return parser(url)
        except Exception as exc:
            last_error = exc
            time.sleep(0.2)
    raise SystemExit(f"UI server did not serve {url}: {last_error}")


def linux_tcp_listeners(port):
    listeners = []
    for table, family in [(Path("/proc/net/tcp"), "ipv4"), (Path("/proc/net/tcp6"), "ipv6")]:
        if not table.exists():
            continue
        for line in table.read_text(encoding="utf-8").splitlines()[1:]:
            parts = line.split()
            if len(parts) < 4 or parts[3] != "0A":
                continue
            local = parts[1]
            if ":" not in local:
                continue
            address_hex, port_hex = local.rsplit(":", 1)
            try:
                local_port = int(port_hex, 16)
            except ValueError:
                continue
            if local_port != port:
                continue
            ip = decode_proc_net_address(address_hex, family)
            listeners.append(
                {
                    "family": family,
                    "address": str(ip),
                    "port": port,
                    "state": "LISTEN",
                    "loopback": ip.is_loopback,
                }
            )
    return listeners


def decode_proc_net_address(address_hex, family):
    raw = bytes.fromhex(address_hex)
    if family == "ipv4":
        return ipaddress.IPv4Address(raw[::-1])
    if family == "ipv6":
        # /proc/net/tcp6 stores each 32-bit word little-endian.
        packed = b"".join(raw[index : index + 4][::-1] for index in range(0, 16, 4))
        return ipaddress.IPv6Address(packed)
    raise ValueError(f"unsupported address family: {family}")


def local_non_loopback_addresses():
    addresses = set()
    try:
        infos = socket.getaddrinfo(socket.gethostname(), None)
    except OSError:
        infos = []
    for family, _, _, _, sockaddr in infos:
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        raw = sockaddr[0]
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            continue
        if not ip.is_loopback and not ip.is_unspecified:
            addresses.add(raw)
    return sorted(addresses)


def fallback_loopback_probe(port):
    exposed = []
    for address in local_non_loopback_addresses():
        try:
            with socket.create_connection((address, port), timeout=0.5):
                exposed.append(address)
        except OSError:
            pass
    if exposed:
        raise SystemExit(
            f"UI server accepted non-loopback connections on port {port}: {exposed}"
        )
    return [
        {
            "family": "probe",
            "address": "127.0.0.1",
            "port": port,
            "state": "reachable",
            "loopback": True,
        }
    ]


def assert_loopback_listener(proc, port):
    if sys.platform.startswith("linux"):
        deadline = time.monotonic() + 5
        listeners = []
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise SystemExit(f"UI server exited early with code {proc.returncode}")
            listeners = linux_tcp_listeners(port)
            if listeners:
                break
            time.sleep(0.1)
        if not listeners:
            raise SystemExit(f"UI server listener for port {port} was not visible in /proc/net/tcp")
    else:
        listeners = fallback_loopback_probe(port)

    non_loopback = [entry for entry in listeners if not entry["loopback"]]
    if non_loopback:
        raise SystemExit(
            f"UI server must bind loopback only; observed listeners: {json.dumps(listeners, sort_keys=True)}"
        )
    return listeners


def run_ui_smoke(binary, cache):
    port = free_port()
    env = base_env(cache)
    proc = subprocess.Popen(
        [str(binary), "--ui=true", f"--port={port}"],
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    try:
        root_url = f"http://127.0.0.1:{port}/"
        index_html = wait_for_http(proc, root_url, http_get_text)
        listeners = assert_loopback_listener(proc, port)
        if "<html" not in index_html.lower() or "assets/" not in index_html:
            raise SystemExit("UI root did not return embedded frontend HTML")

        project = urllib.parse.quote(PROJECT)
        layout_url = f"http://127.0.0.1:{port}/api/layout?project={project}&max_nodes=50"
        layout = wait_for_http(proc, layout_url, http_get_json)
        nodes = layout.get("nodes")
        edges = layout.get("edges")
        if not isinstance(nodes, list) or len(nodes) < 20:
            raise SystemExit(f"UI layout returned too few nodes: {layout}")
        if not isinstance(edges, list) or not edges:
            raise SystemExit(f"UI layout returned no edges: {layout}")

        names = {node.get("name") for node in nodes if isinstance(node, dict)}
        if "f23" not in names or "main" not in names:
            raise SystemExit(f"UI layout missed expected functions: {sorted(names)}")
        for node in nodes:
            if not isinstance(node, dict):
                raise SystemExit(f"UI layout node is not an object: {node}")
            for axis in ["x", "y", "z"]:
                value = node.get(axis)
                if not isinstance(value, (int, float)) or not math.isfinite(value):
                    raise SystemExit(f"UI layout node has invalid {axis}: {node}")

        return {
            "binary": str(binary),
            "port": port,
            "binding": "loopback-only",
            "listeners": listeners,
            "nodes": len(nodes),
            "edges": len(edges),
            "total_nodes": layout.get("total_nodes"),
            "status": "verified",
        }
    finally:
        if proc.poll() is None:
            if proc.stdin:
                proc.stdin.close()
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream", type=Path)
    parser.add_argument("--ui-smoke", action="store_true")
    parser.add_argument("--ui-binary", type=Path)
    parser.add_argument("--build-ui", action="store_true")
    parser.add_argument("--keep-temp", action="store_true")
    args = parser.parse_args()

    upstream = args.upstream or default_upstream() or build_upstream()
    if not upstream.exists():
        raise SystemExit(f"missing upstream binary: {upstream}")
    ui_binary = None
    if args.ui_smoke:
        ui_binary = args.ui_binary or default_ui_binary()
        if args.build_ui or ui_binary is None:
            ui_binary = build_ui_binary()
        if not ui_binary.exists():
            raise SystemExit(f"missing UI binary: {ui_binary}")

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
        determinism_db = lowered_cache / f"{PROJECT}.determinism.db"
        if not native_db.exists():
            raise SystemExit(f"native CBM DB missing: {native_db}")

        lower_report = lower_cbm_sqlite(native_db, PROJECT, lowered_db, determinism_db)
        if not lowered_db.exists():
            raise SystemExit(f"lowered DB missing: {lowered_db}")
        if not determinism_db.exists():
            raise SystemExit(f"determinism DB missing: {determinism_db}")
        determinism = lower_report.get("determinism", {})
        if determinism.get("byte_identical") is not True:
            raise SystemExit(f"lowered artifact bytes were not deterministic: {determinism}")
        if determinism.get("artifact_sha256_matches") is not True:
            raise SystemExit(f"lowered artifact hashes were not deterministic: {determinism}")
        roundtrip = lower_report.get("roundtrip", {})
        if roundtrip.get("matches_original_cx_ids") is not True:
            raise SystemExit(f"lowered artifact roundtrip changed CxIds: {roundtrip}")

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

        ui = run_ui_smoke(ui_binary, lowered_cache) if ui_binary else None
        summary = {
            "schema": "astrolabe-lowered-parity-v1",
            "status": "verified",
            "project": PROJECT,
            "nodes": len(native_nodes),
            "edges": len(sqlite_rows(native_db, edge_sql)),
            "determinism": {
                "artifact_sha256": lower_report["lower"]["artifact_sha256"],
                "byte_identical": True,
            },
            "roundtrip": {
                "cx_id_count": len(roundtrip.get("cx_ids", [])),
                "matches_original_cx_ids": True,
            },
            "upstream": str(upstream),
        }
        if ui is not None:
            summary["ui"] = ui
        print(
            json.dumps(summary, sort_keys=True)
        )
    finally:
        if args.keep_temp:
            print(f"kept temp dir: {tmp}", file=sys.stderr)
        else:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
