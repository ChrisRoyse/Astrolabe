#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from release_artifact import write_artifact  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
PROJECT = "astrolabe_shadow_parity"
WHITELIST = ROOT / "ci" / "shadow-parity-whitelist.json"
SHADOW_VAULT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
DEFAULT_ARTIFACT_DIR = ROOT / "target" / "astrolabe-release-predicate"
PARITY_DASHBOARD_ARTIFACT = "parity-dashboard.json"
PARITY_HISTORY_ARTIFACT = "parity-history.json"
PARITY_TREND_ARTIFACT = "parity-trend.json"
DASHBOARD_SCHEMA_GOLDEN = ROOT / "ci" / "shadow-parity-dashboard-schema.json"
DASHBOARD_SCHEMA = "astrolabe-shadow-parity-dashboard-v1"
HISTORY_SCHEMA = "astrolabe-shadow-parity-history-v1"
TREND_SCHEMA = "astrolabe-shadow-parity-trend-v1"
# How many most-recent dashboard runs the trend history retains. A knob, not a
# magic constant: raise it for longer trend windows (#19 dashboard history).
DEFAULT_HISTORY_RETAIN = 50


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
    # #292: "error", never "none" — a fatal startup/index failure must print its
    # {code, message, remediation} instead of dying as a bare silent rc=1.
    env["CBM_LOG_LEVEL"] = "error"
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


# A whitelist entry suppresses a divergence when every one of its matcher keys
# equals the corresponding field on that divergence. These are the only keys a
# divergence carries (see the compare_* helpers), so an entry that names none of
# them has no discriminating power: `all(...)` over an empty match set is True,
# which would silently suppress *every* divergence. Entries are therefore
# validated fail-closed at load time — see validate_whitelist_entries.
MATCHER_KEYS = ("kind", "field", "qn", "native", "shadow")
# Non-matching metadata a maintainer may attach to document an entry. Never used
# to match a divergence, so it cannot widen suppression.
METADATA_KEYS = ("justification",)
ALLOWED_ENTRY_KEYS = frozenset(MATCHER_KEYS) | frozenset(METADATA_KEYS)


def _whitelist_error(code, message, remediation):
    return SystemExit(
        json.dumps(
            {"code": code, "message": message, "remediation": remediation},
            sort_keys=True,
        )
    )


def validate_whitelist_entries(entries, source):
    if not isinstance(entries, list):
        raise _whitelist_error(
            "shadow_parity_whitelist_entries_not_list",
            f"shadow-parity whitelist 'entries' in {source} must be a JSON array",
            "set 'entries' to a JSON array of matcher objects; see "
            "ci/shadow-parity-whitelist.json",
        )
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise _whitelist_error(
                "shadow_parity_whitelist_entry_not_object",
                f"shadow-parity whitelist entry #{index} in {source} is not a JSON object",
                "replace it with an object naming at least one matcher key "
                f"({', '.join(MATCHER_KEYS)})",
            )
        unknown = sorted(set(entry) - ALLOWED_ENTRY_KEYS)
        if unknown:
            raise _whitelist_error(
                "shadow_parity_whitelist_entry_unknown_keys",
                f"shadow-parity whitelist entry #{index} in {source} has "
                f"unrecognized key(s): {', '.join(unknown)}",
                "remove the unrecognized key(s); allowed keys are "
                f"{', '.join(sorted(ALLOWED_ENTRY_KEYS))}",
            )
        matchers = [key for key in entry if key in MATCHER_KEYS]
        if not matchers:
            raise _whitelist_error(
                "shadow_parity_whitelist_entry_no_matcher",
                f"shadow-parity whitelist entry #{index} in {source} specifies no "
                "concrete matcher; an empty or metadata-only entry would suppress "
                "every divergence",
                "add at least one discriminating matcher key "
                f"({', '.join(MATCHER_KEYS)}) so the entry targets a specific "
                "divergence class",
            )
    # Two entries with an identical matcher set suppress exactly the same
    # divergence class: the duplicate can only be a copy-paste slip that bloats
    # the load-bearing whitelist and masks its true size. Reject fail-closed so
    # the whitelist stays a minimal, auditable set of deliberate suppressions.
    seen: dict[str, int] = {}
    for index, entry in enumerate(entries):
        matcher_map = {key: value for key, value in entry.items() if key in MATCHER_KEYS}
        signature = json.dumps(matcher_map, sort_keys=True)
        if signature in seen:
            raise _whitelist_error(
                "shadow_parity_whitelist_entry_duplicate",
                f"shadow-parity whitelist entry #{index} in {source} duplicates the "
                f"matchers of entry #{seen[signature]} ({signature})",
                "remove the duplicate entry; each suppression must appear once so the "
                "whitelist's true size stays auditable",
            )
        seen[signature] = index
    return entries


def load_whitelist(path):
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema") != "astrolabe-shadow-parity-whitelist-v1":
        raise SystemExit(f"unexpected whitelist schema in {path}")
    return validate_whitelist_entries(payload.get("entries", []), str(path))


def is_whitelisted(divergence, entries):
    for entry in entries:
        matchers = {key: value for key, value in entry.items() if key in MATCHER_KEYS}
        # Defense in depth: validate_whitelist_entries already guarantees at
        # least one matcher, but never let a matcher-less entry blanket-match.
        if matchers and all(
            divergence.get(key) == value for key, value in matchers.items()
        ):
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


def sha256_file(path):
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def astro_meta(path):
    rows = sqlite_rows(
        path,
        "SELECT schema, vault_fingerprint, ledger_head_hash, panel_version, lowered_at "
        "FROM astro_meta",
    )
    if len(rows) != 1:
        raise SystemExit(f"expected exactly one astro_meta row in {path}, got {len(rows)}")
    row = rows[0]
    return {
        "schema": row[0],
        "vault_fingerprint": row[1],
        "ledger_head_hash": row[2],
        "panel_version": row[3],
        "lowered_at": row[4],
    }


def compare_lowered_artifact(native_db, lowered_db, divergences):
    native_schema = schema_rows(native_db)
    lowered_schema = [
        row for row in schema_rows(lowered_db) if row[1] != "astro_meta"
    ]
    if native_schema != lowered_schema:
        divergences.append({"kind": "lowered_schema", "field": "sqlite_master"})

    local = []
    compare_nodes(native_db, lowered_db, local)
    compare_edges(native_db, lowered_db, local)
    compare_fts(native_db, lowered_db, local)
    for divergence in local:
        prefixed = dict(divergence)
        prefixed["kind"] = f"lowered_{divergence['kind']}"
        divergences.append(prefixed)


def validate_lowered_summary(name, summary, expected_nodes, expected_edges, divergences):
    if not isinstance(summary, dict):
        divergences.append({"kind": "lowered_sqlite", "field": f"{name}.missing"})
        return None
    path = Path(summary.get("path", ""))
    if not path.exists():
        divergences.append({"kind": "lowered_sqlite", "field": f"{name}.path_exists"})
        return path
    if summary.get("exists") is not True:
        divergences.append({"kind": "lowered_sqlite", "field": f"{name}.exists"})
    if summary.get("nodes") != expected_nodes:
        divergences.append({"kind": "lowered_sqlite", "field": f"{name}.nodes"})
    if summary.get("edges") != expected_edges:
        divergences.append({"kind": "lowered_sqlite", "field": f"{name}.edges"})
    artifact = summary.get("artifact_sha256")
    if artifact != sha256_file(path):
        divergences.append(
            {"kind": "lowered_sqlite", "field": f"{name}.artifact_sha256"}
        )
    meta = astro_meta(path)
    if meta["schema"] != "astrolabe-astro-meta-v1":
        divergences.append({"kind": "lowered_sqlite", "field": f"{name}.astro_meta.schema"})
    if summary.get("vault_fingerprint_sha256") != meta["vault_fingerprint"]:
        divergences.append(
            {"kind": "lowered_sqlite", "field": f"{name}.astro_meta.vault_fingerprint"}
        )
    if not meta["ledger_head_hash"]:
        divergences.append(
            {"kind": "lowered_sqlite", "field": f"{name}.astro_meta.ledger_head_hash"}
        )
    return path


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


def inject_vault_fault(vault_dir, tmp):
    """Perturb one node-map row inside the REAL durable shadow vault (#19).

    Runs the perturb_vault_and_lower example, which rewrites the persisted row
    through the normal ledger-paired batch path and re-lowers the perturbed
    vault. Returns (fault_payload, perturbed_lowered_db_path).
    """
    output = tmp / "vault-fault-lowered.db"
    proc = run(
        [
            "cargo",
            "run",
            "-q",
            "-p",
            "astrolabe-lower",
            "--example",
            "perturb_vault_and_lower",
            "--",
            vault_dir,
            SHADOW_VAULT_ID,
            f"astrolabe-shadow-v1:{PROJECT}",
            PROJECT,
            output,
        ],
        timeout=900,
    )
    payload = json.loads(proc.stdout)
    if payload.get("schema") != "astrolabe-vault-fault-example-v1":
        raise SystemExit(f"vault fault example schema drift: {payload}")
    if not output.exists():
        raise SystemExit(f"vault fault example did not produce {output}")
    return payload, output


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


def utc_now_iso():
    return datetime.now(tz=timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def compute_status(unwhitelisted):
    """The single source of truth for pass/fail: any unwhitelisted divergence bites.

    Used by both the live harness and the empty-whitelist control demonstration so
    the control proves the *real* gate verdict, not a re-implementation of it.
    """
    return "verified" if not unwhitelisted else "failed"


# JSON type tokens the dashboard golden may require -> acceptance predicates.
# bool is excluded from the numeric/int classes on purpose (it is a Python int
# subclass but never a legitimate count or overlap value).
def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


_TYPE_PREDICATES = {
    "str": lambda v: isinstance(v, str),
    "int": _is_int,
    "number": _is_number,
    "list": lambda v: isinstance(v, list),
    "dict": lambda v: isinstance(v, dict),
    "str_or_null": lambda v: v is None or isinstance(v, str),
    "dict_or_null": lambda v: v is None or isinstance(v, dict),
}


def load_dashboard_schema(path=DASHBOARD_SCHEMA_GOLDEN):
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if payload.get("schema") != "astrolabe-shadow-parity-dashboard-schema-v1":
        raise _whitelist_error(
            "shadow_parity_dashboard_schema_unrecognized",
            f"dashboard schema golden {path} has an unexpected schema tag",
            "restore ci/shadow-parity-dashboard-schema.json to schema "
            "'astrolabe-shadow-parity-dashboard-schema-v1'",
        )
    return payload


def validate_dashboard_schema(dashboard, golden=DASHBOARD_SCHEMA_GOLDEN):
    """Fail closed unless the produced dashboard matches the checked-in golden.

    Guards against silent drift in the dashboard contract: a renamed/removed key,
    a type change, or an out-of-vocabulary status all fail with a structured
    {code, message, remediation} error instead of shipping a malformed artifact.
    """
    golden_payload = golden if isinstance(golden, dict) else load_dashboard_schema(golden)
    required = golden_payload["required_keys"]
    allowed_status = golden_payload["allowed_status"]

    if dashboard.get("schema") != golden_payload["dashboard_schema"]:
        raise _whitelist_error(
            "shadow_parity_dashboard_schema_tag_drift",
            f"dashboard schema tag is {dashboard.get('schema')!r}, golden requires "
            f"{golden_payload['dashboard_schema']!r}",
            "align the dashboard 'schema' field with ci/shadow-parity-dashboard-schema.json",
        )

    missing = sorted(set(required) - set(dashboard))
    if missing:
        raise _whitelist_error(
            "shadow_parity_dashboard_missing_keys",
            f"dashboard is missing required key(s): {', '.join(missing)}",
            "add the missing key(s) or update ci/shadow-parity-dashboard-schema.json "
            "if the contract legitimately changed",
        )
    extra = sorted(set(dashboard) - set(required))
    if extra:
        raise _whitelist_error(
            "shadow_parity_dashboard_unexpected_keys",
            f"dashboard has unexpected key(s): {', '.join(extra)}",
            "remove the key(s) or declare them in ci/shadow-parity-dashboard-schema.json",
        )
    for key, type_token in required.items():
        predicate = _TYPE_PREDICATES.get(type_token)
        if predicate is None:
            raise _whitelist_error(
                "shadow_parity_dashboard_schema_bad_type",
                f"dashboard golden declares unknown type {type_token!r} for key {key!r}",
                f"use one of {', '.join(sorted(_TYPE_PREDICATES))} in the golden",
            )
        if not predicate(dashboard[key]):
            raise _whitelist_error(
                "shadow_parity_dashboard_type_mismatch",
                f"dashboard key {key!r} must be {type_token} but is "
                f"{type(dashboard[key]).__name__}",
                "fix the value type or update the golden's declared type",
            )
    if dashboard["status"] not in allowed_status:
        raise _whitelist_error(
            "shadow_parity_dashboard_status_out_of_vocab",
            f"dashboard status {dashboard['status']!r} is not one of {allowed_status}",
            "the harness must set status via compute_status(); update the golden's "
            "allowed_status only for a deliberate contract change",
        )
    return dashboard


def history_record(dashboard, recorded_at, commit):
    """Compact, deterministic trend row distilled from one dashboard run."""
    return {
        "recorded_at": recorded_at,
        "commit": commit,
        "status": dashboard["status"],
        "nodes": dashboard["nodes"],
        "edges": dashboard["edges"],
        "search_overlap_at_10": dashboard["search_overlap_at_10"],
        "divergence_count": len(dashboard["divergences"]),
        "unwhitelisted_count": len(dashboard["unwhitelisted"]),
    }


def append_history(history_path, record, retain=DEFAULT_HISTORY_RETAIN):
    """Append one run to the retained JSON history, keeping the most-recent `retain`.

    Reads back and re-validates the persisted history before appending, so a
    corrupt or foreign-schema history file fails closed instead of being silently
    overwritten. Returns the retained record list actually persisted.
    """
    history_path = Path(history_path)
    records: list = []
    if history_path.exists():
        try:
            payload = json.loads(history_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise _whitelist_error(
                "shadow_parity_history_corrupt",
                f"parity history {history_path} is not valid JSON: {exc}",
                "delete the corrupt history file so a fresh trend series can start, or "
                "restore it from version control",
            )
        if not isinstance(payload, dict) or payload.get("schema") != HISTORY_SCHEMA:
            raise _whitelist_error(
                "shadow_parity_history_schema_drift",
                f"parity history {history_path} is not a {HISTORY_SCHEMA} object",
                "delete the file or restore a valid history object",
            )
        records = payload.get("records", [])
        if not isinstance(records, list):
            raise _whitelist_error(
                "shadow_parity_history_records_not_list",
                f"parity history {history_path} 'records' must be a JSON array",
                "delete the file so a fresh trend series can start",
            )
    records = list(records) + [record]
    if retain > 0:
        records = records[-retain:]
    payload = {"schema": HISTORY_SCHEMA, "retain": retain, "records": records}
    history_path.parent.mkdir(parents=True, exist_ok=True)
    history_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return records


def compute_trend(records):
    """Summarize a retained history series into a trend artifact payload."""
    if not records:
        return {"schema": TREND_SCHEMA, "count": 0}
    latest = records[-1]
    previous = records[-2] if len(records) > 1 else None
    streak = 0
    for row in reversed(records):
        if row.get("status") == "verified":
            streak += 1
        else:
            break

    def delta(key):
        if previous is None:
            return None
        return latest.get(key) - previous.get(key)

    return {
        "schema": TREND_SCHEMA,
        "count": len(records),
        "latest_status": latest.get("status"),
        "consecutive_verified": streak,
        "first_recorded_at": records[0].get("recorded_at"),
        "latest_recorded_at": latest.get("recorded_at"),
        "latest_unwhitelisted_count": latest.get("unwhitelisted_count"),
        "unwhitelisted_delta": delta("unwhitelisted_count"),
        "divergence_delta": delta("divergence_count"),
        "nodes_delta": delta("nodes"),
        "edges_delta": delta("edges"),
    }


def write_trend(trend_path, trend):
    trend_path = Path(trend_path)
    trend_path.parent.mkdir(parents=True, exist_ok=True)
    trend_path.write_text(json.dumps(trend, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def record_history_and_trend(history_dir, dashboard, recorded_at, retain=DEFAULT_HISTORY_RETAIN):
    """Append this run to the retained history and (re)write the trend artifact.

    Returns (history_path, trend_path, retained_records, trend). The commit binding
    reuses release_artifact.git_commit so a row names the tree that produced it.
    """
    from release_artifact import git_commit

    history_dir = Path(history_dir)
    commit, _dirty = git_commit(ROOT)
    record = history_record(dashboard, recorded_at, commit)
    history_path = history_dir / PARITY_HISTORY_ARTIFACT
    records = append_history(history_path, record, retain)
    trend = compute_trend(records)
    trend_path = history_dir / PARITY_TREND_ARTIFACT
    write_trend(trend_path, trend)
    return history_path, trend_path, records, trend


def write_dashboard(path, dashboard):
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dashboard, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_release_artifact(artifact_dir, dashboard):
    unwhitelisted_count = len(dashboard["unwhitelisted"])
    passed = dashboard["status"] == "verified" and unwhitelisted_count == 0
    artifact = {
        "schema": "astrolabe.parity_dashboard.v1",
        "status": "pass" if passed else "fail",
        "source": "scripts/check-shadow-parity.py",
        "dashboard_schema": dashboard["schema"],
        "dashboard_status": dashboard["status"],
        "reason": None
        if passed
        else f"shadow parity has {unwhitelisted_count} unwhitelisted divergence(s)",
        "project": dashboard["project"],
        "nodes": dashboard["nodes"],
        "edges": dashboard["edges"],
        "search_overlap_at_10": dashboard["search_overlap_at_10"],
        "divergence_count": len(dashboard["divergences"]),
        "unwhitelisted_count": len(dashboard["unwhitelisted"]),
        "second_run_new_cx_ids": dashboard["idempotency"]["second"]["new_cx_ids"],
        "second_run_graph_rows_written": dashboard["idempotency"]["second"]["graph_rows_written"],
        "second_run_edge_rows_written": dashboard["idempotency"]["second"]["edge_rows_written"],
        "deep_verify": dashboard["deep_verify"],
    }
    # #88: every release-predicate artifact is bound to its subject commit and
    # generation instant, so a stale or foreign-commit artifact cannot satisfy a
    # conjunct.
    write_artifact(artifact_dir, PARITY_DASHBOARD_ARTIFACT, artifact, ROOT)


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


def run_selftest():
    """Prove the whitelist validator is fail-closed without touching binaries.

    (a) a {} (or metadata-only) entry raises a structured validation error naming
        its index, (b) legitimate entries still load and match, (c) suppression
        counts (divergences / suppressed / unwhitelisted) stay reported.
    """
    failures = []

    def check(name, condition, detail=""):
        status = "ok" if condition else "FAIL"
        suffix = f" — {detail}" if detail else ""
        print(f"[selftest] {name}: {status}{suffix}")
        if not condition:
            failures.append(name)

    tmp = Path(tempfile.mkdtemp(prefix="astrolabe-shadow-parity-selftest-"))
    try:
        # (a) empty entry {} at index 1 must raise a structured validation error.
        empty_path = tmp / "empty-entry.json"
        empty_path.write_text(
            json.dumps(
                {
                    "schema": "astrolabe-shadow-parity-whitelist-v1",
                    "entries": [{"kind": "fts", "field": "f23"}, {}],
                }
            ),
            encoding="utf-8",
        )
        try:
            load_whitelist(empty_path)
            check("empty_entry_rejected", False, "load_whitelist did not raise")
        except SystemExit as exc:
            payload = json.loads(str(exc.code))
            check(
                "empty_entry_rejected",
                payload.get("code") == "shadow_parity_whitelist_entry_no_matcher"
                and "#1" in payload.get("message", "")
                and bool(payload.get("remediation")),
                json.dumps(payload, sort_keys=True),
            )

        # metadata-only entry (justification, no matcher) is likewise rejected.
        meta_path = tmp / "metadata-only.json"
        meta_path.write_text(
            json.dumps(
                {
                    "schema": "astrolabe-shadow-parity-whitelist-v1",
                    "entries": [{"justification": "known-good drift"}],
                }
            ),
            encoding="utf-8",
        )
        try:
            load_whitelist(meta_path)
            check("metadata_only_rejected", False, "load_whitelist did not raise")
        except SystemExit as exc:
            payload = json.loads(str(exc.code))
            check(
                "metadata_only_rejected",
                payload.get("code") == "shadow_parity_whitelist_entry_no_matcher"
                and "#0" in payload.get("message", ""),
                json.dumps(payload, sort_keys=True),
            )

        # unknown key is rejected so a typo cannot silently broaden a matcher.
        typo_path = tmp / "unknown-key.json"
        typo_path.write_text(
            json.dumps(
                {
                    "schema": "astrolabe-shadow-parity-whitelist-v1",
                    "entries": [{"kynd": "fts"}],
                }
            ),
            encoding="utf-8",
        )
        try:
            load_whitelist(typo_path)
            check("unknown_key_rejected", False, "load_whitelist did not raise")
        except SystemExit as exc:
            payload = json.loads(str(exc.code))
            check(
                "unknown_key_rejected",
                payload.get("code") == "shadow_parity_whitelist_entry_unknown_keys"
                and "#0" in payload.get("message", ""),
                json.dumps(payload, sort_keys=True),
            )

        # (b) legitimate entries still load and match (subset match + justification).
        legit_path = tmp / "legit.json"
        legit_path.write_text(
            json.dumps(
                {
                    "schema": "astrolabe-shadow-parity-whitelist-v1",
                    "entries": [
                        {"kind": "fts", "field": "f23", "justification": "known FTS drift"},
                        {"kind": "node_field", "field": "properties"},
                    ],
                }
            ),
            encoding="utf-8",
        )
        entries = load_whitelist(legit_path)
        check("legit_loads", len(entries) == 2, f"{len(entries)} entries")

        divergences = [
            {"kind": "fts", "field": "f23"},  # -> entry 0
            {
                "kind": "node_field",
                "qn": "src::f01",
                "field": "properties",
                "native": "a",
                "shadow": "b",
            },  # -> entry 1 (subset match on kind+field)
            {"kind": "schema", "field": "sqlite_master"},  # not whitelisted
            {
                "kind": "node_field",
                "qn": "src::f02",
                "field": "name",
                "native": "x",
                "shadow": "y",
            },  # not whitelisted (field != properties)
        ]
        unwhitelisted = [d for d in divergences if not is_whitelisted(d, entries)]
        check("legit_exact_match", is_whitelisted(divergences[0], entries) is True)
        check("legit_subset_match", is_whitelisted(divergences[1], entries) is True)
        check("non_match_class_kept", is_whitelisted(divergences[2], entries) is False)
        check("non_match_field_kept", is_whitelisted(divergences[3], entries) is False)

        # (c) suppression counts remain reported.
        suppressed = len(divergences) - len(unwhitelisted)
        check("divergence_count", len(divergences) == 4, str(len(divergences)))
        check("suppressed_count", suppressed == 2, str(suppressed))
        check("unwhitelisted_count", len(unwhitelisted) == 2, str(len(unwhitelisted)))
        print(
            "[selftest] counts "
            + json.dumps(
                {
                    "divergences": len(divergences),
                    "suppressed": suppressed,
                    "unwhitelisted": len(unwhitelisted),
                },
                sort_keys=True,
            )
        )

        # The shipped whitelist (entries: []) must still load cleanly.
        shipped = load_whitelist(WHITELIST)
        check("shipped_whitelist_loads", shipped == [], f"{len(shipped)} entries")

        # Duplicate matcher entries are rejected fail-closed so the whitelist's
        # true size stays auditable (#19 edge triad: duplicate entries).
        dup_path = tmp / "duplicate.json"
        dup_path.write_text(
            json.dumps(
                {
                    "schema": "astrolabe-shadow-parity-whitelist-v1",
                    "entries": [
                        {"kind": "fts", "field": "f23", "justification": "first"},
                        {"kind": "fts", "field": "f23", "justification": "copy-paste"},
                    ],
                }
            ),
            encoding="utf-8",
        )
        try:
            load_whitelist(dup_path)
            check("duplicate_entry_rejected", False, "load_whitelist did not raise")
        except SystemExit as exc:
            payload = json.loads(str(exc.code))
            check(
                "duplicate_entry_rejected",
                payload.get("code") == "shadow_parity_whitelist_entry_duplicate"
                and "#1" in payload.get("message", "")
                and bool(payload.get("remediation")),
                json.dumps(payload, sort_keys=True),
            )

        # ---- Empty-whitelist-must-bite control demonstration (#19 box 2) ----
        # A known-benign divergence class we would legitimately whitelist. This is
        # the control proof that the whitelist is *load-bearing*: with an entry that
        # names it the gate PASSES; with the shipped empty whitelist the very same
        # divergence is unsuppressed and the gate FAILS. Uses the real is_whitelisted
        # + compute_status the live harness uses, not a re-implementation.
        benign = {"kind": "fts", "field": "f23"}
        suppressing = [{"kind": "fts", "field": "f23", "justification": "known benign drift"}]
        empty = []
        with_wl = [benign] if not is_whitelisted(benign, suppressing) else []
        without_wl = [benign] if not is_whitelisted(benign, empty) else []
        check(
            "control_whitelist_suppresses",
            compute_status(with_wl) == "verified" and with_wl == [],
            f"status={compute_status(with_wl)}",
        )
        check(
            "control_empty_whitelist_bites",
            compute_status(without_wl) == "failed" and without_wl == [benign],
            f"status={compute_status(without_wl)} unwhitelisted={without_wl}",
        )
        # The whitelist is load-bearing iff the two verdicts differ on identical input.
        check(
            "control_whitelist_is_load_bearing",
            compute_status(with_wl) != compute_status(without_wl),
        )
        print(
            "[selftest] control "
            + json.dumps(
                {
                    "divergence": benign,
                    "with_whitelist_status": compute_status(with_wl),
                    "empty_whitelist_status": compute_status(without_wl),
                },
                sort_keys=True,
            )
        )

        # ---- Dashboard schema golden (#19 box 3) ----
        golden = load_dashboard_schema()
        check(
            "dashboard_golden_tag",
            golden["dashboard_schema"] == DASHBOARD_SCHEMA,
            golden["dashboard_schema"],
        )
        synthetic = {
            "schema": DASHBOARD_SCHEMA,
            "status": "verified",
            "project": PROJECT,
            "nodes": 30,
            "edges": 53,
            "search_overlap_at_10": 1.0,
            "divergences": [],
            "unwhitelisted": [],
            "injected_fault_qn": None,
            "injected_vault_fault": None,
            "idempotency": {"first": {}, "second": {}},
            "lowered_sqlite": {"first": {}, "second": {}, "status": {}},
            "deep_verify": {},
            "upstream": "upstream",
            "astrolabe": "astrolabe",
        }
        try:
            validate_dashboard_schema(synthetic, golden)
            check("dashboard_golden_accepts_valid", True)
        except SystemExit as exc:
            check("dashboard_golden_accepts_valid", False, str(exc.code))
        # A missing key must fail closed with a structured error.
        drift = dict(synthetic)
        drift.pop("deep_verify")
        try:
            validate_dashboard_schema(drift, golden)
            check("dashboard_golden_rejects_drift", False, "accepted a missing key")
        except SystemExit as exc:
            payload = json.loads(str(exc.code))
            check(
                "dashboard_golden_rejects_drift",
                payload.get("code") == "shadow_parity_dashboard_missing_keys"
                and "deep_verify" in payload.get("message", ""),
                json.dumps(payload, sort_keys=True),
            )
        # A type mismatch must also fail closed.
        bad_type = dict(synthetic)
        bad_type["nodes"] = "30"
        try:
            validate_dashboard_schema(bad_type, golden)
            check("dashboard_golden_rejects_bad_type", False, "accepted a string count")
        except SystemExit as exc:
            payload = json.loads(str(exc.code))
            check(
                "dashboard_golden_rejects_bad_type",
                payload.get("code") == "shadow_parity_dashboard_type_mismatch",
                json.dumps(payload, sort_keys=True),
            )

        # ---- History / trend retention FSV (#19 box 3) ----
        # Append several runs to a real on-disk history, read the persisted bytes
        # back, and prove retention truncates oldest-first and the trend reflects
        # the series. This is FSV: the assertions read the file, not return values.
        hist_dir = tmp / "history"
        hist_path = hist_dir / PARITY_HISTORY_ARTIFACT
        retain = 3
        for i in range(5):
            run_status = "failed" if i == 2 else "verified"
            rec = history_record(
                {
                    "status": run_status,
                    "nodes": 30,
                    "edges": 53 + i,
                    "search_overlap_at_10": 1.0,
                    "divergences": [],
                    "unwhitelisted": ([{"kind": "fts"}] if run_status == "failed" else []),
                },
                recorded_at=f"2026-07-12T00:0{i}:00Z",
                commit=f"deadbeef{i}",
            )
            append_history(hist_path, rec, retain=retain)
        persisted = json.loads(hist_path.read_text(encoding="utf-8"))
        check("history_schema", persisted.get("schema") == HISTORY_SCHEMA)
        check(
            "history_retains_last_n",
            len(persisted["records"]) == retain,
            f"{len(persisted['records'])} records",
        )
        check(
            "history_drops_oldest",
            [r["edges"] for r in persisted["records"]] == [55, 56, 57],
            str([r["edges"] for r in persisted["records"]]),
        )
        trend = compute_trend(persisted["records"])
        check("trend_schema", trend.get("schema") == TREND_SCHEMA)
        check("trend_count", trend.get("count") == retain, str(trend.get("count")))
        # records[-1] is verified (i=4); i=3 verified too -> streak counts trailing verified.
        check(
            "trend_consecutive_verified",
            trend.get("consecutive_verified") == 2,
            str(trend.get("consecutive_verified")),
        )
        check("trend_edges_delta", trend.get("edges_delta") == 1, str(trend.get("edges_delta")))
        # Corrupt history must fail closed, never silently overwrite a series.
        hist_path.write_text("{ not json", encoding="utf-8")
        try:
            append_history(hist_path, rec, retain=retain)
            check("history_corrupt_rejected", False, "append_history did not raise")
        except SystemExit as exc:
            payload = json.loads(str(exc.code))
            check(
                "history_corrupt_rejected",
                payload.get("code") == "shadow_parity_history_corrupt"
                and bool(payload.get("remediation")),
                json.dumps(payload, sort_keys=True),
            )
        # Foreign-schema history is likewise rejected.
        hist_path.write_text(json.dumps({"schema": "other", "records": []}), encoding="utf-8")
        try:
            append_history(hist_path, rec, retain=retain)
            check("history_schema_drift_rejected", False, "append_history did not raise")
        except SystemExit as exc:
            payload = json.loads(str(exc.code))
            check(
                "history_schema_drift_rejected",
                payload.get("code") == "shadow_parity_history_schema_drift",
                json.dumps(payload, sort_keys=True),
            )
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if failures:
        raise SystemExit(f"shadow-parity whitelist self-test failed: {failures}")
    print("[selftest] all checks passed")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--selftest",
        action="store_true",
        help="run the whitelist-validation self-test (no binaries) and exit",
    )
    parser.add_argument("--upstream", type=Path)
    parser.add_argument("--astrolabe", type=Path)
    parser.add_argument("--whitelist", type=Path, default=WHITELIST)
    parser.add_argument("--dashboard-out", type=Path)
    parser.add_argument("--summary-out", type=Path)
    parser.add_argument("--write-release-artifact", action="store_true")
    parser.add_argument("--artifact-dir", type=Path, default=DEFAULT_ARTIFACT_DIR)
    parser.add_argument(
        "--history-dir",
        type=Path,
        help="directory the retained parity history/trend artifacts are written to "
        "(defaults to --artifact-dir when --write-release-artifact is set)",
    )
    parser.add_argument(
        "--history-retain",
        type=int,
        default=DEFAULT_HISTORY_RETAIN,
        help="how many most-recent runs the trend history keeps",
    )
    parser.add_argument(
        "--recorded-at",
        help="override the history record timestamp (ISO-8601; for deterministic tests)",
    )
    parser.add_argument("--inject-fault", action="store_true")
    parser.add_argument(
        "--inject-vault-fault",
        action="store_true",
        help="perturb one node property in the REAL durable shadow vault and "
        "require the parity comparison to fail naming the exact QN and field",
    )
    parser.add_argument("--expect-failure", action="store_true")
    parser.add_argument("--keep-temp", action="store_true")
    args = parser.parse_args()

    if args.selftest:
        run_selftest()
        return

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
        status_content = structured(
            astrolabe,
            shadow_cache,
            "index_status",
            {"project": PROJECT},
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

        first_grounding = first["grounding_summary"]
        second_grounding = second["grounding_summary"]
        first_idem = first_grounding["idempotency"]
        second_idem = second_grounding["idempotency"]
        first_lowered = first_grounding.get("lowered_sqlite")
        second_lowered = second_grounding.get("lowered_sqlite")
        status_lowered = status_content.get("lowered_sqlite")
        if not isinstance(first_lowered, dict):
            divergences.append({"kind": "lowered_sqlite", "field": "first.missing"})
        second_lowered_path = validate_lowered_summary(
            "second", second_lowered, node_count, edge_count, divergences
        )
        validate_lowered_summary(
            "status", status_lowered, node_count, edge_count, divergences
        )
        if second_lowered and status_lowered:
            if second_lowered.get("artifact_sha256") != status_lowered.get("artifact_sha256"):
                divergences.append(
                    {"kind": "lowered_sqlite", "field": "status_artifact_sha256"}
                )
        if second_lowered_path is not None:
            compare_lowered_artifact(native_db, second_lowered_path, divergences)

        unwhitelisted = [div for div in divergences if not is_whitelisted(div, whitelist)]
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

        vault_fault = None
        if args.inject_vault_fault:
            # Perturb the REAL durable shadow vault only after the clean state
            # fully verified above, then require the lowered-vs-native node
            # comparison to fail naming the exact QN and field.
            fault_payload, fault_lowered = inject_vault_fault(vault_dir, tmp)
            fault_divergences = []
            compare_nodes(native_db, fault_lowered, fault_divergences)
            named = [
                div
                for div in fault_divergences
                if div.get("kind") == "node_field"
                and div.get("qn") == fault_payload["qualified_name"]
                and div.get("field") == fault_payload["field"]
            ]
            if not named:
                raise SystemExit(
                    "vault-fault injection was NOT detected: perturbed "
                    f"qn={fault_payload['qualified_name']} "
                    f"field={fault_payload['field']} but node comparison "
                    f"reported only: {json.dumps(fault_divergences, sort_keys=True)}"
                )
            vault_fault = {
                "qn": fault_payload["qualified_name"],
                "field": fault_payload["field"],
                "detected": True,
                "divergences": named,
            }
            unwhitelisted.append(
                {
                    "kind": "vault_fault",
                    "qn": fault_payload["qualified_name"],
                    "field": fault_payload["field"],
                }
            )

        status = compute_status(unwhitelisted)
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
            "injected_vault_fault": vault_fault,
            "idempotency": {"first": first_idem, "second": second_idem},
            "lowered_sqlite": {
                "first": first_lowered,
                "second": second_lowered,
                "status": status_lowered,
            },
            "deep_verify": deep,
            "upstream": str(upstream),
            "astrolabe": str(astrolabe),
        }
        # Fail closed on any drift from the checked-in dashboard contract before
        # the artifact escapes this process (#19 dashboard schema golden).
        validate_dashboard_schema(dashboard)
        write_dashboard(args.dashboard_out, dashboard)
        write_summary(args.summary_out, dashboard)

        # Append this run to the retained trend history (#19). Both verified and
        # failed runs are recorded so the trend series is honest. History persists
        # only where its directory outlives target/ cleanup; see the coverage note
        # on #238 for the cross-run cadence gap.
        history_dir = args.history_dir
        if history_dir is None and args.write_release_artifact:
            history_dir = args.artifact_dir
        if history_dir is not None:
            recorded_at = args.recorded_at or utc_now_iso()
            history_path, trend_path, retained, trend = record_history_and_trend(
                history_dir, dashboard, recorded_at, args.history_retain
            )
            print(
                "parity history: "
                + json.dumps(
                    {
                        "history": str(history_path),
                        "trend": str(trend_path),
                        "retained": len(retained),
                        "consecutive_verified": trend.get("consecutive_verified"),
                    },
                    sort_keys=True,
                ),
                file=sys.stderr,
            )

        if args.expect_failure:
            if not unwhitelisted:
                raise SystemExit("expected parity failure, but harness passed")
            print(json.dumps(dashboard, sort_keys=True))
            return
        if unwhitelisted:
            if args.write_release_artifact:
                write_release_artifact(args.artifact_dir, dashboard)
            print(json.dumps(dashboard, indent=2, sort_keys=True), file=sys.stderr)
            raise SystemExit(1)
        if args.write_release_artifact:
            write_release_artifact(args.artifact_dir, dashboard)
        print(json.dumps(dashboard, sort_keys=True))
    finally:
        if args.keep_temp:
            print(f"kept temp dir: {tmp}", file=sys.stderr)
        else:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
