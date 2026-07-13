#!/usr/bin/env python3
import argparse
import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROJECT = "astrolabe_cross_process"
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
    for candidate in [
        ROOT / "target" / "cbm-parity" / f"codebase-memory-mcp{exe}",
        ROOT / "target" / "cbm-parity" / "codebase-memory-mcp",
    ]:
        if candidate.exists():
            return candidate
    return None


def default_astrolabe():
    exe = ".exe" if os.name == "nt" else ""
    for candidate in [
        ROOT / "target" / "debug" / f"astrolabe{exe}",
        ROOT / "target" / "debug" / "astrolabe",
    ]:
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
    (src / "main.c").write_text(
        "static int helper(int x) { return x + 1; }\n"
        "static int other(int x) { return helper(x) + 1; }\n"
        "int main(void) { return other(0); }\n",
        encoding="utf-8",
    )


def cli_payload(binary, cache, tool, args):
    proc = run(
        [binary, "cli", "--json", tool, json.dumps(args, separators=(",", ":"))],
        env=base_env(cache),
        timeout=240,
    )
    payload = json.loads(proc.stdout)
    if payload.get("isError") is True:
        raise SystemExit(f"{tool} returned isError=true: {payload}")
    return payload


def spawn_cli(binary, cache, tool, args):
    return subprocess.Popen(
        [str(binary), "cli", "--json", tool, json.dumps(args, separators=(",", ":"))],
        env=base_env(cache),
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def wait_payload(proc, label):
    stdout, stderr = proc.communicate(timeout=240)
    if proc.returncode != 0:
        raise SystemExit(
            f"{label} failed rc={proc.returncode}\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
        )
    payload = json.loads(stdout)
    if payload.get("isError") is True:
        raise SystemExit(f"{label} returned isError=true: {payload}")
    return payload


def persist_shadow_dial(cache):
    connection = sqlite3.connect(cache / "_config.db")
    try:
        connection.execute("CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)")
        connection.execute(
            "INSERT OR REPLACE INTO config(key, value) VALUES (?, ?)",
            (f"astrolabe.calyx.{PROJECT}", "shadow"),
        )
        connection.commit()
    finally:
        connection.close()


def deep_verify(astrolabe, cache):
    vault_dir = cache / f"{PROJECT}.astrolabe-vault"
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
            f"astrolabe-shadow-v1:{PROJECT}",
        ],
        timeout=120,
    )
    return json.loads(proc.stdout)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream", type=Path)
    parser.add_argument("--astrolabe", type=Path)
    parser.add_argument("--keep-temp", action="store_true")
    args = parser.parse_args()

    upstream = args.upstream or default_upstream() or build_upstream()
    astrolabe = args.astrolabe or default_astrolabe() or build_astrolabe()
    if not upstream.exists():
        raise SystemExit(f"missing upstream binary: {upstream}")
    if not astrolabe.exists():
        raise SystemExit(f"missing astrolabe binary: {astrolabe}")

    tmp = Path(tempfile.mkdtemp(prefix="astrolabe-cross-process-"))
    try:
        repo = tmp / "repo"
        cache = tmp / "cache"
        repo.mkdir()
        cache.mkdir()
        write_fixture(repo)

        cli_payload(
            upstream,
            cache,
            "index_repository",
            {"repo_path": str(repo), "mode": "fast", "name": PROJECT},
        )
        persist_shadow_dial(cache)

        first = spawn_cli(astrolabe, cache, "index_status", {"project": PROJECT})
        second = spawn_cli(astrolabe, cache, "index_status", {"project": PROJECT})
        first_payload = wait_payload(first, "first index_status")
        second_payload = wait_payload(second, "second index_status")

        stable = cli_payload(astrolabe, cache, "index_status", {"project": PROJECT})
        search = cli_payload(
            astrolabe,
            cache,
            "search_graph",
            {"project": PROJECT, "label": "Function", "name_pattern": "helper", "limit": 5},
        )["structuredContent"]
        if search.get("total", 0) < 1:
            raise SystemExit(f"legacy search failed after concurrent vault open: {search}")

        deep = deep_verify(astrolabe, cache)
        if deep["ledger_chain_status"] != "intact":
            raise SystemExit(f"deep verify failed after concurrent load: {deep}")
        if deep["sqlite_constellation_rows"] < 1 or deep["ledger_payload_rows"] < 1:
            raise SystemExit(f"deep verify did not observe imported vault rows: {deep}")
        lowered = stable["structuredContent"].get("lowered_sqlite", {})
        if lowered.get("exists") is not True:
            raise SystemExit(f"lowered SQLite sidecar missing after concurrent load: {lowered}")

        summary = {
            "schema": "astrolabe-cross-process-vault-v1",
            "status": "verified",
            "project": PROJECT,
            "processes": 2,
            "semantics": "concurrent shadow recovery/import processes complete; Aster durable commits serialize through locks/durable.commit.lock and lowered SQLite sidecars through .astrolabe-lowered.lock",
            "first_status": first_payload["structuredContent"].get("vault", {}).get("verify_chain"),
            "second_status": second_payload["structuredContent"].get("vault", {}).get("verify_chain"),
            "stable_status": stable["structuredContent"].get("vault", {}).get("verify_chain"),
            "lowered_sqlite": lowered,
            "deep_verify": deep,
            "legacy_search_total": search.get("total"),
            "upstream": str(upstream),
            "astrolabe": str(astrolabe),
        }
        print(json.dumps(summary, sort_keys=True))
    finally:
        if args.keep_temp:
            print(f"kept temp dir: {tmp}")
        else:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
