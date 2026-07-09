#!/usr/bin/env python3
import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "ci" / "installer-roundtrip-agents.json"


def fail(message):
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_fixture():
    value = json.loads(FIXTURE.read_text(encoding="utf-8"))
    if value.get("schema") != "astrolabe.installer_roundtrip_agents.v1":
        fail("installer roundtrip fixture schema mismatch")
    agents = value.get("agents")
    if not isinstance(agents, list) or len(agents) != 13:
        fail("installer roundtrip fixture must declare exactly 13 agents")
    ids = [agent.get("id") for agent in agents]
    if len(set(ids)) != len(ids) or any(not item for item in ids):
        fail("installer roundtrip agent ids must be unique non-empty strings")
    return value


def resolve_binary(path):
    candidate = Path(path)
    if candidate.exists():
        return candidate
    fail(f"binary not found: {candidate}")


def run(argv, *, env, timeout=120):
    proc = subprocess.run(
        [str(arg) for arg in argv],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        timeout=timeout,
        check=False,
    )
    if proc.returncode != 0:
        fail(
            f"{Path(argv[0]).name} {' '.join(str(arg) for arg in argv[1:])} "
            f"failed rc={proc.returncode}\nstdout={proc.stdout[:500]}\nstderr={proc.stderr[:500]}"
        )
    return proc


def write_executable(path, text):
    path.write_text(text, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def setup_fake_home(home, fixture):
    fakebin = home / "fakebin"
    fakebin.mkdir(parents=True)
    for agent in fixture["agents"]:
        detect = agent.get("detect") or {}
        if "dir" in detect:
            (home / detect["dir"]).mkdir(parents=True, exist_ok=True)
        if "fake_cli" in detect:
            write_executable(fakebin / detect["fake_cli"], "#!/usr/bin/env sh\nexit 0\n")
    for command in fixture.get("shadowed_system_commands", []):
        name = command.get("name")
        if name:
            write_executable(fakebin / name, "#!/usr/bin/env sh\nexit 1\n")
    return fakebin


def snapshot_files(home):
    files = {}
    for path in sorted(home.rglob("*")):
        if path.is_file():
            files[str(path.relative_to(home))] = path.read_bytes()
    return files


def assert_no_residue(home, baseline):
    final = snapshot_files(home)
    if final != baseline:
        added = sorted(set(final) - set(baseline))
        removed = sorted(set(baseline) - set(final))
        changed = sorted(path for path in set(final) & set(baseline) if final[path] != baseline[path])
        fail(
            "installer roundtrip left filesystem residue: "
            + json.dumps(
                {"added": added, "removed": removed, "changed": changed},
                sort_keys=True,
            )
        )
    for rel, data in final.items():
        if b"codebase-memory-mcp" in data and not rel.startswith("fakebin/"):
            fail(f"installer residue marker remains in {rel}")


def assert_plan(binary, env, expected_agents):
    proc = run([binary, "install", "--plan"], env=env, timeout=60)
    try:
        plan = json.loads(proc.stdout)
    except json.JSONDecodeError as error:
        fail(f"{binary.name} install --plan did not return JSON: {error}")
    if plan.get("type") != "agent.install.plan.v1":
        fail(f"{binary.name} install plan type mismatch")
    if plan.get("writes_started") is not False:
        fail(f"{binary.name} install plan must be record-only")
    if plan.get("network_after_install") is not False:
        fail(f"{binary.name} install plan must not use network")
    agents = sorted(plan.get("agents_detected") or [])
    if agents != sorted(expected_agents):
        fail(f"{binary.name} detected agents mismatch: {agents}")
    if not plan.get("config_files_planned"):
        fail(f"{binary.name} install plan did not declare config files")
    if not plan.get("hooks_planned"):
        fail(f"{binary.name} install plan did not declare hooks")


def run_roundtrip(binary, fixture):
    home = Path(tempfile.mkdtemp(prefix=f"astrolabe-installer-{binary.name}-"))
    try:
        fakebin = setup_fake_home(home, fixture)
        env = dict(os.environ)
        env["HOME"] = str(home)
        env["XDG_CONFIG_HOME"] = str(home / ".config")
        env["CBM_CACHE_DIR"] = str(home / ".cache")
        env["PATH"] = str(fakebin) + os.pathsep + env.get("PATH", "")
        env["SHELL"] = "/bin/sh"
        expected_agents = [agent["id"] for agent in fixture["agents"]]

        baseline = snapshot_files(home)
        assert_plan(binary, env, expected_agents)
        if snapshot_files(home) != baseline:
            fail(f"{binary.name} install --plan mutated the filesystem")

        run([binary, "install", "-y", "--force"], env=env, timeout=120)
        installed = snapshot_files(home)
        installed_binary = ".local/bin/codebase-memory-mcp"
        if installed_binary not in installed:
            fail(f"{binary.name} install did not write {installed_binary}")

        run([binary, "update", "--dry-run", "--standard", "--force"], env=env, timeout=120)
        if snapshot_files(home) != installed:
            fail(f"{binary.name} update dry-run mutated the filesystem")

        run([binary, "uninstall", "-y"], env=env, timeout=120)
        assert_no_residue(home, baseline)
        return {
            "agents_detected": len(expected_agents),
            "files_after_install": len(installed),
            "baseline_files": len(baseline),
        }
    finally:
        shutil.rmtree(home, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--astrolabe", default=str(ROOT / "target" / "debug" / "astrolabe"))
    parser.add_argument(
        "--shim", default=str(ROOT / "target" / "debug" / "codebase-memory-mcp")
    )
    args = parser.parse_args()

    fixture = load_fixture()
    astrolabe = resolve_binary(args.astrolabe)
    shim = resolve_binary(args.shim)
    result = {
        "astrolabe": run_roundtrip(astrolabe, fixture),
        "codebase-memory-mcp": run_roundtrip(shim, fixture),
    }
    print(
        "installer roundtrip verified: "
        + json.dumps(
            {
                "schema": "astrolabe.installer_roundtrip_check.v1",
                "agent_targets": len(fixture["agents"]),
                "results": result,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )


if __name__ == "__main__":
    main()
