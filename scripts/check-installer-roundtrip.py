#!/usr/bin/env python3
import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
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
    if candidate.suffix == "" and candidate.with_name(candidate.name + ".exe").exists():
        return candidate.with_name(candidate.name + ".exe")
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


def fixture_detect_dir(detect, *, os_name=None, platform=None):
    if os_name is None:
        os_name = os.name
    if platform is None:
        platform = sys.platform
    if os_name == "nt":
        return detect.get("windows_dir", detect.get("dir"))
    if platform == "darwin":
        return detect.get("macos_dir", detect.get("dir"))
    return detect.get("dir")


def setup_fake_home(home, fixture):
    fakebin = home / "fakebin"
    fakebin.mkdir(parents=True)
    for agent in fixture["agents"]:
        detect = agent.get("detect") or {}
        detect_dir = fixture_detect_dir(detect)
        if detect_dir:
            (home / detect_dir).mkdir(parents=True, exist_ok=True)
        if "fake_cli" in detect:
            write_executable(fakebin / detect["fake_cli"], "#!/usr/bin/env sh\nexit 0\n")
    for command in fixture.get("shadowed_system_commands", []):
        name = command.get("name")
        if name:
            write_executable(fakebin / name, "#!/usr/bin/env sh\nexit 1\n")
    return fakebin


def fixture_environment(home, fakebin):
    temp = home / "tmp"
    temp.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env["HOME"] = str(home)
    env["USERPROFILE"] = str(home)
    env["XDG_CONFIG_HOME"] = str(home / ".config")
    env["APPDATA"] = str(home / "AppData" / "Roaming")
    env["LOCALAPPDATA"] = str(home / "AppData" / "Local")
    env["CBM_CACHE_DIR"] = str(home / ".cache")
    env["TEMP"] = str(temp)
    env["TMP"] = str(temp)
    env["PATH"] = str(fakebin) + os.pathsep + env.get("PATH", "")
    env["SHELL"] = "/bin/sh"
    return env


def installed_binary_relative_path(os_name=None):
    if os_name is None:
        os_name = os.name
    suffix = ".exe" if os_name == "nt" else ""
    return f".local/bin/codebase-memory-mcp{suffix}"


def snapshot_files(home):
    files = {}
    for path in sorted(home.rglob("*")):
        if path.is_file():
            files[path.relative_to(home).as_posix()] = path.read_bytes()
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


def spawn_server(binary, env, cache_dir):
    # A real MCP stdio server held open on stdin: the canonical long-lived
    # instance shape the install kill targets. Its store points OUTSIDE the
    # snapshot home so the residue check stays byte-exact.
    cache_dir.mkdir(parents=True, exist_ok=True)
    server_env = dict(env)
    server_env["CBM_CACHE_DIR"] = str(cache_dir)
    return subprocess.Popen(
        [str(binary)],
        env=server_env,
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def stop_server(proc):
    if proc.poll() is None:
        if proc.stdin:
            try:
                proc.stdin.close()
            except OSError:
                pass
        proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=10)


def wait_for_exit(proc, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return True
        time.sleep(0.1)
    return proc.poll() is not None


def run_roundtrip(binary, fixture, decoy_binary):
    target = ROOT / "target"
    target_existed = target.exists()
    target.mkdir(parents=True, exist_ok=True)
    home = Path(
        tempfile.mkdtemp(prefix=f"astrolabe-installer-{binary.name}-", dir=target)
    )
    scratch = Path(
        tempfile.mkdtemp(prefix=f"astrolabe-installer-decoy-{binary.name}-", dir=target)
    )
    decoy = None
    victim = None
    try:
        fakebin = setup_fake_home(home, fixture)
        env = fixture_environment(home, fakebin)
        expected_agents = [agent["id"] for agent in fixture["agents"]]

        baseline = snapshot_files(home)
        assert_plan(binary, env, expected_agents)
        if snapshot_files(home) != baseline:
            fail(f"{binary.name} install --plan mutated the filesystem")

        # #292 negative control: a live server that merely SHARES THE IMAGE
        # NAME (spawned from a different on-disk binary) must survive install.
        # The retired name-wide taskkill murdered exactly this process.
        decoy = spawn_server(decoy_binary, env, scratch / "decoy-cache")

        run([binary, "install", "-y", "--force"], env=env, timeout=120)
        if decoy.poll() is not None:
            fail(
                f"{binary.name} install killed an UNRELATED process that only shares "
                f"the image name (decoy {decoy_binary} exited rc={decoy.returncode}) — "
                "#292 kill-scope regression"
            )
        installed = snapshot_files(home)
        installed_binary = installed_binary_relative_path()
        if installed_binary not in installed:
            fail(f"{binary.name} install did not write {installed_binary}")

        run([binary, "update", "--dry-run", "--standard", "--force"], env=env, timeout=120)
        if snapshot_files(home) != installed:
            fail(f"{binary.name} update dry-run mutated the filesystem")

        # #292 positive control: a server running FROM the install target is
        # exactly what the kill exists for — reinstall must stop it (and the
        # decoy from a different binary must still survive).
        victim = spawn_server(home / installed_binary, env, scratch / "victim-cache")
        run([binary, "install", "-y", "--force"], env=env, timeout=120)
        if not wait_for_exit(victim, timeout=10):
            fail(
                f"{binary.name} reinstall did not stop the server running from the "
                f"install target (pid {victim.pid} still alive) — #292 kill scope "
                "lost its intended positive case"
            )
        if decoy.poll() is not None:
            fail(
                f"{binary.name} reinstall killed the unrelated same-name decoy "
                f"(rc={decoy.returncode}) — #292 kill-scope regression"
            )

        run([binary, "uninstall", "-y"], env=env, timeout=120)
        assert_no_residue(home, baseline)
        return {
            "agents_detected": len(expected_agents),
            "files_after_install": len(installed),
            "baseline_files": len(baseline),
            "kill_scope": {
                "same_name_foreign_binary": "survived",
                "install_target_instance": "stopped",
            },
        }
    finally:
        if victim is not None:
            stop_server(victim)
        if decoy is not None:
            stop_server(decoy)
        shutil.rmtree(home, ignore_errors=True)
        shutil.rmtree(scratch, ignore_errors=True)
        if not target_existed:
            try:
                target.rmdir()
            except OSError:
                pass


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
    # The shim IS named codebase-memory-mcp[.exe] — the exact image name the
    # #292 name-wide kill matched — making it the canonical same-name decoy.
    result = {
        "astrolabe": run_roundtrip(astrolabe, fixture, decoy_binary=shim),
        "codebase-memory-mcp": run_roundtrip(shim, fixture, decoy_binary=shim),
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
