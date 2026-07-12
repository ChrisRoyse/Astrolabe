#!/usr/bin/env python3
"""Fail-closed test-sandbox escape gate (#237).

ASTROLABE keeps re-discovering one defect: a test or gate run escapes its
sandbox and persists state in the operator's environment.

  * the CBM C suite registered 25 fixture projects in the operator's global
    project store (~/.cache/codebase-memory-mcp)          -- #194 / #232
  * astrolabe-anchors left vault dirs in %TEMP% on the panic path   -- #236
  * astrolabe-ingest left vault dirs in %TEMP%                      -- #133

Each was fixed by hand. Discipline does not hold: #236 is #133 in a different
crate, two milestones later. Containment was asserted by convention and verified
by a human noticing litter afterwards, so the *class* stayed open even when
every instance was closed.

This gate closes the class with the two layers the issue demands, in order.

LAYER 1 -- CONTAIN BY CONSTRUCTION (`run`)
  Execute a suite with its state roots redirected into a per-run sandbox:
  HOME/USERPROFILE, TMP/TEMP/TMPDIR, XDG_*_HOME, APPDATA/LOCALAPPDATA. Escape
  then requires an *absolute* path outside the sandbox -- a much smaller,
  reviewable surface. This mirrors Bazel's test contract, where a test may write
  only inside the dirs the harness declares for it and paths under /home "may
  not be available" (https://bazel.build/reference/test-encyclopedia).

  CARGO_HOME / RUSTUP_HOME / SCCACHE_DIR are *declared writable* toolchain roots:
  they are resolved from the real home and passed through explicitly, because
  they are the toolchain's own store, not operator state under test. Declaring
  them is the Bazel/Nx model -- a hermeticity gate names what may be written and
  fails on everything else.

  CBM_CACHE_DIR is deliberately NOT set. The vendored CBM C tests derive their
  store from $HOME, and pinning CBM_CACHE_DIR globally regresses ~808 of them;
  redirecting HOME keeps the C half and the Rust half in sync. `--set-cbm-cache-dir`
  exists for callers that have proven they need it.

LAYER 2 -- DETECT ESCAPE AND FAIL THE BUILD (`snapshot` / `verify`)
  Read the protected roots' bytes before the suite and again after. Any added,
  removed, or modified entry is a HARD FAILURE naming the offending paths. This
  is the FSV doctrine turned on the gate itself, and it is the only un-forgeable
  proof: a regex or lint gate cannot see a subprocess, a shell test, or a code
  path written next month -- reading the directory back sees all of them. Nx's
  sandboxing makes the same distinction and only its *strict* mode is worth
  anything: a violation that merely warns is a violation that ships. This gate
  has no warning mode.

COST (the caution in #237)
  Hashing the operator's whole cache tree on every run would be both slow and
  wrong (it churns constantly from unrelated processes). The registry therefore
  declares two kinds of root:

    exclusive  -- project-owned outright (the CBM store, ~/.astrolabe). Small,
                  bounded, fully hashed with sha256. Third parties never write
                  here, so ANY delta is ours and fails the build.
    signature  -- shared with the operator and the OS (%TEMP%, $HOME). Scanned
                  to depth 1 by stat only (size + mtime_ns, no hashing), and the
                  assertion is scoped to project-signature names -- exactly the
                  escape shape of #133/#236. Foreign entries are counted and
                  reported, never used to pass or fail.

  Both kinds are bounded by max_entries_per_root / max_hash_bytes_per_root, and
  exceeding a bound FAILS CLOSED (ASTRO_NO_ESCAPE_ROOT_TOO_LARGE) rather than
  silently truncating the manifest. Every scan is strictly read-only: scandir,
  stat, and open('rb'). The gate never creates, moves, or deletes anything in a
  protected root.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ROOTS = ROOT / "scripts" / "no-escape-roots.json"
MANIFEST_SCHEMA = "astrolabe.no_escape_manifest.v1"
ROOTS_SCHEMA = "astrolabe.no_escape_roots.v1"
READ_BLOCK_BYTES = 1 << 20

ESCAPE_CODE = "ASTRO_TEST_SANDBOX_ESCAPE"


def fail(code: str, message: str, remediation: str, details: dict[str, Any] | None = None) -> None:
    payload: dict[str, Any] = {"code": code, "message": message, "remediation": remediation}
    if details:
        payload["details"] = details
    print(f"ERROR: {json.dumps(payload, sort_keys=True)}", file=sys.stderr)
    raise SystemExit(1)


# --------------------------------------------------------------------------
# Environment-independent resolution of the operator's real state roots.
#
# The whole point of layer 1 is that the child's HOME/TEMP are redirected. If
# the gate resolved its protected roots from those same variables it would
# police the sandbox and declare victory. So the real roots come from the OS.
# --------------------------------------------------------------------------


def real_home() -> Path:
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        # FOLDERID_Profile -- the user profile dir, straight from the shell API,
        # unaffected by USERPROFILE/HOME in the environment.
        class GUID(ctypes.Structure):
            _fields_ = [
                ("Data1", wintypes.DWORD),
                ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD),
                ("Data4", ctypes.c_byte * 8),
            ]

        folderid_profile = GUID(
            0x5E6C858F,
            0x0E22,
            0x4760,
            (ctypes.c_byte * 8)(*[0x9A, 0xFE, 0xEA, 0x33, 0x17, 0xB6, 0x71, 0x73]),
        )
        out = ctypes.c_wchar_p()
        result = ctypes.windll.shell32.SHGetKnownFolderPath(
            ctypes.byref(folderid_profile), 0, None, ctypes.byref(out)
        )
        if result == 0 and out.value:
            path = Path(out.value)
            ctypes.windll.ole32.CoTaskMemFree(out)
            return path
        fail(
            "ASTRO_NO_ESCAPE_NO_REAL_HOME",
            "SHGetKnownFolderPath(FOLDERID_Profile) failed, so the operator's real home "
            "cannot be resolved independently of the environment",
            "run the gate as a normal interactive user; the gate refuses to fall back to "
            "$USERPROFILE, because a redirected variable would make it police the sandbox "
            "instead of the operator's state",
            {"hresult": result},
        )
    import pwd

    return Path(pwd.getpwuid(os.getuid()).pw_dir)


def real_roots_vars() -> dict[str, str]:
    home = real_home()
    values = {"REAL_HOME": str(home), "REAL_CACHE": str(home / ".cache")}
    if os.name == "nt":
        local = home / "AppData" / "Local"
        values["REAL_LOCALAPPDATA"] = str(local)
        values["REAL_TEMP"] = str(local / "Temp")
    else:
        values["REAL_TEMP"] = "/tmp"
    return values


def expand(template: str, variables: dict[str, str]) -> str | None:
    """Expand ${VAR} from the real-root table then the environment. None if unresolved."""
    out = template
    while "${" in out:
        start = out.index("${")
        end = out.index("}", start)
        name = out[start + 2 : end]
        value = variables.get(name) or os.environ.get(name)
        if not value:
            return None
        out = out[:start] + value + out[end + 1 :]
    return out


# --------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------


def digest(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            block = handle.read(READ_BLOCK_BYTES)
            if not block:
                break
            sha.update(block)
    return sha.hexdigest()


def scan_exclusive(root: Path, limits: dict[str, int], name: str) -> dict[str, list[Any]]:
    entries: dict[str, list[Any]] = {}
    total_bytes = 0
    for path in sorted(root.rglob("*")):
        try:
            if path.is_symlink() or not path.is_file():
                continue
            stat = path.stat()
        except OSError:
            # A file that vanished mid-scan is itself churn in a root nothing
            # else should touch; record it as unreadable rather than skipping.
            entries[path.relative_to(root).as_posix()] = ["unreadable", -1, -1]
            continue
        total_bytes += stat.st_size
        if len(entries) >= limits["max_entries_per_root"]:
            fail(
                "ASTRO_NO_ESCAPE_ROOT_TOO_LARGE",
                f"protected root {name} ({root}) holds more than "
                f"{limits['max_entries_per_root']} entries; the manifest would be truncated",
                "an exclusive project root must stay small. Either the run leaked massively "
                "into it, or the root is misdeclared in scripts/no-escape-roots.json and is "
                "not actually project-exclusive.",
                {"root": str(root), "limit": limits["max_entries_per_root"]},
            )
        if total_bytes > limits["max_hash_bytes_per_root"]:
            fail(
                "ASTRO_NO_ESCAPE_ROOT_TOO_LARGE",
                f"protected root {name} ({root}) holds more than "
                f"{limits['max_hash_bytes_per_root']} bytes to hash",
                "an exclusive project root must stay small. Raise the registry limit only "
                "after confirming the growth is legitimate operator state, not a leak.",
                {"root": str(root), "bytes": total_bytes},
            )
        entries[path.relative_to(root).as_posix()] = [
            digest(path),
            stat.st_size,
            stat.st_mtime_ns,
        ]
    return entries


def scan_signature(
    root: Path, globs: list[str], max_depth: int, limits: dict[str, int], name: str
) -> tuple[dict[str, list[Any]], int]:
    """Stat-only, depth-bounded scan. Returns (signature_entries, foreign_count)."""
    entries: dict[str, list[Any]] = {}
    foreign = 0
    stack: list[tuple[Path, int]] = [(root, 0)]
    seen = 0
    while stack:
        current, depth = stack.pop()
        try:
            children = list(os.scandir(current))
        except OSError:
            continue
        for child in children:
            seen += 1
            if seen > limits["max_entries_per_root"]:
                fail(
                    "ASTRO_NO_ESCAPE_ROOT_TOO_LARGE",
                    f"protected root {name} ({root}) exposed more than "
                    f"{limits['max_entries_per_root']} entries at depth <= {max_depth}",
                    "lower max_depth for this root or raise max_entries_per_root in "
                    "scripts/no-escape-roots.json after confirming the churn is foreign",
                    {"root": str(root)},
                )
            rel = Path(child.path).relative_to(root).as_posix()
            top = rel.split("/", 1)[0]
            if not any(fnmatch.fnmatch(top.lower(), pattern.lower()) for pattern in globs):
                foreign += 1
                continue
            try:
                stat = child.stat(follow_symlinks=False)
                entries[rel] = [
                    "dir" if child.is_dir(follow_symlinks=False) else "file",
                    stat.st_size,
                    stat.st_mtime_ns,
                ]
            except OSError:
                entries[rel] = ["unreadable", -1, -1]
            if child.is_dir(follow_symlinks=False) and depth + 1 < max_depth:
                stack.append((Path(child.path), depth + 1))
    return entries, foreign


def load_roots(path: Path) -> dict[str, Any]:
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(
            "ASTRO_NO_ESCAPE_BAD_REGISTRY",
            f"cannot read the protected-root registry at {path}",
            "restore scripts/no-escape-roots.json",
            {"error": str(exc)},
        )
    if config.get("schema") != ROOTS_SCHEMA:
        fail(
            "ASTRO_NO_ESCAPE_BAD_REGISTRY",
            f"protected-root registry has wrong schema: {config.get('schema')!r}",
            f"set schema to {ROOTS_SCHEMA}",
        )
    if not config.get("roots"):
        fail(
            "ASTRO_NO_ESCAPE_BAD_REGISTRY",
            "protected-root registry declares no roots, so the gate would police nothing",
            "declare the operator state roots in scripts/no-escape-roots.json",
        )
    return config


def snapshot(config: dict[str, Any]) -> dict[str, Any]:
    variables = real_roots_vars()
    globs = config["signature_globs"]
    limits = config["limits"]
    roots: list[dict[str, Any]] = []
    for declared in config["roots"]:
        resolved = expand(declared["path"], variables)
        if resolved is None:
            print(
                f"INFO[ASTRO_NO_ESCAPE_ROOT_UNRESOLVED]: {declared['name']} "
                f"({declared['path']}) -- no value for one of its variables on this host; "
                "the root is not policed on this run"
            )
            roots.append(
                {
                    "name": declared["name"],
                    "template": declared["path"],
                    "path": None,
                    "mode": declared["mode"],
                    "resolved": False,
                    "exists": False,
                    "entries": {},
                    "foreign_count": 0,
                }
            )
            continue
        path = Path(resolved)
        exists = path.is_dir()
        entries: dict[str, list[Any]] = {}
        foreign = 0
        if exists:
            if declared["mode"] == "exclusive":
                entries = scan_exclusive(path, limits, declared["name"])
            else:
                entries, foreign = scan_signature(
                    path, globs, int(declared.get("max_depth", 1)), limits, declared["name"]
                )
        roots.append(
            {
                "name": declared["name"],
                "template": declared["path"],
                "path": str(path),
                "mode": declared["mode"],
                "max_depth": int(declared.get("max_depth", 1)),
                "resolved": True,
                "exists": exists,
                "entries": entries,
                "foreign_count": foreign,
            }
        )
    return {
        "schema": MANIFEST_SCHEMA,
        "captured_at_unix": int(time.time()),
        "signature_globs": globs,
        "limits": limits,
        "roots": roots,
    }


def summarize(manifest: dict[str, Any]) -> None:
    for root in manifest["roots"]:
        if not root["resolved"]:
            print(f"  [unresolved] {root['name']:<34} {root['template']}")
            continue
        state = "exists" if root["exists"] else "absent"
        extra = ""
        if root["mode"] == "signature":
            extra = f", {root['foreign_count']} foreign entries (not policed)"
        print(
            f"  [{root['mode']:<9}] {root['name']:<34} {state}: "
            f"{len(root['entries'])} policed entries{extra}"
        )
        print(f"      path: {root['path']}")
        for rel in sorted(root["entries"]):
            fingerprint = root["entries"][rel]
            head = str(fingerprint[0])[:16]
            print(f"        {head:<16} {fingerprint[1]:>10}  {rel}")


def report_foreign_churn(before: dict[str, Any], after: dict[str, Any]) -> None:
    """Label and count third-party churn in shared roots. Never a pass/fail signal."""
    foreign_before = sum(root["foreign_count"] for root in before["roots"])
    foreign_after = sum(root["foreign_count"] for root in after["roots"])
    print(
        f"INFO[ASTRO_NO_ESCAPE_FOREIGN_CHURN]: {foreign_before} -> {foreign_after} "
        "non-project entries in shared roots; counted, not policed"
    )


def diff_roots(before: dict[str, Any], after: dict[str, Any]) -> list[dict[str, Any]]:
    escapes: list[dict[str, Any]] = []
    before_by_name = {root["name"]: root for root in before["roots"]}
    for root in after["roots"]:
        prior = before_by_name.get(root["name"])
        if prior is None:
            fail(
                "ASTRO_NO_ESCAPE_MANIFEST_MISMATCH",
                f"root {root['name']} is not present in the before-manifest",
                "take the before-snapshot and the after-verify with the same registry",
            )
        if not root["resolved"]:
            continue
        prior_entries = prior["entries"]
        entries = root["entries"]
        for rel in sorted(set(entries) - set(prior_entries)):
            escapes.append(
                {
                    "root": root["name"],
                    "change": "ADDED",
                    "path": str(Path(root["path"]) / rel),
                    "fingerprint": entries[rel],
                }
            )
        for rel in sorted(set(prior_entries) - set(entries)):
            escapes.append(
                {
                    "root": root["name"],
                    "change": "REMOVED",
                    "path": str(Path(root["path"]) / rel),
                    "fingerprint": prior_entries[rel],
                }
            )
        for rel in sorted(set(prior_entries) & set(entries)):
            if prior_entries[rel] != entries[rel]:
                escapes.append(
                    {
                        "root": root["name"],
                        "change": "MODIFIED",
                        "path": str(Path(root["path"]) / rel),
                        "fingerprint": entries[rel],
                        "was": prior_entries[rel],
                    }
                )
    return escapes


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------


def cmd_snapshot(args: argparse.Namespace) -> int:
    config = load_roots(args.roots)
    manifest = snapshot(config)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(f"protected-root snapshot -> {args.out}")
    summarize(manifest)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    config = load_roots(args.roots)
    try:
        before = json.loads(args.before.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(
            "ASTRO_NO_ESCAPE_NO_BASELINE",
            f"cannot read the before-snapshot at {args.before}",
            "run `check-no-escape.py snapshot` before the suite; without a baseline the "
            "gate cannot prove containment and must not pass",
            {"error": str(exc)},
        )
    if before.get("schema") != MANIFEST_SCHEMA:
        fail(
            "ASTRO_NO_ESCAPE_NO_BASELINE",
            f"before-snapshot has wrong schema: {before.get('schema')!r}",
            f"regenerate the snapshot; expected {MANIFEST_SCHEMA}",
        )
    after = snapshot(config)
    if args.out is not None:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(after, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    escapes = diff_roots(before, after)
    report_foreign_churn(before, after)

    if escapes:
        for escape in escapes:
            print(
                f"  {escape['change']:<8} [{escape['root']}] {escape['path']}",
                file=sys.stderr,
            )
        fail(
            ESCAPE_CODE,
            f"the run escaped its sandbox and mutated {len(escapes)} entr"
            f"{'y' if len(escapes) == 1 else 'ies'} of the operator's protected state: "
            + ", ".join(escape["path"] for escape in escapes[:8]),
            "A test or gate wrote outside its sandbox. Run the suite under "
            "`scripts/check-no-escape.py run` so HOME/TMP/XDG roots are redirected, and fix "
            "the code path that used an absolute path or an un-redirected state root. Vault "
            "and cache dirs must be removed on the panic path too (see #133/#236: an RAII "
            "Drop guard, not a happy-path cleanup).",
            {"escapes": escapes},
        )

    print("no-escape verified: every protected root is byte-identical to the baseline")
    summarize(after)
    return 0


def sandbox_env(sandbox: Path, args: argparse.Namespace) -> dict[str, str]:
    home = sandbox / "home"
    tmp = sandbox / "tmp"
    for path in (home, tmp, home / ".cache", home / ".config", home / ".local" / "share"):
        path.mkdir(parents=True, exist_ok=True)

    env = dict(os.environ)
    env["HOME"] = str(home)
    env["USERPROFILE"] = str(home)
    env["TMP"] = str(tmp)
    env["TEMP"] = str(tmp)
    env["TMPDIR"] = str(tmp)
    env["XDG_CACHE_HOME"] = str(home / ".cache")
    env["XDG_CONFIG_HOME"] = str(home / ".config")
    env["XDG_DATA_HOME"] = str(home / ".local" / "share")
    env["ASTRO_SANDBOX_ROOT"] = str(sandbox)
    if os.name == "nt":
        local = home / "AppData" / "Local"
        roaming = home / "AppData" / "Roaming"
        local.mkdir(parents=True, exist_ok=True)
        roaming.mkdir(parents=True, exist_ok=True)
        env["LOCALAPPDATA"] = str(local)
        env["APPDATA"] = str(roaming)

    if args.set_cbm_cache_dir:
        # Off by default: the vendored CBM C tests derive their store from $HOME,
        # and pinning CBM_CACHE_DIR globally regresses ~808 of them. Redirecting
        # HOME already moves the store.
        cbm = home / ".cache" / "codebase-memory-mcp"
        cbm.mkdir(parents=True, exist_ok=True)
        env["CBM_CACHE_DIR"] = str(cbm)

    # Declared writable toolchain roots (the Bazel model: name what may be
    # written, fail on everything else). These are the toolchain's own store, not
    # operator state under test, and the redirect above would otherwise strand
    # cargo/rustup/sccache in an empty home.
    declared: list[str] = []
    operator_home = real_home()
    for name, default in (
        ("CARGO_HOME", operator_home / ".cargo"),
        ("RUSTUP_HOME", operator_home / ".rustup"),
    ):
        value = os.environ.get(name) or str(default)
        env[name] = value
        declared.append(f"{name}={value}")
    if os.environ.get("SCCACHE_DIR"):
        declared.append(f"SCCACHE_DIR={os.environ['SCCACHE_DIR']}")

    print(f"sandbox root      : {sandbox}")
    print(f"  HOME/USERPROFILE: {home}")
    print(f"  TMP/TEMP/TMPDIR : {tmp}")
    print(f"  XDG_CACHE_HOME  : {home / '.cache'}")
    print(f"  declared writable (toolchain, not policed): {', '.join(declared)}")
    return env


def cmd_run(args: argparse.Namespace) -> int:
    if not args.command:
        fail(
            "ASTRO_NO_ESCAPE_NO_COMMAND",
            "no command was given to run under the sandbox",
            "pass the suite after `--`, e.g. check-no-escape.py run -- cargo test --workspace",
        )
    config = load_roots(args.roots)
    sandbox = args.sandbox.resolve()
    if sandbox.exists() and args.fresh:
        shutil.rmtree(sandbox)
    sandbox.mkdir(parents=True, exist_ok=True)

    before = snapshot(config)
    baseline = sandbox / "no-escape-before.json"
    baseline.write_text(json.dumps(before, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print("=== protected roots BEFORE ===")
    summarize(before)

    env = sandbox_env(sandbox, args)
    print(f"=== running under sandbox: {' '.join(args.command)} ===")
    proc = subprocess.run(args.command, cwd=args.cwd or ROOT, env=env, check=False)

    print("=== protected roots AFTER ===")
    after = snapshot(config)
    summarize(after)
    (sandbox / "no-escape-after.json").write_text(
        json.dumps(after, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )

    escapes = diff_roots(before, after)
    report_foreign_churn(before, after)
    if escapes:
        for escape in escapes:
            print(
                f"  {escape['change']:<8} [{escape['root']}] {escape['path']}",
                file=sys.stderr,
            )
        fail(
            ESCAPE_CODE,
            f"the sandboxed run escaped and mutated {len(escapes)} entr"
            f"{'y' if len(escapes) == 1 else 'ies'} of the operator's protected state: "
            + ", ".join(escape["path"] for escape in escapes[:8]),
            "The command wrote outside the sandbox even though HOME/TMP/XDG were "
            "redirected, so it used an absolute path or an un-redirected state root. Fix the "
            "code path; do not widen the registry. Vault and cache dirs must be removed on "
            "the panic path too (#133/#236: an RAII Drop guard, not a happy-path cleanup).",
            {"escapes": escapes, "command": args.command},
        )

    if args.require_sandbox_writes:
        written = [path for path in sandbox.rglob("*") if path.is_file()]
        # The two manifests this command writes are not the suite's writes.
        suite_writes = [
            path for path in written if path.parent != sandbox or "no-escape-" not in path.name
        ]
        if not suite_writes:
            fail(
                "ASTRO_NO_ESCAPE_SANDBOX_EMPTY",
                f"the sandbox at {sandbox} received no writes from the run",
                "a clean protected root proves nothing if the suite never wrote anywhere. "
                "Confirm the redirected environment reaches the child process and that the "
                "suite actually ran before trusting this containment result.",
                {"sandbox": str(sandbox)},
            )
        print(f"sandbox received {len(suite_writes)} file(s) from the run")

    if proc.returncode != 0:
        print(
            f"no-escape: the sandboxed command exited {proc.returncode}; "
            "containment held, but the command itself failed",
            file=sys.stderr,
        )
        return proc.returncode

    print("no-escape verified: the run stayed inside its sandbox")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--roots",
        type=Path,
        default=DEFAULT_ROOTS,
        help="Protected-root registry (default scripts/no-escape-roots.json).",
    )
    sub = parser.add_subparsers(dest="command_name", required=True)

    snap = sub.add_parser("snapshot", help="record a byte manifest of every protected root")
    snap.add_argument("--out", type=Path, required=True)
    snap.set_defaults(func=cmd_snapshot)

    verify = sub.add_parser("verify", help="fail closed if any protected root changed")
    verify.add_argument("--before", type=Path, required=True)
    verify.add_argument("--out", type=Path, default=None)
    verify.set_defaults(func=cmd_verify)

    run = sub.add_parser("run", help="run a suite contained in a sandbox, then prove no escape")
    run.add_argument("--sandbox", type=Path, required=True)
    run.add_argument("--cwd", type=Path, default=None)
    run.add_argument("--fresh", action="store_true", help="remove an existing sandbox first")
    run.add_argument(
        "--require-sandbox-writes",
        action="store_true",
        help="fail if the run wrote nothing to the sandbox (a no-op suite proves nothing).",
    )
    run.add_argument(
        "--set-cbm-cache-dir",
        action="store_true",
        help="also pin CBM_CACHE_DIR into the sandbox (off by default; see module docs).",
    )
    run.add_argument("command", nargs=argparse.REMAINDER)
    run.set_defaults(func=cmd_run)

    args = parser.parse_args()
    if getattr(args, "command", None) and args.command and args.command[0] == "--":
        args.command = args.command[1:]
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
