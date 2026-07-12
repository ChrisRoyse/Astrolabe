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
import re
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
ATTRIBUTION_SCHEMA = "astrolabe.no_escape_attribution.v1"
ATTRIBUTION_ENV = "ASTRO_NO_ESCAPE_ATTRIBUTION"
READ_BLOCK_BYTES = 1 << 20

ESCAPE_CODE = "ASTRO_TEST_SANDBOX_ESCAPE"

# --------------------------------------------------------------------------
# CAUSAL ATTRIBUTION (#278)
#
# The gate protects roots the operator SHARES with the OS and -- on this
# machine -- with other Calyx/codebase-memory projects and concurrent MCP
# servers. Deciding "is this delta OURS?" by NAME PATTERN (calyx*, cbm*) is
# unsound there: a `cargo test` in the operator's OWN Calyx checkout drops
# `calyx-retention-<pid>` dirs into %TEMP%, and a second Claude session's MCP
# server writes ~/.cache/codebase-memory-mcp/_config.db -- both match the
# project signature yet neither is ours. Nominal attribution turns that foreign
# churn into a false ASTRO_TEST_SANDBOX_ESCAPE.
#
# Attribution is therefore CAUSAL: a delta is OURS only if it is traceable to a
# process in THIS run's launcher-rooted process tree. The launcher records that
# tree (Windows Job Object; every descendant PID) plus any protected-root path
# it observed a tree process open, into an attribution manifest the gate reads.
#   * tree_pids  -- every PID that belonged to our Job Object. The vendored test
#                   scratch-dir convention embeds std::process::id() in the name
#                   (`calyx-retention-mixed-<pid>`), so a PID token in a shared-
#                   root entry that is in tree_pids proves the dir is ours.
#   * owned_paths -- absolute protected-root paths a tree process opened for
#                   write (for artifacts that carry no PID, e.g. store files).
#
# Confinement (launcher redirects TMP/TEMP/TMPDIR into the workspace; every gate
# phase pins CBM_CACHE_DIR to a sandbox) means our env-respecting tests never
# reach these operator roots at all, so in practice tree_pids/owned_paths are
# EMPTY of operator-root entries on a clean run and the only deltas are foreign.
# Attribution is the backstop for a regression that bypasses the redirect: such
# a leak still carries our PID (Bazel's rule -- tests use unique, pid-stamped
# paths), so it is attributed and RED. Foreign churn is counted, never policed.
_PID_TOKEN = re.compile(r"(?<![0-9])([0-9]{2,7})(?![0-9])")


def load_attribution(path: Path | None) -> dict[str, Any] | None:
    """Load the launcher-produced causal-attribution manifest. None if absent."""
    if path is None:
        env_value = os.environ.get(ATTRIBUTION_ENV)
        if env_value:
            path = Path(env_value)
    if path is None:
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(
            "ASTRO_NO_ESCAPE_BAD_ATTRIBUTION",
            f"cannot read the causal-attribution manifest at {path}",
            "the launcher writes this file (process-tree PIDs); regenerate it or unset "
            f"{ATTRIBUTION_ENV}. The gate refuses to guess attribution.",
            {"error": str(exc)},
        )
    if data.get("schema") != ATTRIBUTION_SCHEMA:
        fail(
            "ASTRO_NO_ESCAPE_BAD_ATTRIBUTION",
            f"attribution manifest has wrong schema: {data.get('schema')!r}",
            f"set schema to {ATTRIBUTION_SCHEMA}",
        )
    try:
        tree_pids = {int(pid) for pid in data.get("tree_pids", [])}
    except (TypeError, ValueError) as exc:
        fail(
            "ASTRO_NO_ESCAPE_BAD_ATTRIBUTION",
            "attribution manifest tree_pids must be integers",
            "the launcher writes integer PIDs; regenerate the manifest",
            {"error": str(exc)},
        )
    owned_paths = {
        os.path.normcase(os.path.abspath(str(entry))) for entry in data.get("owned_paths", [])
    }
    run_started = data.get("run_started_unix_ns")
    if run_started is not None:
        try:
            run_started = int(run_started)
        except (TypeError, ValueError) as exc:
            fail(
                "ASTRO_NO_ESCAPE_BAD_ATTRIBUTION",
                "attribution manifest run_started_unix_ns must be an integer",
                "the launcher writes an epoch-ns start time; regenerate the manifest",
                {"error": str(exc)},
            )
    # #278 attempt 8b: manifest flush timestamp. The launcher's recorder rewrites
    # this manifest THROTTLED (~1/sec) while the run is live, and `verify` reads it
    # MID-SESSION -- before the launcher teardown's final flush. So the manifest the
    # gate sees can lag reality: a process that leaked into a shared root may not yet
    # be recorded in tree_pids/pid_intervals. Classifying such a delta FOREIGN just
    # because its pid is not (yet) in a stale manifest would be a SILENT FALLBACK to
    # green. written_at stamps each flush so the gate can detect that a delta POSTDATES
    # the manifest and fail toward RED (ASTRO_NO_ESCAPE_STALE_MANIFEST) instead. A
    # manifest without written_at (older recorder) disables the guard -- but then the
    # open-interval/first-seen guards still point toward policing; written_at only adds
    # protection, never removes it.
    written_at = data.get("written_at")
    if written_at is not None:
        try:
            written_at = int(written_at)
        except (TypeError, ValueError) as exc:
            fail(
                "ASTRO_NO_ESCAPE_BAD_ATTRIBUTION",
                "attribution manifest written_at must be an integer",
                "the launcher writes an epoch-ns flush time; regenerate the manifest",
                {"error": str(exc)},
            )
    try:
        pid_first_seen = {
            int(pid): int(seen_ns) for pid, seen_ns in (data.get("pid_first_seen") or {}).items()
        }
    except (TypeError, ValueError) as exc:
        fail(
            "ASTRO_NO_ESCAPE_BAD_ATTRIBUTION",
            "attribution manifest pid_first_seen must map integer pids to epoch-ns integers",
            "the launcher writes {pid: first_seen_ns}; regenerate the manifest",
            {"error": str(exc)},
        )
    # #278 attempt 7: pid INSTANCE LIFETIME windows. pid_intervals maps each pid to
    # a list of [first_seen_ns, last_seen_ns|null] intervals -- one per instance of
    # that pid inside OUR tree (the Job Object delivers both NEW_PROCESS and
    # EXIT_PROCESS, and the same pid can genuinely serve two of our short-lived
    # children). null upper bound = the instance had not exited when the manifest
    # was written -> OPEN window (never 'assume dead'; fail closed toward policing).
    # A manifest without pid_intervals (older recorder) degrades to open-ended
    # windows derived from pid_first_seen -- again the toward-RED direction.
    pid_intervals: dict[int, list[tuple[int, int | None]]] = {}
    raw_intervals = data.get("pid_intervals")
    if raw_intervals is not None:
        try:
            for pid, spans in raw_intervals.items():
                parsed: list[tuple[int, int | None]] = []
                for span in spans:
                    first, last = span[0], span[1]
                    parsed.append((int(first), None if last is None else int(last)))
                pid_intervals[int(pid)] = parsed
        except (TypeError, ValueError, IndexError, AttributeError) as exc:
            fail(
                "ASTRO_NO_ESCAPE_BAD_ATTRIBUTION",
                "attribution manifest pid_intervals must map pids to [first_ns, last_ns|null] pairs",
                "the launcher writes instance lifetime intervals; regenerate the manifest",
                {"error": str(exc)},
            )
    else:
        pid_intervals = {pid: [(seen, None)] for pid, seen in pid_first_seen.items()}
    return {
        "path": str(path),
        "launcher_pid": data.get("launcher_pid"),
        "run_started_unix_ns": run_started,
        "written_at": written_at,
        "tree_pids": tree_pids,
        "pid_first_seen": pid_first_seen,
        "pid_intervals": pid_intervals,
        "owned_paths": owned_paths,
    }


# Verdicts for a delta in a causally-policed (signature/attributed) root.
OURS = "ours"
FOREIGN = "foreign"
PRE_RUN = "pre_run"
PID_INSTANCE = "pid_instance"
STALE_DIR_MTIME = "stale_dir_mtime"
# #278 attempt 8b: a delta that POSTDATES the manifest's flush timestamp. The
# throttled recorder may not have observed the leaking process yet, so a FOREIGN
# classification cannot be trusted -- policed (RED), never silently counted.
STALE_MANIFEST = "stale_manifest"

# Verdicts that POLICE the delta (fail the build). Every other verdict is counted
# and labeled, never used to fail. STALE_MANIFEST joins OURS on the fail-closed side.
POLICED_VERDICTS = frozenset({OURS, STALE_MANIFEST})


def classify_causal_delta(
    change: str,
    rel: str,
    abspath: Path,
    post_fp: list[Any] | None,
    prior_fp: list[Any] | None,
    attribution: dict[str, Any],
    skew_ns: int,
    run_started_ns: int | None,
) -> str:
    """Classify a shared-root delta: OURS (policed) or a counted-not-policed verdict.

    Attempt-6 refinement (#278): PID-token matching alone is defeated by PID REUSE
    (a foreign batch's creator pid recycled by one of our thousands of short-lived
    children) and by NTFS STALE DIRECTORY TIMESTAMPS (scandir returns the directory
    entry's lazily-synced duplicated file info, which can lag a fresh-handle
    os.stat; both flagged mtimes in attempt 6 PREDATED the run). Three causal
    guards close both holes:

      RUN-WINDOW  -- a delta whose post-state timestamp predates run_started (minus
                     the registry-declared skew margin) cannot be our escape:
                     nothing we ran existed yet. -> PRE_RUN, counted.
      STALE-MTIME -- a dir-type MODIFIED whose only delta is the timestamp (type
                     and size unchanged) is re-read with a FRESH os.stat; if the
                     fresh value matches the baseline or predates the run, the
                     "change" was a lazily-synced directory timestamp, not a write
                     in our window. -> STALE_DIR_MTIME, counted. Never applied to
                     exclusive roots, ADDED/REMOVED, or content (digest) changes.
      FIRST-SEEN  -- a pid token only attributes an entry whose timestamp is >=
                     that pid's first-seen time in OUR tree (the Job Object stamps
                     each pid at creation): a dir created at 12:57 cannot belong
                     to our pid instance first seen at 13:4x. -> PID_INSTANCE.

    Attempt-7 refinement: first-seen alone still false-attributed DEAD instances --
    four foreign-sweep pids collided with launcher-startup children of ours that
    were first seen at 14:2x and long dead when the foreign dirs appeared at
    14:34-14:36. A pid token therefore attributes only an entry whose timestamp
    falls INSIDE one of that pid's instance LIFETIME intervals in our tree:
    first_seen - skew <= entry_ts <= last_seen + skew, per instance (the recorder
    also consumes JOB_OBJECT_MSG_(ABNORMAL_)EXIT_PROCESS and keeps a [first, last]
    list per pid, so a pid recycled WITHIN our own tree matches on any of its
    instances). A missing exit stamp means the instance was still alive at
    manifest-write time -> open upper bound; a tree pid with no interval data at
    all (older manifest, recorder stopped early) also degrades to an open window.
    Both degradations point toward POLICING (never 'assume dead'). Identity vs
    instance for REMOVED entries: a removal has no event timestamp in either
    manifest, so a tree-pid token polices it unconditionally -- the fail-closed
    direction; the run-window/stale guards never apply to REMOVED.
    """
    entry_ts: int | None = None
    if change in ("ADDED", "MODIFIED") and post_fp is not None:
        entry_ts = int(post_fp[2])

    # STALE-MTIME: dir-type MODIFIED, type and size unchanged -> only the
    # scandir-cached timestamp moved. Confirm with a fresh stat.
    if (
        change == "MODIFIED"
        and post_fp is not None
        and prior_fp is not None
        and post_fp[0] == "dir"
        and prior_fp[0] == "dir"
        and post_fp[1] == prior_fp[1]
    ):
        try:
            fresh_mtime_ns = os.stat(abspath, follow_symlinks=False).st_mtime_ns
        except OSError:
            fresh_mtime_ns = None
        if fresh_mtime_ns is not None and (
            fresh_mtime_ns == int(prior_fp[2])
            or (run_started_ns is not None and fresh_mtime_ns < run_started_ns - skew_ns)
        ):
            return STALE_DIR_MTIME

    # RUN-WINDOW: an entry whose post-state timestamp predates the run cannot be
    # ours, whatever its name says (REMOVED has no post state; not gated).
    if entry_ts is not None and run_started_ns is not None and entry_ts < run_started_ns - skew_ns:
        return PRE_RUN

    norm = os.path.normcase(os.path.abspath(str(abspath)))
    for owned in attribution["owned_paths"]:
        if norm == owned or norm.startswith(owned + os.sep):
            return OURS

    tree_pids = attribution["tree_pids"]
    pid_intervals = attribution.get("pid_intervals") or {}
    top_name = rel.split("/", 1)[0]
    saw_pid_instance_mismatch = False
    if tree_pids:
        for token in _PID_TOKEN.findall(top_name):
            pid = int(token)
            if pid not in tree_pids:
                continue
            if entry_ts is None:
                # REMOVED: no event timestamp exists for a deletion, so instance
                # windows cannot apply. A tree-pid token polices it (fail closed).
                return OURS
            intervals = pid_intervals.get(pid)
            if not intervals:
                # In our tree but without lifetime data (older manifest / recorder
                # stopped early): open window, never 'assume dead'. The upstream
                # run-window guard has already excluded pre-run entries.
                return OURS
            for first_seen_ns, last_seen_ns in intervals:
                if entry_ts < first_seen_ns - skew_ns:
                    continue  # entry predates this instance
                if last_seen_ns is not None and entry_ts > last_seen_ns + skew_ns:
                    continue  # entry postdates this instance's exit (attempt 7)
                return OURS
            # Every instance of this pid in our tree was dead (or unborn) when the
            # entry was written -- the token matches a RECYCLED pid, not our process.
            saw_pid_instance_mismatch = True
    # STALE-MANIFEST (#278 attempt 8b): the delta did not attribute to our tree, but
    # the manifest may simply be STALE for it -- the throttled recorder rewrites the
    # manifest ~1/sec and `verify` reads it mid-session, so a process that leaked
    # AFTER the last flush is not yet in tree_pids/pid_intervals. If this delta's
    # timestamp POSTDATES the manifest flush (beyond skew), the FOREIGN verdict is
    # untrustworthy: the recorder had not observed the leaker at write time. Fail
    # toward RED rather than silently toward foreign. (PRE_RUN / STALE_DIR_MTIME have
    # already returned above; a delta predating the run can never postdate a later
    # flush, so this never re-reddens the pre-run/stale-timestamp cases.)
    written_at = attribution.get("written_at")
    if entry_ts is not None and written_at is not None and entry_ts > written_at + skew_ns:
        return STALE_MANIFEST
    if saw_pid_instance_mismatch:
        return PID_INSTANCE
    return FOREIGN


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
    valid_modes = {"exclusive", "signature", "attributed"}
    for declared in config["roots"]:
        mode = declared.get("mode")
        if mode not in valid_modes:
            fail(
                "ASTRO_NO_ESCAPE_BAD_REGISTRY",
                f"root {declared.get('name')!r} has unknown mode {mode!r}",
                f"mode must be one of {sorted(valid_modes)}",
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
            # `attributed` roots are shared-by-design (the CBM store: concurrent
            # MCP servers write it too) but small and worth a full byte manifest;
            # they are hashed like an exclusive root and attributed at diff time.
            if declared["mode"] in ("exclusive", "attributed"):
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


def report_foreign_churn(
    before: dict[str, Any], after: dict[str, Any], counted: dict[str, int] | None = None
) -> None:
    """Label and count third-party churn in shared roots. Never a pass/fail signal."""
    foreign_before = sum(root["foreign_count"] for root in before["roots"])
    foreign_after = sum(root["foreign_count"] for root in after["roots"])
    counted = counted or {}
    extra = ""
    if counted.get(FOREIGN):
        extra = (
            f"; plus {counted[FOREIGN]} signature-matching delta(s) NOT attributable to this "
            "run's process tree (concurrent Calyx/CBM work), counted not policed"
        )
    print(
        f"INFO[ASTRO_NO_ESCAPE_FOREIGN_CHURN]: {foreign_before} -> {foreign_after} "
        f"non-project entries in shared roots; counted, not policed{extra}"
    )
    if counted.get(PRE_RUN):
        print(
            f"INFO[ASTRO_NO_ESCAPE_PRE_RUN_DELTA]: {counted[PRE_RUN]} shared-root delta(s) "
            "whose timestamps predate this run's start (cannot be our escape by causality); "
            "counted, not policed"
        )
    if counted.get(PID_INSTANCE):
        print(
            f"INFO[ASTRO_NO_ESCAPE_PID_INSTANCE_MISMATCH]: {counted[PID_INSTANCE]} shared-root "
            "delta(s) naming a RECYCLED pid (entry predates that pid's first-seen time in our "
            "tree); counted, not policed"
        )
    if counted.get(STALE_DIR_MTIME):
        print(
            f"INFO[ASTRO_NO_ESCAPE_STALE_DIR_MTIME]: {counted[STALE_DIR_MTIME]} dir entr"
            f"{'y' if counted[STALE_DIR_MTIME] == 1 else 'ies'} whose only delta was a "
            "directory timestamp that a fresh os.stat shows baseline-consistent or pre-run "
            "(NTFS lazily-synced duplicated file info); counted, not policed"
        )


def requires_attribution(config: dict[str, Any]) -> bool:
    """True if any declared root is policed CAUSALLY (shared-by-design roots)."""
    return any(root["mode"] in ("signature", "attributed") for root in config["roots"])


def skew_margin_ns(config: dict[str, Any]) -> int:
    """Registry-declared timestamp-skew margin (invariant 4: a knob, not a constant).

    Declared in scripts/no-escape-roots.json under attribution.skew_margin_secs.
    Bounds every timestamp-granularity/laziness source the run-window and
    first-seen guards compare across: NTFS duplicated-info lazy sync (attempt 6
    measured 164-168 ms), FAT-class 2 s metadata granularity ceiling, the ~15.6 ms
    Windows clock tick, and completion-port delivery latency for first-seen stamps.
    """
    declared = (config.get("attribution") or {}).get("skew_margin_secs", 2.0)
    try:
        value = float(declared)
    except (TypeError, ValueError):
        fail(
            "ASTRO_NO_ESCAPE_BAD_REGISTRY",
            f"attribution.skew_margin_secs must be a number, got {declared!r}",
            "declare a numeric skew margin in scripts/no-escape-roots.json",
        )
    if value < 0:
        fail(
            "ASTRO_NO_ESCAPE_BAD_REGISTRY",
            f"attribution.skew_margin_secs must be >= 0, got {value}",
            "declare a non-negative skew margin in scripts/no-escape-roots.json",
        )
    return int(value * 1_000_000_000)


def resolve_run_started_ns(
    attribution: dict[str, Any] | None, before: dict[str, Any]
) -> int | None:
    """The run-window guard's start time: launcher start if recorded, else baseline.

    The launcher's run_started_unix_ns (recorder start) precedes the baseline
    snapshot, so preferring it is the conservative choice -- it attributes MORE
    deltas to us, never fewer. The baseline's captured_at_unix always exists, so
    the window guard is always active during verify.
    """
    if attribution is not None and attribution.get("run_started_unix_ns") is not None:
        return int(attribution["run_started_unix_ns"])
    captured = before.get("captured_at_unix")
    if captured is not None:
        return int(captured) * 1_000_000_000
    return None


def diff_roots(
    before: dict[str, Any],
    after: dict[str, Any],
    attribution: dict[str, Any] | None,
    skew_ns: int,
    run_started_ns: int | None,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Return (escapes, counted-not-policed verdict counts).

    An escape is a delta CAUSALLY OURS. For `exclusive` roots (truly project-only)
    every delta is ours. For `signature`/`attributed` roots (shared with the OS and
    concurrent projects) a delta is ours only if classify_causal_delta traces it to
    the launcher-recorded process tree WITHIN this run's time window; every other
    verdict (foreign, pre-run, recycled-pid, stale dir timestamp) is counted and
    labeled, never used to fail the build.
    """
    escapes: list[dict[str, Any]] = []
    counted: dict[str, int] = {FOREIGN: 0, PRE_RUN: 0, PID_INSTANCE: 0, STALE_DIR_MTIME: 0}
    stale_manifest_hits = 0
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
        causal = root["mode"] in ("signature", "attributed")
        prior_entries = prior["entries"]
        entries = root["entries"]
        changes: list[tuple[str, str, list[Any] | None, list[Any] | None]] = []
        for rel in sorted(set(entries) - set(prior_entries)):
            changes.append(("ADDED", rel, entries[rel], None))
        for rel in sorted(set(prior_entries) - set(entries)):
            changes.append(("REMOVED", rel, None, prior_entries[rel]))
        for rel in sorted(set(prior_entries) & set(entries)):
            if prior_entries[rel] != entries[rel]:
                changes.append(("MODIFIED", rel, entries[rel], prior_entries[rel]))
        for change, rel, post_fp, prior_fp in changes:
            abspath = Path(root["path"]) / rel
            if causal:
                # attribution is guaranteed present for causal roots (the caller
                # fails closed otherwise); a delta not traceable to our tree
                # WITHIN OUR WINDOW is concurrent churn, not our escape.
                if attribution is None:
                    verdict = FOREIGN
                else:
                    verdict = classify_causal_delta(
                        change,
                        rel,
                        abspath,
                        post_fp,
                        prior_fp,
                        attribution,
                        skew_ns,
                        run_started_ns,
                    )
                if verdict not in POLICED_VERDICTS:
                    counted[verdict] += 1
                    print(
                        f"  COUNTED[{verdict}] {change:<8} [{root['name']}] {abspath}"
                    )
                    continue
                if verdict == STALE_MANIFEST:
                    stale_manifest_hits += 1
                    print(
                        f"  POLICED[stale_manifest] {change:<8} [{root['name']}] {abspath} "
                        "(delta postdates the attribution manifest's flush; the recorder had "
                        "not observed the writer, so 'foreign' cannot be trusted -- failing RED)"
                    )
            record: dict[str, Any] = {
                "root": root["name"],
                "change": change,
                "path": str(abspath),
                "fingerprint": post_fp if post_fp is not None else prior_fp,
            }
            if change == "MODIFIED" and prior_fp is not None:
                record["was"] = prior_fp
            escapes.append(record)
    if stale_manifest_hits:
        print(
            f"ERROR[ASTRO_NO_ESCAPE_STALE_MANIFEST]: {stale_manifest_hits} shared-root "
            "delta(s) postdate the attribution manifest's flush timestamp (written_at); the "
            "throttled process-tree recorder had not observed the writing process when the "
            "manifest was read, so they cannot be safely classified foreign and are POLICED. "
            "remediation: ensure the launcher's tree recorder flushed after the run (a healthy "
            "recorder rewrites within the skew margin); a persistently stale manifest means the "
            "recorder died mid-run -- restart the run so attribution is complete."
        )
    return escapes, counted


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
    attribution = load_attribution(args.attribution)
    if attribution is None and requires_attribution(config):
        fail(
            "ASTRO_NO_ESCAPE_NO_ATTRIBUTION",
            "the registry declares shared-by-design roots (operator %TEMP%/$HOME, the CBM "
            "store) that can only be policed by CAUSAL attribution, but no attribution "
            "manifest was supplied, so the gate cannot tell this run's writes from a "
            "concurrent Calyx/CBM process on this machine",
            "run under the launcher (which records the process tree) or pass "
            f"--attribution <manifest> / set {ATTRIBUTION_ENV}. The gate refuses to fall "
            "back to name-pattern attribution, which false-positives on shared roots (#278).",
        )
    skew_ns = skew_margin_ns(config)
    run_started_ns = resolve_run_started_ns(attribution, before)
    if attribution is not None:
        interval_count = sum(len(spans) for spans in attribution["pid_intervals"].values())
        open_count = sum(
            1
            for spans in attribution["pid_intervals"].values()
            for _, last in spans
            if last is None
        )
        print(
            f"INFO[ASTRO_NO_ESCAPE_ATTRIBUTION]: launcher_pid={attribution['launcher_pid']}, "
            f"{len(attribution['tree_pids'])} tree PID(s), "
            f"{interval_count} instance interval(s) ({open_count} open), "
            f"{len(attribution['owned_paths'])} owned path(s), "
            f"run_started_ns={run_started_ns}, written_at={attribution.get('written_at')}, "
            f"skew_ns={skew_ns} from {attribution['path']}"
        )

    after = snapshot(config)
    if args.out is not None:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(after, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    escapes, counted = diff_roots(before, after, attribution, skew_ns, run_started_ns)
    report_foreign_churn(before, after, counted)

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


def run_in_job(command: list[str], *, cwd: Path, env: dict[str, str]):
    """Run `command` on Windows inside a Job Object.

    Returns (proc, tree_pids, pid_first_seen, pid_intervals). Descendants
    auto-join the job, so polling its process-id list while the child runs
    captures the causal process tree (the same primitive the launcher uses for
    the aggregate). Instance lifetimes: a pid present in one poll and absent in
    the next has exited -- its interval closes at that poll's time; a pid that
    reappears later is a NEW instance and opens a new interval (attempt 7:
    attribution is per pid INSTANCE, never per pid identity). A pid still
    present at the last poll keeps an open (null) upper bound -- never 'assume
    dead'. Best-effort: any Win32 failure falls back to the direct child PID.
    """
    import ctypes
    from ctypes import wintypes

    tree_pids: set[int] = set()
    pid_first_seen: dict[int, int] = {}
    pid_intervals: dict[int, list[list[int | None]]] = {}
    live: set[int] = set()

    def note_pid(pid: int, now_ns: int) -> None:
        if pid not in tree_pids:
            tree_pids.add(pid)
            pid_first_seen[pid] = now_ns
        if pid not in live:
            live.add(pid)
            pid_intervals.setdefault(pid, []).append([now_ns, None])

    def close_absent(current: set[int], now_ns: int) -> None:
        for pid in list(live - current):
            live.discard(pid)
            spans = pid_intervals.get(pid)
            if spans and spans[-1][1] is None:
                spans[-1][1] = now_ns

    proc = subprocess.Popen(command, cwd=cwd, env=env)
    note_pid(proc.pid, time.time_ns())
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        job = kernel32.CreateJobObjectW(None, None)
        if not job:
            raise ctypes.WinError(ctypes.get_last_error())
        # AssignProcessToJobObject via the live child handle subprocess already holds.
        if not kernel32.AssignProcessToJobObject(job, int(proc._handle)):  # type: ignore[attr-defined]
            raise ctypes.WinError(ctypes.get_last_error())

        capacity = 4096
        job_basic_process_id_list = 3

        def poll_pids() -> None:
            class JOBOBJECT_BASIC_PROCESS_ID_LIST(ctypes.Structure):
                _fields_ = [
                    ("NumberOfAssignedProcesses", wintypes.DWORD),
                    ("NumberOfProcessIdsInList", wintypes.DWORD),
                    ("ProcessIdList", ctypes.c_size_t * capacity),
                ]

            info = JOBOBJECT_BASIC_PROCESS_ID_LIST()
            if kernel32.QueryInformationJobObject(
                job, job_basic_process_id_list, ctypes.byref(info), ctypes.sizeof(info), None
            ):
                now_ns = time.time_ns()
                current: set[int] = set()
                for index in range(min(info.NumberOfProcessIdsInList, capacity)):
                    pid = int(info.ProcessIdList[index])
                    current.add(pid)
                    note_pid(pid, now_ns)
                close_absent(current, now_ns)

        while proc.poll() is None:
            poll_pids()
            time.sleep(0.03)
        poll_pids()
        kernel32.CloseHandle(job)
    except OSError:
        proc.wait()
    intervals = {pid: [(span[0], span[1]) for span in spans] for pid, spans in pid_intervals.items()}
    return proc, tree_pids, pid_first_seen, intervals


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
    run_started_ns = time.time_ns()
    if os.name == "nt":
        # Capture the WHOLE descendant tree causally via a Job Object so an escape
        # by a grandchild is still attributed to this run (the launcher uses the
        # same primitive for the aggregate). Falls back to the direct child PID.
        proc, tree_pids, pid_first_seen, pid_intervals = run_in_job(
            args.command, cwd=args.cwd or ROOT, env=env
        )
    else:
        proc = subprocess.Popen(args.command, cwd=args.cwd or ROOT, env=env)
        proc.wait()
        tree_pids = {proc.pid}
        pid_first_seen = {proc.pid: run_started_ns}
        pid_intervals = {proc.pid: [(run_started_ns, time.time_ns())]}

    print("=== protected roots AFTER ===")
    after = snapshot(config)
    summarize(after)
    (sandbox / "no-escape-after.json").write_text(
        json.dumps(after, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )

    # `run` owns the sandbox it just executed, so it attributes causally from the
    # process tree IT captured. An EXPLICIT --attribution manifest overrides that
    # (the aggregate/self-tests pass one to drive multi-PID/owned-path cases), but
    # the ambient ${ATTRIBUTION_ENV} does NOT: that env var describes an OUTER
    # launcher run, not the suite this `run` just launched, so honoring it would
    # judge a fixture leak against the live session's tree and misclassify our own
    # child's escape as foreign (#278 attempt 8). Precedence: explicit flag >
    # captured tree > (env var deliberately ignored here).
    attribution = load_attribution(args.attribution) if args.attribution is not None else None
    if attribution is None:
        attribution = {
            "path": "<run: captured process tree>",
            "launcher_pid": os.getpid(),
            "run_started_unix_ns": run_started_ns,
            # The captured tree is authoritative and fully current (this process
            # observed every child live), so there is no stale-manifest window:
            # written_at=None deliberately disables that guard for `run`.
            "written_at": None,
            "tree_pids": tree_pids,
            "pid_first_seen": pid_first_seen,
            "pid_intervals": pid_intervals,
            "owned_paths": set(),
        }
    skew_ns = skew_margin_ns(config)
    effective_run_started = resolve_run_started_ns(attribution, before)
    print(
        f"INFO[ASTRO_NO_ESCAPE_ATTRIBUTION]: {len(attribution['tree_pids'])} tree PID(s), "
        f"{len(attribution['owned_paths'])} owned path(s), "
        f"run_started_ns={effective_run_started}, skew_ns={skew_ns}"
    )

    escapes, counted = diff_roots(before, after, attribution, skew_ns, effective_run_started)
    report_foreign_churn(before, after, counted)
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
    verify.add_argument(
        "--attribution",
        type=Path,
        default=None,
        help=(
            "causal-attribution manifest (launcher process-tree PIDs). Required when the "
            "registry declares shared-by-design roots. PRECEDENCE: an explicit path given "
            f"here BEATS the ${ATTRIBUTION_ENV} environment variable; the env var is used "
            "only when this flag is omitted. Self-tests pass the flag so a fixture run is "
            f"judged against its OWN manifest even when an ambient ${ATTRIBUTION_ENV} from a "
            "live launcher session is exported (#278 attempt 8)."
        ),
    )
    verify.set_defaults(func=cmd_verify)

    run = sub.add_parser("run", help="run a suite contained in a sandbox, then prove no escape")
    run.add_argument("--sandbox", type=Path, required=True)
    run.add_argument("--cwd", type=Path, default=None)
    run.add_argument(
        "--attribution",
        type=Path,
        default=None,
        help=(
            "optional explicit attribution manifest; otherwise the process tree this "
            "command captures is used. PRECEDENCE: an explicit path here BEATS both the "
            f"captured tree and the ${ATTRIBUTION_ENV} environment variable. When omitted, "
            f"the captured tree is preferred over ${ATTRIBUTION_ENV} so a `run` in a live "
            "launcher session still attributes to the suite it actually launched (#278)."
        ),
    )
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
