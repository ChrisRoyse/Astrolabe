#!/usr/bin/env python3
"""#227 Full State Verification: cbm_spawn_capture is shell-free end to end.

Source of truth: the exact argv bytes the spawned child receives, and the bytes
on disk in a real git repository whose PATH contains cmd.exe expansion
metacharacters. A return code proves nothing here; this harness reads BOTH back.

What it does (all with real data, no mocks):
  1. Build a tiny native C harness that links patches/cbm/astro_spawn.c and calls
     cbm_spawn_capture() with an explicit argv.
  2. Build a native "argv echoer" that prints, one per line, every argv element
     it was handed by the OS (its GetCommandLineW/CRT-parsed argv). This is the
     independent read-back of "the bytes git receives".
  3. Create a REAL git repo whose absolute path contains `%PATH%`, a literal `!`,
     a `^`, and a `;rm -rf x` suffix — every class cmd.exe would expand or treat
     specially. Commit a file so `git rev-parse HEAD` has an answer.
  4. Drive cbm_spawn_capture(["git","-C",<evil path>,"rev-parse","HEAD"]) and
     read back the captured stdout: it must equal the real HEAD sha on disk.
  5. Drive cbm_spawn_capture([<echoer>, <evil path>, "%PATH%", "a;b", "a b",
     'a"b', "back\\slash"]) and read back the echoer's argv: each element must be
     byte-for-byte identical to what we passed — proving no shell expanded
     %PATH%, no `;` split a command, and the CommandLineToArgvW round-trip holds.
  6. Assert a canary env var the harness sets is NOT expanded into any captured
     output — direct proof no %VAR% substitution occurred.

Requires a C compiler and git. On a host without them it exits 0 with a printed
SKIP so it never fakes a pass; the canonical-workspace native gate is where the
compiled evidence is authoritative.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATCH_DIR = ROOT / "patches" / "cbm"
SPAWN_C = PATCH_DIR / "astro_spawn.c"

IS_WIN = os.name == "nt"

# The adversarial path segment: every cmd.exe expansion/redirection class plus a
# canary variable name we will define in the environment. If ANY of these were
# interpreted by a shell, the read-back would differ from the literal bytes.
CANARY_ENV = "ASTRO_SPAWN_CANARY"
CANARY_VALUE = "EXPANDED_BY_SHELL_SHOULD_NEVER_APPEAR"
# Kept filesystem-legal on Windows (no : * ? " < > | / \\) but full of shell
# metacharacters: % for %VAR%, ! for delayed expansion, ^ for the escape char,
# ; and & for command separation, spaces for word splitting.
EVIL_SEGMENT = "repo %ASTRO_SPAWN_CANARY% !x! ^y ;rm -rf z & echo hi"


HARNESS_C = r"""
#include "astro_spawn.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Mode 1: run the given argv through cbm_spawn_capture and print captured
 * stdout verbatim to our stdout, then a trailer line with rc/exit/code.
 * argv: harness --spawn PROG [ARG...]  */
int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "--echo-argv") == 0) {
        /* Mode 2: the "child" — print every argument we received, one per line,
         * exactly as the OS handed it to us. This is the argv read-back. */
        for (int i = 2; i < argc; i++) {
            printf("ARG[%d]=%s\n", i - 2, argv[i]);
        }
        return 0;
    }
    if (argc < 3 || strcmp(argv[1], "--spawn") != 0) {
        fprintf(stderr, "usage: harness --spawn PROG [ARG...]\n");
        return 2;
    }
    /* Build the child argv from argv[2..]. */
    int n = argc - 2;
    const char **child = (const char **)malloc((size_t)(n + 1) * sizeof(char *));
    for (int i = 0; i < n; i++) {
        child[i] = argv[i + 2];
    }
    child[n] = NULL;

    char *out = NULL;
    size_t len = 0;
    cbm_spawn_error_t err;
    memset(&err, 0, sizeof(err));
    int rc = cbm_spawn_capture(child, &out, &len, &err);
    if (out) {
        fwrite(out, 1, len, stdout);
    }
    fflush(stdout);
    fprintf(stderr, "SPAWN_RC=%d CODE=%s EXIT=%d OSERR=%lu MSG=%s\n", rc,
            err.code_name ? err.code_name : "(null)", err.exit_code, err.os_error,
            err.message ? err.message : "");
    free(out);
    free(child);
    return rc == 0 ? 0 : 1;
}
"""


def skip(msg: str) -> None:
    print(f"SKIP[ASTRO_CBM_SPAWN_FSV]: {msg}")
    print("  (compiled FSV runs in the canonical native workspace with a C compiler + git)")
    raise SystemExit(0)


def find_compiler() -> list[str] | None:
    env_cc = os.environ.get("CC")
    if env_cc:
        return env_cc.split()
    toolchain = ROOT / ".toolchains" / "mingw-14.1.0-posix-seh-msvcrt-rt_v12-rev0" / "bin"
    gcc = toolchain / ("gcc.exe" if IS_WIN else "gcc")
    if gcc.is_file():
        return [str(gcc)]
    for name in ("cc", "gcc", "clang"):
        found = shutil.which(name)
        if found:
            return [found]
    return None


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"CBM spawn FSV failed: {message}")


def main() -> None:
    if not shutil.which("git"):
        skip("git not on PATH")
    cc = find_compiler()
    if cc is None:
        skip("no C compiler found (set CC or bootstrap .toolchains)")

    work = Path(tempfile.mkdtemp(prefix="astro-spawn-fsv-"))
    try:
        run_fsv(cc, work)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def run_fsv(cc: list[str], work: Path) -> None:
    harness_src = work / "harness.c"
    harness_src.write_text(HARNESS_C, encoding="utf-8")
    harness_bin = work / ("harness.exe" if IS_WIN else "harness")

    compile_cmd = cc + [
        "-std=c11",
        "-O2",
        "-I",
        str(PATCH_DIR),
        str(harness_src),
        str(SPAWN_C),
        "-o",
        str(harness_bin),
    ]
    proc = subprocess.run(compile_cmd, capture_output=True, text=True)
    require(proc.returncode == 0, f"harness failed to compile:\n{proc.stderr}")

    # ── Build the adversarial real git repo ──────────────────────────────
    evil_root = work / EVIL_SEGMENT
    evil_root.mkdir(parents=True)
    env = dict(os.environ)
    env[CANARY_ENV] = CANARY_VALUE
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_AUTHOR_NAME"] = env["GIT_COMMITTER_NAME"] = "fsv"
    env["GIT_AUTHOR_EMAIL"] = env["GIT_COMMITTER_EMAIL"] = "fsv@example.com"

    def git(*args: str) -> str:
        r = subprocess.run(
            ["git", "-C", str(evil_root), *args], capture_output=True, text=True, env=env
        )
        require(r.returncode == 0, f"git {args} failed in evil repo:\n{r.stderr}")
        return r.stdout.strip()

    git("init", "-q")
    (evil_root / "file.txt").write_text("hello\n", encoding="utf-8")
    git("add", "file.txt")
    git("-c", "commit.gpgsign=false", "commit", "-q", "-m", "seed")

    # SOURCE OF TRUTH #1: the real HEAD sha, read directly from the repo on disk.
    truth_head = git("rev-parse", "HEAD")
    require(len(truth_head) == 40, f"expected a 40-char HEAD sha, got {truth_head!r}")

    print("-- BEFORE --")
    print(f"  repo path on disk : {evil_root}")
    print(f"  path length bytes : {len(str(evil_root).encode('utf-8'))}")
    print(f"  {CANARY_ENV}={CANARY_VALUE}  (defined in child environment)")
    print(f"  truth HEAD (git on disk) : {truth_head}")

    # ── FSV 1: git rev-parse HEAD through cbm_spawn_capture ───────────────
    spawn = subprocess.run(
        [str(harness_bin), "--spawn", "git", "-C", str(evil_root), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        env=env,
    )
    captured_head = spawn.stdout.strip()
    print("-- AFTER: cbm_spawn_capture git rev-parse HEAD --")
    print(f"  spawn stderr trailer : {spawn.stderr.strip()}")
    print(f"  captured HEAD        : {captured_head}")
    require(
        captured_head == truth_head,
        f"captured HEAD {captured_head!r} != on-disk HEAD {truth_head!r} "
        "(the shell-free spawn did not reach the repo at the evil path)",
    )
    require(
        CANARY_VALUE not in spawn.stdout,
        "the canary value appeared in git output — a shell expanded %VAR% (MUST NOT happen)",
    )
    print("  PASS: git resolved the literal evil path; no %VAR% expansion in output")

    # ── FSV 2: argv round-trip through the echoer ────────────────────────
    # These arguments each carry a shell metacharacter class. The echoer prints
    # back exactly what the OS gave it; every element must survive verbatim.
    payload = [
        str(evil_root),            # the whole adversarial path
        "%PATH%",                  # cmd.exe %VAR%
        "!DELAYED!",               # delayed expansion
        "a;b & c | d",             # command separators / pipe
        "a b\tc",                  # spaces + tab (word splitting)
        'quote"inside',            # embedded double quote (backslash rules)
        "trailing\\",             # trailing backslash (CommandLineToArgvW edge)
        "%ASTRO_SPAWN_CANARY%",    # the canary, as a literal argument
    ]
    echo = subprocess.run(
        [str(harness_bin), "--spawn", str(harness_bin), "--echo-argv", *payload],
        capture_output=True,
        text=True,
        env=env,
    )
    lines = [ln for ln in echo.stdout.splitlines() if ln.startswith("ARG[")]
    got = [ln.split("=", 1)[1] for ln in lines]
    print("-- AFTER: argv round-trip through echoer --")
    for i, (want, have) in enumerate(zip(payload, got)):
        status = "ok" if want == have else "MISMATCH"
        print(f"  ARG[{i}] {status}: sent={want!r}  received={have!r}")
    require(
        got == payload,
        f"argv round-trip mismatch:\n  sent    = {payload}\n  received= {got}\n"
        "(a shell re-parsed the arguments — expansion or splitting occurred)",
    )
    require(
        CANARY_VALUE not in echo.stdout,
        "the canary value was expanded into the echoed argv — a shell ran (MUST NOT happen)",
    )
    print("  PASS: every argv element survived byte-for-byte; %ASTRO_SPAWN_CANARY% NOT expanded")

    # ── FSV 3: fail-closed on a non-existent program ─────────────────────
    missing = subprocess.run(
        [str(harness_bin), "--spawn", "definitely-not-a-real-program-xyz"],
        capture_output=True,
        text=True,
        env=env,
    )
    require(
        "CBM_SPAWN_E_EXEC_NOT_FOUND" in missing.stderr,
        f"a missing program must fail closed with CBM_SPAWN_E_EXEC_NOT_FOUND, got:\n{missing.stderr}",
    )
    print("  PASS: missing executable fails closed with CBM_SPAWN_E_EXEC_NOT_FOUND")

    print("CBM spawn FSV passed: shell-free spawn verified against real git + real argv read-back")


if __name__ == "__main__":
    main()
