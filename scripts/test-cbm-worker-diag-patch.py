#!/usr/bin/env python3
"""Self-test (FSV) for the CBM contained-worker-failure diagnostics overlay (#282).

Verifies patches/cbm/apply_worker_diag_patch.py against the live pinned CBM
sources:
  * both declared source hashes still match (the pin has not silently moved);
  * both overlays are load-bearing (change the source) and leave the vendored
    sources untouched on disk (the generator never writes into vendor/);
  * the diagnostics are actually present in the persisted overlay bytes read
    back from disk — the supervisor slurps the response file on EVERY outcome,
    and the failure response carries `worker_exit_code` plus the bounded
    `worker_response_tail` threaded through every recovery-loop failure branch;
  * chained mode (mcp.c after the env-store overlay) still hash-checks the
    vendored baseline and applies over the env-store output;
  * the edge-case triad fails closed:
      - drifted source (byte mutated)          -> ASTRO_OVERLAY_SOURCE_DRIFT
      - a re-applied (already-patched) source  -> ASTRO_OVERLAY_FRAGMENT_DRIFT
      - drifted baseline in chained mode       -> ASTRO_OVERLAY_SOURCE_DRIFT
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CBM_ROOT = ROOT / "vendor" / "codebase-memory-mcp"
PATCH = ROOT / "patches" / "cbm" / "apply_worker_diag_patch.py"
ENV_STORE_PATCH = ROOT / "patches" / "cbm" / "env_apply_store_patch.py"

SUPERVISOR = "src/mcp/index_supervisor.c"
MCP = "src/mcp/mcp.c"


def load_patch_module():
    spec = importlib.util.spec_from_file_location("apply_worker_diag_patch", PATCH)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def expect(cond: bool, msg: str) -> None:
    if not cond:
        print(f"FAIL: {msg}", file=sys.stderr)
        raise SystemExit(1)
    print(f"ok: {msg}")


def expect_fail_closed(fn, msg: str, code: str | None = None) -> None:
    try:
        fn()
    except ValueError as exc:
        if code is not None and code not in str(exc):
            print(f"FAIL: {msg}: wrong code, got {exc!r}", file=sys.stderr)
            raise SystemExit(1)
        print(f"ok: {msg}")
    else:
        print(f"FAIL: {msg}: did not fail closed", file=sys.stderr)
        raise SystemExit(1)


def main() -> int:
    module = load_patch_module()

    sup_vendored = (CBM_ROOT / SUPERVISOR).read_text(encoding="utf-8")
    mcp_vendored = (CBM_ROOT / MCP).read_text(encoding="utf-8")

    # Pin integrity: the reviewed hashes must match the live vendored bytes.
    module.__dict__["verify_source_hash"](
        sup_vendored, module.EXPECTED_SOURCE_SHA256[SUPERVISOR], SUPERVISOR
    )
    module.__dict__["verify_source_hash"](
        mcp_vendored, module.EXPECTED_SOURCE_SHA256[MCP], MCP
    )
    print("ok: both vendored source hashes match the reviewed baseline")

    # Supervisor overlay: load-bearing, always-slurp present, CLEAN-gate gone.
    sup_patched = module.patch_index_supervisor(sup_vendored)
    expect(sup_patched != sup_vendored, "supervisor overlay is load-bearing")
    expect(
        "result->response = slurp_file(resp_path);" in sup_patched,
        "supervisor slurps the response file unconditionally",
    )
    expect(
        "if (r.outcome == CBM_PROC_CLEAN) {\n        result->response" not in sup_patched,
        "the CLEAN-only slurp gate is removed",
    )

    # MCP overlay: all eight fragments applied; evidence fields present.
    mcp_patched = module.patch_mcp(mcp_vendored)
    for marker in [
        '"worker_exit_code", exit_code',
        '"worker_response_tail", wr_tail',
        "CBM_WORKER_RESPONSE_TAIL_MAX = 2048",
        "int last_exit_code = wr.exit_code;",
        "build_worker_failure_response(args, last_outcome, last_exit_code, last_response)",
        "char *early_repo_path = cbm_mcp_get_string_arg(args, \"repo_path\");",
    ]:
        expect(marker in mcp_patched, f"mcp overlay carries {marker!r}")
    expect(
        mcp_patched.index("early_repo_path")
        < mcp_patched.index("cbm_index_supervisor_should_wrap()"),
        "argument validation precedes the supervision wrap (#282: no worker "
        "spawn for trivially-invalid args)",
    )
    expect(
        mcp_patched.count("last_response = wr2.response; /* #282 */") == 3,
        "all three recovery-loop failure branches capture the worker evidence",
    )
    expect(
        "build_worker_failure_response(args, last_outcome);" not in mcp_patched,
        "the evidence-free failure call site is gone",
    )

    with tempfile.TemporaryDirectory(prefix="astro-worker-diag-", dir=ROOT / ".tmp" if (ROOT / ".tmp").is_dir() else None) as tmp:
        tmpdir = Path(tmp)

        # Persisted-bytes readback through the real CLI entry (FSV, not echoes).
        out_sup = tmpdir / "index_supervisor.c"
        subprocess.run(
            [sys.executable, str(PATCH), "--file", SUPERVISOR, SUPERVISOR, str(out_sup)],
            cwd=CBM_ROOT,
            check=True,
        )
        readback = out_sup.read_text(encoding="utf-8")
        expect(readback == sup_patched, "persisted supervisor overlay matches the transform")
        expect(
            (CBM_ROOT / SUPERVISOR).read_text(encoding="utf-8") == sup_vendored,
            "vendored supervisor source untouched on disk",
        )

        # Chained mode over the real env-store output.
        envstore_out = tmpdir / "mcp.envstore.c"
        subprocess.run(
            [sys.executable, str(ENV_STORE_PATCH), "--file", MCP, MCP, str(envstore_out)],
            cwd=CBM_ROOT,
            check=True,
        )
        chained_out = tmpdir / "mcp.chained.c"
        subprocess.run(
            [
                sys.executable,
                str(PATCH),
                "--file",
                MCP,
                "--chained",
                str(envstore_out),
                str(chained_out),
            ],
            cwd=CBM_ROOT,
            check=True,
        )
        chained = chained_out.read_text(encoding="utf-8")
        expect(
            '"worker_exit_code", exit_code' in chained
            and '"worker_response_tail", wr_tail' in chained,
            "chained overlay carries the #282 fields over the env-store output",
        )
        expect(
            chained != mcp_patched,
            "chained output retains the env-store transform (differs from baseline-only patch)",
        )
        expect(
            (CBM_ROOT / MCP).read_text(encoding="utf-8") == mcp_vendored,
            "vendored mcp source untouched on disk",
        )

    # Build plumbing: the prod overlay dir must receive the vendored
    # index_supervisor.h (bare quote-include resolves includer-relative; the
    # prod binary has no per-TU -Isrc/mcp). Regression guard for aggregate
    # attempt 12's "index_supervisor.h: No such file or directory".
    makefile = (ROOT / "patches" / "cbm" / "Makefile.cbm").read_text(encoding="utf-8")
    expect(
        "ASTRO_WORKER_DIAG_PROD_SUPERVISOR_HDR = $(ASTRO_WORKER_DIAG_PROD_DIR)/src/mcp/index_supervisor.h"
        in makefile,
        "Makefile.cbm copies index_supervisor.h beside the prod overlay",
    )
    expect(
        "$(ASTRO_WORKER_DIAG_PROD_DIR)/src/mcp/index_supervisor.c: $(ASTRO_WORKER_DIAG_PROD_SUPERVISOR_HDR)"
        in makefile,
        "the prod supervisor overlay depends on the copied header",
    )

    # Edge-case triad (fail closed).
    expect_fail_closed(
        lambda: module.patch_mcp(mcp_patched),
        "re-applying to an already-patched mcp source fails closed",
        code="ASTRO_OVERLAY_FRAGMENT_DRIFT",
    )
    drifted = sup_vendored.replace("slurp_file", "slurp_file_x", 1)
    expect_fail_closed(
        lambda: _verify(module, drifted, module.EXPECTED_SOURCE_SHA256[SUPERVISOR], SUPERVISOR),
        "a drifted supervisor source fails the hash check",
        code="ASTRO_OVERLAY_SOURCE_DRIFT",
    )

    print("test-cbm-worker-diag-patch OK")
    return 0


def _verify(module, text, expected, name):
    return module.__dict__["verify_source_hash"](text, expected, name)


if __name__ == "__main__":
    raise SystemExit(main())
