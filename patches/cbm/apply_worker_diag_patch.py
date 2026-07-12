#!/usr/bin/env python3
"""Generate hash-checked CBM overlays that make a contained index-worker failure
self-describing (#282).

When the supervised index worker dies, the pinned supervisor discards the
worker's ``--response-out`` file (slurped only on a CLEAN outcome) and the
failure response carries only ``{status, outcome, hint, repo_path}`` — no exit
code, no worker evidence. Aggregate attempt 10 (2026-07-12) RED'd at
shadow-parity with exactly that unattributable payload. These overlays:

  src/mcp/index_supervisor.c — slurp the response file on EVERY outcome, not
      only CLEAN. The worker CLI writes ``--response-out`` before exiting
      nonzero, so on failure the file usually holds the worker's true error;
      deleting it unread made contained failures unattributable.

  src/mcp/mcp.c — thread the last failed worker's exit code and response text
      through the recovery loop into ``build_worker_failure_response``, which
      now emits ``worker_exit_code`` and a bounded ``worker_response_tail``
      alongside the generic hint. Containment behavior is unchanged; the
      failure artifact simply carries its own evidence.

``vendor/codebase-memory-mcp`` is byte-pinned and never edited: this script
verifies the reviewed source hash, applies exact textual edits, and writes a
build-local overlay compiled in place of the vendored object (libcbm only —
the upstream parity binary keeps the pinned behavior, and no parity corpus
entry contains a worker-failure response).

``src/mcp/mcp.c`` is already overlaid by ``env_apply_store_patch.py``; this
script therefore supports ``--chained``: the input is the env-store overlay
output (whose bytes legitimately differ from the pin), so the input hash check
is replaced by a hash check of the UNTOUCHED vendored baseline plus the
fail-closed ``replace_once`` anchors themselves.

Usage:
    apply_worker_diag_patch.py --file src/mcp/index_supervisor.c <source> <output>
    apply_worker_diag_patch.py --file src/mcp/mcp.c --chained <envstore_overlay> <output>

Verify with ``python -B scripts/test-cbm-worker-diag-patch.py``. Temporary
integration patch; intended for upstreaming to CBM.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from astro_overlay import replace_once, verify_source_hash  # noqa: E402


EXPECTED_SOURCE_SHA256 = {
    "src/mcp/index_supervisor.c": (
        "0c727860cab54bab78d190c50c4124ba107a063b45e5f7ecb5ac1f68894ef700"
    ),
    "src/mcp/mcp.c": (
        "18a803f3fd93fd2269e3f1198cd65587e707df8c415970b9dd6121f45e63d234"
    ),
}


SUPERVISOR_SLURP_OLD = """    result->outcome = r.outcome;
    result->exit_code = r.exit_code;
    result->term_signal = r.term_signal;
    if (r.outcome == CBM_PROC_CLEAN) {
        result->response = slurp_file(resp_path);
    }
    (void)remove(resp_path);
"""

SUPERVISOR_SLURP_NEW = """    result->outcome = r.outcome;
    result->exit_code = r.exit_code;
    result->term_signal = r.term_signal;
    /* #282: slurp the response file on EVERY outcome, not only CLEAN. The
     * worker CLI writes --response-out before exiting nonzero, so on failure
     * this file usually carries the worker's true error (e.g. the exact
     * isError text). Discarding it unread made contained failures
     * unattributable — the supervisor deleted the one artifact that named the
     * defect. */
    result->response = slurp_file(resp_path);
    (void)remove(resp_path);
"""

MCP_SIGNATURE_OLD = (
    "static char *build_worker_failure_response(const char *args, "
    "cbm_proc_outcome_t outcome) {\n"
)

MCP_SIGNATURE_NEW = """/* #282: bound on the worker-response excerpt embedded in the failure JSON. A
 * response is normally a short error result; the tail keeps the terminal error
 * text if something ever writes more. */
enum { CBM_WORKER_RESPONSE_TAIL_MAX = 2048 };

static char *build_worker_failure_response(const char *args, cbm_proc_outcome_t outcome,
                                           int exit_code, const char *worker_response) {
"""

MCP_FIELDS_OLD = """              "survived). Re-run to retry; a future release isolates the culprit file.");
    if (repo_path) {
"""

MCP_FIELDS_NEW = """              "survived). Re-run to retry; a future release isolates the culprit file.");
    /* #282: carry the worker's own evidence so a contained failure is
     * attributable from this artifact alone. */
    yyjson_mut_obj_add_int(doc, root, "worker_exit_code", exit_code);
    if (worker_response && worker_response[0]) {
        size_t wr_len = strlen(worker_response);
        const char *wr_tail = wr_len > CBM_WORKER_RESPONSE_TAIL_MAX
                                  ? worker_response + (wr_len - CBM_WORKER_RESPONSE_TAIL_MAX)
                                  : worker_response;
        yyjson_mut_obj_add_strcpy(doc, root, "worker_response_tail", wr_tail);
    }
    if (repo_path) {
"""

MCP_INITIAL_CAPTURE_OLD = """    cbm_proc_outcome_t last_outcome = wr.outcome;
    cbm_index_worker_result_free(&wr);
"""

MCP_INITIAL_CAPTURE_NEW = """    cbm_proc_outcome_t last_outcome = wr.outcome;
    int last_exit_code = wr.exit_code;
    char *last_response = wr.response; /* #282: keep the worker's evidence */
    wr.response = NULL;
    cbm_index_worker_result_free(&wr);
"""

MCP_SPAWNFAIL_CAPTURE_OLD = """        if (rc2 != 0) {
            last_outcome = wr2.outcome;
            cbm_index_worker_result_free(&wr2);
            break; /* spawn failed mid-recovery — give up */
"""

MCP_SPAWNFAIL_CAPTURE_NEW = """        if (rc2 != 0) {
            last_outcome = wr2.outcome;
            last_exit_code = wr2.exit_code;
            free(last_response);
            last_response = wr2.response; /* #282 */
            wr2.response = NULL;
            cbm_index_worker_result_free(&wr2);
            break; /* spawn failed mid-recovery — give up */
"""

MCP_CRASHHANG_CAPTURE_OLD = """        if (wr2.outcome == CBM_PROC_CRASH || wr2.outcome == CBM_PROC_HANG) {
            last_outcome = wr2.outcome;
            cbm_index_worker_result_free(&wr2);
"""

MCP_CRASHHANG_CAPTURE_NEW = """        if (wr2.outcome == CBM_PROC_CRASH || wr2.outcome == CBM_PROC_HANG) {
            last_outcome = wr2.outcome;
            last_exit_code = wr2.exit_code;
            free(last_response);
            last_response = wr2.response; /* #282 */
            wr2.response = NULL;
            cbm_index_worker_result_free(&wr2);
"""

MCP_NONZERO_CAPTURE_OLD = """        /* SPAWN_FAILED / nonzero exit / non-fault kill → not a crash we can
         * attribute; stop and report a contained failure. */
        last_outcome = wr2.outcome;
        cbm_index_worker_result_free(&wr2);
        break;
"""

MCP_NONZERO_CAPTURE_NEW = """        /* SPAWN_FAILED / nonzero exit / non-fault kill → not a crash we can
         * attribute; stop and report a contained failure. */
        last_outcome = wr2.outcome;
        last_exit_code = wr2.exit_code;
        free(last_response);
        last_response = wr2.response; /* #282 */
        wr2.response = NULL;
        cbm_index_worker_result_free(&wr2);
        break;
"""

MCP_TAIL_OLD = """    if (resp) {
        return resp;
    }
    return build_worker_failure_response(args, last_outcome);
}
"""

MCP_TAIL_NEW = """    if (resp) {
        free(last_response);
        return resp;
    }
    char *failure =
        build_worker_failure_response(args, last_outcome, last_exit_code, last_response);
    free(last_response);
    return failure;
}
"""


def patch_index_supervisor(source: str) -> str:
    return replace_once(
        source,
        SUPERVISOR_SLURP_OLD,
        SUPERVISOR_SLURP_NEW,
        "supervisor always-slurp (#282)",
    )


def patch_mcp(source: str) -> str:
    source = replace_once(source, MCP_SIGNATURE_OLD, MCP_SIGNATURE_NEW, "failure-response signature (#282)")
    source = replace_once(source, MCP_FIELDS_OLD, MCP_FIELDS_NEW, "failure-response fields (#282)")
    source = replace_once(source, MCP_INITIAL_CAPTURE_OLD, MCP_INITIAL_CAPTURE_NEW, "initial capture (#282)")
    source = replace_once(source, MCP_SPAWNFAIL_CAPTURE_OLD, MCP_SPAWNFAIL_CAPTURE_NEW, "spawn-fail capture (#282)")
    source = replace_once(source, MCP_CRASHHANG_CAPTURE_OLD, MCP_CRASHHANG_CAPTURE_NEW, "crash-hang capture (#282)")
    source = replace_once(source, MCP_NONZERO_CAPTURE_OLD, MCP_NONZERO_CAPTURE_NEW, "nonzero-exit capture (#282)")
    source = replace_once(source, MCP_TAIL_OLD, MCP_TAIL_NEW, "failure-response call site (#282)")
    return source


PATCHED_FILES = {
    "src/mcp/index_supervisor.c": patch_index_supervisor,
    "src/mcp/mcp.c": patch_mcp,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", required=True, choices=sorted(PATCHED_FILES))
    parser.add_argument(
        "--chained",
        action="store_true",
        help=(
            "input is a prior overlay's output (env-store mcp.c); verify the "
            "vendored baseline hash instead of the input hash"
        ),
    )
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    source_text = args.source.read_text(encoding="utf-8")
    expected = EXPECTED_SOURCE_SHA256[args.file]
    if args.chained:
        # The input already carries another reviewed overlay; the pinned
        # baseline must still be the reviewed bytes, and replace_once fails
        # closed on any anchor drift the prior overlay could introduce.
        baseline = Path(args.file).read_text(encoding="utf-8")
        verify_source_hash(baseline, expected, f"{args.file} (vendored baseline)")
    else:
        verify_source_hash(source_text, expected, args.file)
    patched = PATCHED_FILES[args.file](source_text)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(patched, encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
