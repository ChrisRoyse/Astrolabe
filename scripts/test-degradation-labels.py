#!/usr/bin/env python3
"""Self-tests for the degradation-label gate.

Proves the gate is load-bearing: it must FAIL on each historical false claim
(#224 positive controls) and on an unlabeled port-phase deferral, it must PASS
the honest replacements, and the live tree must be clean. A gate that cannot
fail is not a gate.
"""

from __future__ import annotations

import importlib.util
import shutil
import sys
import tempfile
from pathlib import Path

# Loading the gate by path must not leave a __pycache__ behind in scripts/.
sys.dont_write_bytecode = True


ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts" / "check-degradation-labels.py"

DEFERRAL = (
    'echo "DEFERRED[ASTRO_PORT_PHASE]: deferred to the port phase; tracked in #238."'
)


def load_gate():
    spec = importlib.util.spec_from_file_location("check_degradation_labels", GATE)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


# RULE 1 positive controls: the exact strings that were live before #224.
CI_CLAIMS = (
    "echo \"SKIP[ASTRO_CBM_CLANG_TIDY_LINUX_REQUIRED]: clang-tidy is "
    "platform-dependent; required Linux CI job cbm lint / clang-tidy cppcheck "
    'format owns this gate"',
    'echo "INFO[ASTRO_CBM_CPPCHECK_LINUX_ABI]: cppcheck targets the required '
    'Linux CI unix64 ABI"',
    '"Linux strace coverage is required from CI job portable-gates"',
    "# Sanitizer coverage of the CBM C suite is owned by the required Linux CI jobs.",
    'if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then',
    "# see .github/workflows/portable-gates.yml",
    "# coverage is provided by GitHub Actions",
    "# do not check this locally; wait for CI",
    "# this is enforced by a required status check",
)

# RULE 1 negative controls: the honest replacements shipped by #224.
HONEST = (
    'echo "SKIP[ASTRO_CBM_CLANG_TIDY_LINUX_REQUIRED]: clang-tidy analysis needs a '
    'Linux host; this run has NO clang-tidy coverage."\n' + DEFERRAL,
    "# no gate may claim a CI job as its caller.",
    "# owned by a native run on that platform -- a tracked deferral, never a CI job",
    "echo 'COUNTS[ASTRO_CBM_TESTS] passed=5764 failed=0 skipped=18'",
)


def fixture(root: Path, name: str, body: str) -> None:
    path = root / "scripts" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body + "\n", encoding="utf-8", newline="\n")


def main() -> int:
    gate = load_gate()
    scratch_parent = ROOT / ".tmp"
    scratch_parent_existed = scratch_parent.exists()
    scratch_parent.mkdir(parents=True, exist_ok=True)

    try:
        with tempfile.TemporaryDirectory(
            prefix="degradation-labels-", dir=scratch_parent
        ) as temp:
            root = Path(temp)

            # (a) RULE 1 positive controls: every historical false claim rejected.
            for index, claim in enumerate(CI_CLAIMS):
                probe = root / f"ci-claim-{index}"
                probe.mkdir()
                fixture(probe, "gate.sh", claim)
                if not gate.violations(probe):
                    raise AssertionError(
                        f"gate ACCEPTED a CI-ownership claim it must reject:\n  {claim}"
                    )

            # (b) RULE 1 negative controls: honest labels accepted.
            for index, honest in enumerate(HONEST):
                probe = root / f"honest-{index}"
                probe.mkdir()
                fixture(probe, "gate.sh", honest)
                errors = gate.violations(probe)
                if errors:
                    raise AssertionError(
                        f"gate REJECTED an honest degradation label:\n  {honest}\n"
                        f"  errors: {errors}"
                    )

            # (c) RULE 2 positive control: a platform skip with NO port-phase
            # deferral is exactly the silent-fallback this gate exists to stop.
            probe = root / "unlabeled-deferral"
            probe.mkdir()
            fixture(
                probe,
                "gate.sh",
                'echo "SKIP[ASTRO_EGRESS_LINUX_REQUIRED]: needs Linux strace."',
            )
            errors = gate.violations(probe)
            if not errors:
                raise AssertionError(
                    "gate ACCEPTED a platform skip carrying no "
                    "DEFERRED[ASTRO_PORT_PHASE] classification"
                )
            if "DEFERRED[ASTRO_PORT_PHASE]" not in " ".join(errors):
                raise AssertionError(f"finding did not name the missing token: {errors}")

            # (d) RULE 2 positive control: deferral token present but no issue.
            probe = root / "unissued-deferral"
            probe.mkdir()
            fixture(
                probe,
                "gate.sh",
                'echo "SKIP[ASTRO_EGRESS_LINUX_REQUIRED]: needs Linux strace."\n'
                'echo "DEFERRED[ASTRO_PORT_PHASE]: later."',
            )
            if not gate.violations(probe):
                raise AssertionError(
                    "gate ACCEPTED a port-phase deferral naming no tracking issue"
                )

            # (e) RULE 2 negative control: skip + deferral + issue is accepted.
            probe = root / "labeled-deferral"
            probe.mkdir()
            fixture(
                probe,
                "gate.sh",
                'echo "SKIP[ASTRO_EGRESS_LINUX_REQUIRED]: needs Linux strace."\n'
                + DEFERRAL,
            )
            errors = gate.violations(probe)
            if errors:
                raise AssertionError(
                    f"gate REJECTED a correctly-labeled port-phase deferral: {errors}"
                )

            # (f) Empty tree: no files, no findings, no crash.
            empty = root / "empty"
            empty.mkdir()
            if gate.violations(empty):
                raise AssertionError("gate reported findings on an empty tree")
    finally:
        if not scratch_parent_existed:
            shutil.rmtree(scratch_parent, ignore_errors=True)

    # (g) The live tree is clean. This is what #224 is closed against.
    live = gate.violations(ROOT)
    if live:
        detail = "\n".join(live)
        raise AssertionError(f"live tree carries mislabeled degradations:\n{detail}")

    print(
        f"degradation-label contract passed ({len(CI_CLAIMS)} CI claims rejected, "
        f"{len(HONEST)} honest labels accepted, unlabeled deferrals rejected, "
        "live tree clean)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
