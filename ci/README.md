# `ci/` — local gate configuration (historical name)

**This directory has nothing to do with CI.** There is no CI.

GitHub Actions and every other hosted CI/CD system are **banned** in this
repository (owner directive, 2026-07-11). `.github/` is deleted, there are no
workflows, no required status checks, and no CI jobs — and none may be added.
All verification is local full-state verification: `scripts/check.sh`,
`scripts/check-full.sh`, `scripts/check-release.sh`, the native aggregate via
`scripts/windows-gnu-toolchain.ps1`, and FSV byte readback, run from the
canonical workspace with the output recorded on the driving GitHub issue.

Everything in this directory is **local gate configuration and measured
baselines, consumed by the check scripts.** The `ci/` name — and the `ci-*.sh`
prefix on `scripts/ci-cbm-lint.sh`, `scripts/ci-cbm-test.sh`, and
`scripts/ci-rust-gate.sh` — are historical, from before the ban.

## Rename-or-document decision (#224)

**Decision: document in place, and enforce the ban mechanically.** Rejected:
renaming `ci/` → `gates/` and `ci-*.sh` → `gate-*.sh` in this pass.

Rationale — a rename addresses the *name*, but the defect #224 actually names is
**false ownership claims** ("this skip is owned by the required Linux CI job"). A
rename does not prevent anyone from writing "owned by CI" inside
`gates/gate-cbm-lint.sh` tomorrow; it only makes the lie better-spelled. The
durable fix for a class of false claims is a gate that fails closed when one
reappears, which is what `scripts/check-no-ci-ownership.py` now does (wired into
`scripts/check.sh`, so every aggregate run enforces it).

The rename remains desirable for readability and is worth doing, but it is a
wide mechanical change that touches the check scripts, the Python gates, the
gate-wiring contract, `CLAUDE.md`/`AGENTS.md`, and live GitHub issue bodies that
reference these paths. It must be done as one serialized change, not inside a
parallel fanout where other branches hold diffs against `scripts/ci-cbm-lint.sh`
— a rename there would silently break the merged gate. Tracked as a follow-up.

Until then: **`ci/` is local gate config. It is not GitHub configuration, and no
gate may claim a CI job as its coverage owner.** Platform-limited coverage is
classified `DEFERRED[ASTRO_PORT_PHASE]` and tracked in issue #238
(`docs/port-phase-deferrals.md`) — never a CI-owned skip.

`scripts/check-degradation-labels.py` enforces both rules on every aggregate run.

## Contents

| File | Consumed by | Purpose |
|---|---|---|
| `binary-size-gate.json` | `scripts/check-binary-size.py` | Release binary size ceiling. |
| `cbm-cache-path-offenders.md` | `scripts/check-cbm-cache-paths.py` | Allowlist of CBM cache-path construction sites. |
| `cbm-test-totals.md` | `scripts/ci-cbm-test.sh` | Measured CBM registered-test baseline per platform label. |
| `cli-parity-fixtures.json` | `scripts/check-cli-parity.py` | CLI parity corpus. |
| `compat-shim-fixtures.json` | `scripts/check-compat-shim.py` | Compat-shim parity corpus. |
| `fixtures/` | several gates | Shared fixture inputs. |
| `hazard-suite.json` | `scripts/check-hazard-suite.py` | Hazard suite declarations. |
| `hook-contracts.json` | `scripts/check-hook-contracts.py` | Hook contract corpus. |
| `installer-roundtrip-agents.json` | `scripts/check-installer-roundtrip.py` | Installer roundtrip agents. |
| `known-skips.md` | `scripts/check-cbm-skip-count.sh` | Exact-count platform skip allowlist. |
| `license-notices.json` | `scripts/check-license-notices.py` | Required NOTICE terms. |
| `mcp-parity-corpus.json` | `scripts/check-mcp-parity.py` | MCP parity corpus. |
| `mcp-parity-normalizers.json` | `scripts/check-mcp-parity.py` | Parity normalizers. |
| `redaction-writers.json` | `scripts/check-redaction-writers.py` | Redaction writer allowlist. |
| `shadow-parity-whitelist.json` | `scripts/check-shadow-parity.py` | Shadow parity whitelist. |
| `shadow-parity-dashboard-schema.json` | `scripts/check-shadow-parity.py` | Golden schema for the parity dashboard artifact (`--selftest` validates conformance). |
| `shell-arg-audit.json` | `scripts/check-shell-arg-audit.py` | Shell argument audit allowlist. |
