---
name: astro-new-issue
description: Files a well-formed ASTROLABE GitHub issue for a discovered problem — correct labels (area/status/sev/type), milestone mapping, Blocked-by/Blocks links, Scope + DoD skeleton with FSV requirements — and links it from the active issue with a telemetry block. Use whenever work reveals a problem, coverage gap, or adjacent improvement outside the current issue's scope. Never expand scope in place; never carry a problem forward silently.
argument-hint: ["short title"]
allowed-tools: Bash(gh issue *), Bash(gh api *)
---

# File a discovered problem

Title seed: `$ARGUMENTS`

## 1. Dedup first

`gh issue list --state all --search "<keywords>" --limit 20` — if it exists, comment new evidence there instead of filing.

## 2. Compose

**Title prefix conventions:** `[bug]` `[build]` `[test]` `[gate]` `[lint]` `[process]` `[hardening]` `[spec]` `[audit-followup]`, plus `[Windows]`/`[Windows GNU]` qualifiers, or `P<phase>.<n>:` for spine work. (`[vendor]` is retired with the vendoring doctrine, #286 — CBM/Calyx changes are ordinary source changes.)

**Body skeleton:**
```markdown
## Problem
<observed behavior, exact commands/output, execution context>

## Evidence
<how it was observed — FSV readback, gate output tail, file:line>

## Root cause (if known)
<first-principles cause; attribution: git log -S / merge-base evidence if pre-existing>

## Scope
<the fix, bounded>

Blocked by: #N (omit if none)
Blocks: #M (omit if none)

## DoD
- [ ] <fix implemented, fail-closed {code, message, remediation} on error paths>
- [ ] <named test/gate proving it, with FSV readback of persisted state>
- [ ] Native gate evidence recorded here; target/ cleaned and verified absent
```

## 3. Labels and milestone

- Exactly one `status:*`: `status:ready` (spec unambiguous, deps met) | `status:blocked` (has open Blocked-by) | `status:needs-spec`.
- `area:*` (one or more): build-ffi, data-model, lens-panel, graph-weave, ingest, assay, grounding, kernel-context, guard, search, oracle, provenance, self-opt, mcp-surface, testing, migration, performance, security.
- Severity for defects: `sev:critical` | `sev:high` | `sev:medium` | `sev:low`. Type: `bug`, `documentation`, `meta:process`, `audit` (2026-07 audit findings only).
- Milestone: the phase the work belongs to (`P0 — Foundations & proof of link` … `P9 — Native steady state & hardening`); leave off for cross-phase/process items.

`gh issue create --title "..." --label "..." --milestone "..." --body-file <file>`

## 4. Link back (mandatory)

On the ACTIVE issue, comment the discovery + link, with telemetry kind `filed` (`filed_issue`, `reason`) per `${CLAUDE_PROJECT_DIR}/.claude/skills/astro-telemetry/references/spec.md`. If the new issue blocks the active one, add the `Blocked by:` line to the active issue body and set `status:blocked` honestly.
