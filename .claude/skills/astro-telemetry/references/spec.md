# astro-telemetry/v1 — block specification

## Contents
1. [Placement and encoding](#placement-and-encoding)
2. [Common fields](#common-fields)
3. [Kinds and required keys](#kinds-and-required-keys)
4. [Field semantics](#field-semantics)
5. [Query recipes](#query-recipes)
6. [Versioning](#versioning)

## Placement and encoding

- Lives only inside GitHub issue/PR comments (or issue bodies), as a fenced code block whose info string is exactly `json astro-telemetry`.
- The JSON object is minified on a **single line** (enables `grep -A1 'json astro-telemetry' | grep '^{'`).
- One block per comment. The human-readable prose around it remains the primary record; the block is the machine index of the same facts — they must agree.
- Honesty: a field you did not measure is omitted, never guessed. `exit` is the real exit code; `gates` values are the literal printed verdicts.

## Common fields

| Key | Type | Req | Meaning |
|---|---|---|---|
| `v` | int | yes | Always `1`. |
| `kind` | string | yes | One of the kinds below. |
| `ts` | string | yes | UTC ISO-8601, e.g. `2026-07-11T18:00:00Z`. |
| `session` | string | yes | Claude session id (`${CLAUDE_SESSION_ID}`) or another stable session tag. |
| `issue` | int | yes | Issue number the block is about (the one it is posted on, except `filed`). |

## Kinds and required keys

| kind | Additional required keys | When |
|---|---|---|
| `claim` | `next` | On claiming an issue (astro-issue §2). |
| `evidence` | `cmd`, `exit`, `evidence[]` | Each DoD item verified; each FSV readback. |
| `gate` | `cmd`, `exit`, `gates{}` | Each aggregate/named gate run (astro-gate). |
| `close` | `cmd`, `exit`, `gates{}`, `evidence[]` | Closing comment. |
| `handoff` | `done[]`, `not_done[]`, `next`, `uncommitted` | Early stop / pause (astro-handoff). |
| `filed` | `filed_issue`, `reason` | Posted on the ACTIVE issue when a discovered problem is filed (astro-new-issue). `issue` = active issue, `filed_issue` = new one. |
| `fanout` | `wave`, `agents`, `results{}` | Orchestrator summary of a parallel wave (astro-fanout). |

## Field semantics

- `cmd` — exact command line, with the execution context implied by doctrine (native Windows, cwd `C:/code/Astrolabe`); note deviations in prose.
- `exit` — integer exit code of `cmd`. For bash pipelines capture `${PIPESTATUS[0]}`, not the pipe tail.
- `evidence[]` — short strings, each naming a real observation: test name + result, or a source-of-truth readback ("sqlite: 42 rows in lens_s0 after import").
- `gates{}` — map of gate name → literal verdict: `PASS`, `FAIL`, `SKIP[CODE]`, `DEFERRED[CODE]`, `INFO[CODE]`. `SKIP`/`DEFERRED` are never passing evidence.
- `done[]` / `not_done[]` — handoff: verified-done items vs remaining; unverified work belongs in `not_done` with a note.
- `uncommitted` — handoff: summary of `git status --short` (or `"clean"`).
- `next` — the single next concrete step.
- Optional anywhere: `commit` (sha), `branch`, `notes`.

## Query recipes

```bash
# All telemetry on one issue, time-ordered
gh issue view N --comments | grep -A1 'json astro-telemetry' | grep '^{' | jq -s 'sort_by(.ts)'

# Gate history for an issue (which gates ran, verdicts)
gh issue view N --comments | grep -A1 'json astro-telemetry' | grep '^{' \
  | jq -s '[.[] | select(.gates) | {ts, cmd, gates}]'

# Latest handoff (resume point) on an issue
gh issue view N --comments | grep -A1 'json astro-telemetry' | grep '^{' \
  | jq -s '[.[] | select(.kind=="handoff")] | max_by(.ts)'

# Everything a given session touched (issue numbers), repo-wide
gh search issues --repo ChrisRoyse/Astrolabe --match comments "<session-id>" --json number,title

# Open state snapshot
gh issue list --state open --json number,title,labels,milestone --limit 300 \
  | jq '[group_by(.milestone.title)[] | {milestone: .[0].milestone.title, count: length}]'
```

## Versioning

Breaking schema changes bump `v` and this file gains a new section; readers must tolerate unknown keys at the same `v`.
