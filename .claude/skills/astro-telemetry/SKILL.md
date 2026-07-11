---
name: astro-telemetry
description: Machine-readable agent telemetry for ASTROLABE — the astro-telemetry/v1 JSON block format posted in GitHub issue comments, and gh/jq recipes to reconstruct project state (done, in flight, blocked, gate history, handoffs) from the tracker. Use when posting claim/evidence/gate/close/handoff/filed comments, auditing what previous sessions did, or answering "what is the current project state / what happened on issue N".
---

# Agent telemetry

GitHub issues are the only durable state store. Telemetry is therefore structured **issue-comment blocks**, never local log files (workspace outputs are wiped; local logs violate the evidence-stream rule).

## Writing

Every state-changing comment (claim, DoD evidence, gate run, close, handoff, filed-issue link) embeds exactly one fenced block:

````markdown
```json astro-telemetry
{"v":1,"kind":"evidence","ts":"2026-07-11T18:00:00Z","session":"<id>","issue":123,"cmd":"cargo test -p astrolabe-panel","exit":0,"evidence":["panel_s0_fsv: ok","sqlite readback: 42 rows in lens_s0"]}
```
````

Rules:
- JSON is **minified, single line** — this is what makes it greppable.
- Never fabricate fields; omit what you did not measure. `exit` is the real process exit code.
- Full schema, required keys per kind, and validation rules: [references/spec.md](references/spec.md).

## Reading (state reconstruction)

- Open state: `gh issue list --state open --json number,title,labels,milestone --limit 300`
- One issue's history: `gh issue view N --comments`
- All telemetry blocks on an issue:
  `gh issue view N --comments | grep -A1 'json astro-telemetry' | grep '^{' | jq -s 'sort_by(.ts)'`
- Cross-issue sweep (recent sessions): `gh search issues --repo ChrisRoyse/Astrolabe --match comments "astro-telemetry" --limit 50`

More recipes (per-kind filters, gate-history extraction, EPIC #65 reconciliation): [references/spec.md](references/spec.md).
