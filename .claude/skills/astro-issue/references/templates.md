# Issue comment templates

All telemetry blocks are single-line minified JSON per `.claude/skills/astro-telemetry/references/spec.md`.

## Claim

```markdown
Claiming. <one sentence: what this session will do.>

Plan:
- <bullet 1>
- <bullet 2 (≤5 total)>

```json astro-telemetry
{"v":1,"kind":"claim","ts":"<UTC ISO-8601>","session":"<session-id>","issue":<N>,"next":"<first concrete step>"}
```
```

## Progress / evidence (DoD box)

```markdown
DoD item: "<checkbox text>" — VERIFIED.

Command (native, from C:/code/Astrolabe):
    <exact command>
Result tail:
    <last ~10 lines>

```json astro-telemetry
{"v":1,"kind":"evidence","ts":"...","session":"...","issue":<N>,"cmd":"<command>","exit":0,"evidence":["<test name>: <result>","<source-of-truth readback: what was read, what it contained>"]}
```
```

## Close

```markdown
Closing. All DoD boxes checked with evidence in this thread.

Gates (native, C:/code/Astrolabe):
    <command>
    <output tail incl. final PASS/counts>

Post-close: commit <sha> pushed; target/ verified absent.

```json astro-telemetry
{"v":1,"kind":"close","ts":"...","session":"...","issue":<N>,"cmd":"<gate command>","exit":0,"gates":{"<gate>":"PASS"},"evidence":["commit <sha> pushed","target absent"]}
```
```

## Early stop (handoff)

See astro-handoff — it owns this template (kind `handoff`).
