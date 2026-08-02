# Port-phase deferrals — RETIRED (owner directive, 2026-08-01)

**This register is closed. `DEFERRED[ASTRO_PORT_PHASE]` is no longer a valid label and
must not be written into any new issue, DoD clause, comment, or code comment.**

## What changed

The Windows-only scope directive of 2026-07-11 — *"We need to only get this system
running on Windows and no other system… We will port over to all other systems at the
very end"* — is **withdrawn in full**.

ASTROLABE is now **cross-platform with macOS on Apple Silicon as its primary,
evidence-bearing host**. macOS FSV is first-class closure evidence. Windows and Linux
remain supported targets whose platform branches stay in the tree and must not be
deleted, but they no longer gate any DoD.

This register existed for exactly one purpose: to name, count, and track coverage that
was deliberately not being produced *because* non-Windows work was out of scope. With
that scope gone, the deferral has nothing left to defer.

## What replaced it

The doctrine is superseded, not the honesty requirement. Standing invariants 1 and 3
still bind: **no unlabeled claim, and every degradation labeled with every skip
counted.** What changes is only the label and the owner.

| Formerly | Now |
|---|---|
| `DEFERRED[ASTRO_PORT_PHASE]` — "proven on Windows, other platforms deferred" | Either **satisfied by native macOS FSV**, or an **ordinary open gap** on its own issue with a real owner and a real closure condition |
| "Windows-green is not cross-platform-green" | Still true, and now cuts the other way too: macOS-green is not Windows-green. State the host that produced the evidence. |
| Non-Windows evidence has no owner (#238) | Closed by this directive |

A clause whose evidence was deferred is now handled one of two ways, and never a third:

1. **Produce the evidence** natively on macOS and close the clause on it, or
2. **File it as an ordinary gap** — labeled, milestoned, with a named closure condition.

What is still forbidden is what was always forbidden: presenting missing coverage as
passing, silently ticking a clause from an aggregate that never exercised it, or
citing a CI job as an evidence owner (there is no CI — see `CLAUDE.md`).

## Historical note

The three false labels this register was written to prevent remain false, and the
reasoning is preserved here because it is still instructive:

- **"owned by the required CI job"** — hosted CI/CD is banned (owner directive,
  2026-07-11). A CI job cannot own coverage, because none exist.
- **"permanent coverage gap"** — misrepresents a scheduled commitment as an abandoned
  one.
- **"run it on another host to close"** — was false as an *instruction* only while that
  work was deliberately out of scope. It is now simply normal work.

See `docs/deferred-coverage-register.md` for the index of remaining named
`SKIP[...]` / `DEFERRED[...]` tokens, each of which needs its own owner issue now that
the port-phase umbrella is gone.
