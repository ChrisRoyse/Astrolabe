# Astrolabe project status

> Snapshot: **2026-07-25T18:03:44Z**. GitHub issues and their comments are the state of record. These files summarize that ledger; they do not replace it.

## The short answer

Astrolabe is an advanced integration and hardening project, not a release-complete product. The single native Rust/C host, identity and vault layers, graph import/lowering, measurement substrate, kernel/guard/oracle foundations, and many MCP surfaces exist. The flagship context-pack path, search non-regression and primary flip, most self-optimization, final security/ecosystem work, and the zero-touch reality-verification loop do not yet meet their issue-level completion criteria.

The best concise progress reading is:

- **61 of 83 core tracker issues are closed (73.5%); 22 remain open.** This is an issue-unit ratio, not a readiness percentage.
- **515 of 696 total issues are closed; 181 are open.** The open ledger includes 120 bugs, 13 critical issues, and 100 high-severity issues.
- **P1, P2, and P5 are closed at the core-tracker level.** P0 has been reopened by a live store-integrity problem; P3/P4/P6/P7/P9 have remaining gates; P8 has only 1 of 11 tracker items closed.
- **`ASTROLABE_DONE` is false.** Completion is a conjunction: a missing grounded, distilled, guarded, predictive, self-optimizing, compatible, provenanced, or honest gate prevents the whole claim.

The project is therefore better described as **foundation largely built, decisive product loop and hardening still underway**. The remaining 26.5% of tracker issue units contains several of the most dependency-heavy capabilities, so “about three quarters of issues closed” must not be read as “about three quarters of calendar time elapsed” or “three quarters release-ready.”

## Snapshot numbers

| View | Reading |
|---|---:|
| All GitHub issues | 696 |
| Closed / open | 515 / 181 |
| Core tracker closed / open | 61 / 22 |
| Open bugs | 120 |
| Open critical / high severity | 13 / 100 |
| Open ingest-area issues | 65 |
| In progress / ready / blocked / needs spec | 87 / 37 / 34 / 1 |
| Open issues with no workflow label | 23 |

Workflow-label counts overlap because [#479](https://github.com/ChrisRoyse/Astrolabe/issues/479) carries both `status:in-progress` and `status:blocked`. Epics and protocol records often intentionally carry no workflow label.

At the repository audit point, `main` and remote `main` both resolved to `07844f1247488d586c93e878bab8dfb8e88304bb`; the checkout was clean, and both `target/` and `.tmp/astrolabe-launcher.lock` were absent. This is source-state context, not build or behavior evidence.

## Read the status set

1. [Desired end state](end-state.md) — what Astrolabe is intended to become and how completion is measured.
2. [What has been delivered](delivered.md) — issue-backed accomplishments, with boundaries around partial work.
3. [Current state](current-state.md) — phase, severity, workflow, and blocker readings at the snapshot cutoff.
4. [Remaining roadmap](roadmap.md) — the dependency-ordered work still required.
5. [Open issue inventory](issue-inventory.md) — every open issue at the cutoff, grouped by milestone.
6. [Method and caveats](methodology.md) — sources, precedence, counting rules, and known inconsistencies.

## Authority and freshness

Use [EPIC #65](https://github.com/ChrisRoyse/Astrolabe/issues/65) for the core dependency spine and project completion predicate, [the live open-issue view](https://github.com/ChrisRoyse/Astrolabe/issues?q=is%3Aissue%20is%3Aopen) for current work, and each issue’s latest comments for implementation/evidence details. The [blueprint](../astrolabe-blueprint.md) is the design plan, not a progress tracker.

Three known ledger/document inconsistencies matter when reading this snapshot:

- [#43](https://github.com/ChrisRoyse/Astrolabe/issues/43) is closed, but its checkbox in #65 was still unchecked at the cutoff. Core counts here use the issue’s actual closed state.
- Milestone descriptions still contain retired CI/test language; correction is tracked in [#721](https://github.com/ChrisRoyse/Astrolabe/issues/721).
- The root README names deleted gate/test scripts; correction is tracked in [#734](https://github.com/ChrisRoyse/Astrolabe/issues/734).

No honest calendar completion estimate can be derived from the ledger. The blueprint’s original 40–59 engineer-week design estimate predates the large correctness, GPU, compression, launcher, and CBM audit backlogs and is not a current forecast.
