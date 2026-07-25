# Method and caveats

## Authority order

This status set uses the repository’s required authority model:

1. GitHub issue state, bodies, and comments are the project-state record.
2. The [operating manual](../../CLAUDE.md) and [agent context](../../AGENTS.md) define current execution and verification doctrine.
3. [EPIC #65](https://github.com/ChrisRoyse/Astrolabe/issues/65) defines the core dependency spine and project completion predicate.
4. The [blueprint](../astrolabe-blueprint.md) and [Calyx handbook](../BUILDING_ON_CALYX.md) define architecture/design doctrine, not progress.
5. The live source tree is used to confirm structural facts such as workspace layout and declared tool surfaces. Source inspection alone is not behavior evidence.

Later owner directives and issue decisions supersede older blueprint or issue wording. Examples include manual-FSV-only/no-tests, Windows-first port deferral, first-class ownership of both parent trees, and the Calyx-native information-home direction.

## Snapshot procedure

The issue inventory and counts were sampled from `ChrisRoyse/Astrolabe` at **2026-07-25T18:03:44Z** using GitHub CLI issue metadata for all open and closed issues. The audit also read:

- all current operating instructions;
- repository layout, root/workspace manifests, server modules/tool definitions, recent Git history, and the relevant design sections;
- milestone descriptions/counts;
- the full #65 structure and its comment index;
- bodies and recent progress/blocker comments for core open issues;
- ownership EPIC [#286](https://github.com/ChrisRoyse/Astrolabe/issues/286), kernel-farming EPIC [#461](https://github.com/ChrisRoyse/Astrolabe/issues/461), Calyx-native-home EPIC [#504](https://github.com/ChrisRoyse/Astrolabe/issues/504), protocol [#139](https://github.com/ChrisRoyse/Astrolabe/issues/139), and audit [#140](https://github.com/ChrisRoyse/Astrolabe/issues/140).

No build or product behavior was run for this documentation audit. That would require a separate issue-bound native launcher batch and would prove only the exercised behavior, not the whole project. Repository state was inspected read-only; the status files themselves are manually read back under [#732](https://github.com/ChrisRoyse/Astrolabe/issues/732).

## Counting rules

- “All issues” means GitHub issues returned by `gh issue list`, not pull requests.
- Closed/open counts are issue states at the cutoff.
- Core phase counts are the 83 numbered issue entries in #65, mapped to each referenced issue’s actual state.
- Milestone counts include every issue assigned to that milestone, including discovered bugs and extensions not present in #65.
- Labels are counted independently. One issue can contribute to several area counts and, when the ledger is inconsistent, more than one workflow count.
- Issue counts are unweighted. A one-line documentation defect and a multi-month product umbrella each count as one.
- An open issue can contain substantial landed partial work; a closed issue establishes only its own scope.

These rules are why 73.5% core issue closure and 74.0% total issue closure are descriptive ratios, not completion forecasts.

## Known inconsistencies preserved

- #65 had [#43](https://github.com/ChrisRoyse/Astrolabe/issues/43) unchecked although #43 is closed. This status set uses the issue state and calls out the mismatch.
- [#479](https://github.com/ChrisRoyse/Astrolabe/issues/479) had both `status:in-progress` and `status:blocked`; both are counted.
- Twenty-three open issues had no `status:*` label. Many are epics/protocol records; others should be read individually.
- Milestone descriptions still carry obsolete test/CI language, tracked by [#721](https://github.com/ChrisRoyse/Astrolabe/issues/721). They were used for grouping/counts, not current verification doctrine.
- The root README still names deleted verification paths, tracked by [#734](https://github.com/ChrisRoyse/Astrolabe/issues/734).
- The `Port — cross-platform (deferred)` milestone has zero assigned issues. [#238](https://github.com/ChrisRoyse/Astrolabe/issues/238) closed after recording the deferral doctrine/register; the actual future port is neither started nor complete.
- EPIC [#286](https://github.com/ChrisRoyse/Astrolabe/issues/286) remains open with stale-looking unchecked mechanics even though the current tree and manual establish top-level first-class ownership. The status documents describe the visible delivered ownership model and preserve the epic’s open state.

## Historical evidence caution

Many early issue comments cite tests, gate scripts, or hosted-automation-era language. The owner’s later manual-FSV-only directive supersedes those methods. This audit does not retroactively re-open every closed issue or pretend to have re-verified 515 closures; it reports the GitHub states and clearly separates current open product truth from historical evidence language.

## Refreshing this snapshot

Do not edit these files as the primary way to change project state. Update the relevant GitHub issue first. A later status refresh should:

1. choose and record a new UTC cutoff;
2. re-read the operating manual, #65, active issue comments, milestone metadata, and live Git state;
3. regenerate the full open-issue inventory;
4. reconcile core issue references against actual issue states;
5. update narrative conclusions only when supported by issue evidence; and
6. preserve prior snapshots in Git history rather than treating prose as authority.
