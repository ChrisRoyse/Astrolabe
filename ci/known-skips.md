# Known Skips (exact-count allowlist)

This file is the exact-count allowlist for platform-specific skips in the local
gate. The CBM C harness must report exactly the count recorded for its platform
label; both added and removed skips fail.

There is no hosted CI (GitHub Actions and all hosted CI/CD are banned, owner
directive 2026-07-11). The labels below name a **local gate run on a host of
that platform**, not a CI job.

Astrolabe is **Windows-only scope** until the system is fully operational on
native Windows; other platforms are a scheduled port phase at the end (owner
directive, 2026-07-11). Only `windows-x64-mingw` is exercised today. The other
rows are the counts a native run on that platform is expected to produce; they
are **unproven and `DEFERRED[ASTRO_PORT_PHASE]`**, tracked in issue #238 (see
`docs/port-phase-deferrals.md`). They are retained as the port-phase baseline —
never as evidence that those platforms pass.

Calyx does not whitelist platform skips; manual FSV, GPU, and aiwonder-only
tests remain upstream `#[ignore]` tests and are documented in
`vendor/calyx/docs/systemspecs/18_test_suite.md`.

| System | Gate label | Expected skip count | Whitelisted skip class | Source |
|---|---|---:|---|---|
| CBM | linux-x64-gcc | 1 | Windows-only socket handle inheritance guard. | `vendor/codebase-memory-mcp/tests/test_httpd.c` |
| CBM | linux-x64-clang | 1 | Windows-only socket handle inheritance guard. | `vendor/codebase-memory-mcp/tests/test_httpd.c` |
| CBM | macos-arm64-clang | 1 | Windows-only socket handle inheritance guard. | `vendor/codebase-memory-mcp/tests/test_httpd.c` |
| CBM | windows-x64-mingw | 18 | POSIX-only CLI lookup (2), git-context (3), symlink (1), Cypher isolation (1), HTTP isolation (1), MCP isolation/path (4), subprocess (5), and UI isolation (1) guards. | `vendor/codebase-memory-mcp/tests/` |
