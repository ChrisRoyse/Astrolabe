# CI Known Skips

This file is the exact-count allowlist for platform-specific skips in the
three-platform CI gate. The CBM C harness must report exactly the count recorded
for its platform label; both added and removed skips fail. Calyx ordinary CI does
not whitelist platform skips; manual FSV, GPU, and aiwonder-only tests remain
upstream `#[ignore]` tests and are documented in
`vendor/calyx/docs/systemspecs/18_test_suite.md`.

| System | CI label | Expected skip count | Whitelisted skip class | Source |
|---|---|---:|---|---|
| CBM | linux-x64-gcc | 1 | Windows-only socket handle inheritance guard. | `vendor/codebase-memory-mcp/tests/test_httpd.c` |
| CBM | linux-x64-clang | 1 | Windows-only socket handle inheritance guard. | `vendor/codebase-memory-mcp/tests/test_httpd.c` |
| CBM | macos-arm64-clang | 1 | Windows-only socket handle inheritance guard. | `vendor/codebase-memory-mcp/tests/test_httpd.c` |
| CBM | windows-x64-mingw | 18 | POSIX-only CLI lookup (2), git-context (3), symlink (1), Cypher isolation (1), HTTP isolation (1), MCP isolation/path (4), subprocess (5), and UI isolation (1) guards. | `vendor/codebase-memory-mcp/tests/` |
