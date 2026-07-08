# CI Known Skips

This file is the whitelist for platform-specific skips in the three-platform CI
gate. Any runtime skip reported by the CBM C harness must be represented here by
platform label. Calyx ordinary CI does not whitelist platform skips; manual FSV,
GPU, and aiwonder-only tests remain upstream `#[ignore]` tests and are documented
in `vendor/calyx/docs/systemspecs/18_test_suite.md`.

| System | CI label | Whitelisted skip class | Source |
|---|---|---|---|
| CBM | linux-x64-gcc | Windows-only socket handle inheritance guard; platform-only skip is reported by the harness. | `vendor/codebase-memory-mcp/tests/test_httpd.c` |
| CBM | linux-x64-clang | Windows-only socket handle inheritance guard; platform-only skip is reported by the harness. | `vendor/codebase-memory-mcp/tests/test_httpd.c` |
| CBM | macos-arm64-clang | Windows-only socket handle inheritance guard; platform-only skip is reported by the harness. | `vendor/codebase-memory-mcp/tests/test_httpd.c` |
| CBM | windows-x64-mingw | POSIX-only fork/alarm, shell-spawn, symlink, canonical-root, and supervisor isolation guards; platform-only skips are reported by the harness. | `vendor/codebase-memory-mcp/tests/` |
