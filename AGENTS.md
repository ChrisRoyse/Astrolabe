# Astrolabe Agent Context

`CLAUDE.md` is the repository operating manual and must be read before doing any work. GitHub issues are the state of record.

The execution boundary is non-negotiable:

- Work only from the canonical checkout at `C:\code\Astrolabe`.
- Use native Windows processes only. Never invoke WSL, `wsl.exe`, a WSL distribution, `C:\Windows\System32\bash.exe`, or `/mnt/c/...` paths.
- WSL is not part of this development environment. Do not install, start, invoke, or retain WSL services or processes for this project. Before handoff, verify `WSLService`, `wsl`, `wslhost`, and `vmmemWSL` are absent; when WSL removal is explicitly requested, use native Windows management tools to stop, disable, or uninstall it and record any permission or host-level blocker in GitHub.
- Native Git for Windows Bash is allowed only when a repository POSIX script requires it; verify the executable resolves under `C:\Program Files\Git\`, not Windows System32.
- Run native Cargo, C build, and aggregate commands through `scripts\\windows-gnu-toolchain.ps1`; it pins the matching GNU runtime and LLVM analysis tools, confines temporary files to a launcher-owned workspace child, and removes that child and `target/` on exit.
- The launcher builds the pinned Cppcheck 2.20.0 source commit with its matching GNU compiler and retains only the active launcher-managed Cppcheck cache root.
- CBM format validation uses the hash-checked temporary overlay in `patches/cbm`; never run an in-place formatter or patch against either vendor tree.
- On non-Linux hosts, blocking Cppcheck targets `unix64` and emits `INFO[ASTRO_CBM_CPPCHECK_LINUX_ABI]` to match the required Linux CI ABI; native runtime suites still own Windows behavior.
- On non-Linux native aggregates, `SKIP[ASTRO_CBM_CLANG_TIDY_LINUX_REQUIRED]` means the required Linux `cbm lint / clang-tidy cppcheck format` CI job owns clang-tidy; it is not local analyzer-pass evidence. The other CBM lint gates still run.
- Keep repository-controlled outputs inside the workspace, normally in `target/`.
- Delete `C:\code\Astrolabe\target` after every build/test/check batch, including failure or interruption, and verify it is absent before any pause, stop, issue close, turn end, or handoff.
- `scripts/check-full.sh` bounds its workspace-test phase by default and exits `125` with a `DEFERRED[...]` continuation when the deadline is reached; that is incomplete evidence, never a passing aggregate. Use its printed continuation with `ASTROLABE_WORKSPACE_TEST_TIMEOUT_SECS=0` only when a full, unbounded native run is intentional.
- WSL-derived verification does not satisfy issue completion. Re-run required evidence natively and record the Windows execution context in the issue.
- Make and execute the technical, environment/toolchain, prioritization, and implementation decisions needed to reach ASTROLABE's intended end state. Prefer the most robust, durable, project-aligned solution over a locally easier workaround; do not pause for routine choices or leave known next steps undecided.
- GitHub issues and their comments are the durable state record. At every resume or context compaction, re-read this file, `CLAUDE.md`, the active issue and its comments, and the current Git/worktree state before acting. A claimed or `status:in-progress` issue is still available to this sole agent.
- Treat a result as real only after direct state verification of the actual artifact, process, browser state, or persisted data. Record that evidence in the issue before closing it; commit and push the verified repository state after every issue close.
- Use the already-open authenticated Chrome session through Synapse for browser work, opening only background tabs in that browser. Keep worktrees, branches, temporary tools, and outputs clean; create and track a GitHub issue for every discovered problem that is outside the current fix.
- For the complete Rust formatter, run `python scripts/native-cargo-fmt.py --all -- --check`. Do not run bare `cargo fmt --all` on native Windows: upstream cargo-fmt submits the Calyx graph as one Windows-overlimit process.
- Treat `vendor/calyx` and `vendor/codebase-memory-mcp` as pinned upstream sources. Do not edit them except through the documented patch flow.
