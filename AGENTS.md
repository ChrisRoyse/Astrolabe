# Astrolabe Agent Context

`CLAUDE.md` is the repository operating manual and must be read before doing any work. GitHub issues are the state of record.

The execution boundary is non-negotiable:

- Work only from the canonical checkout at `C:\code\Astrolabe`.
- Use native Windows processes only. Never invoke WSL, `wsl.exe`, a WSL distribution, `C:\Windows\System32\bash.exe`, or `/mnt/c/...` paths.
- Native Git for Windows Bash is allowed only when a repository POSIX script requires it; verify the executable resolves under `C:\Program Files\Git\`, not Windows System32.
- Keep repository-controlled outputs inside the workspace, normally in `target/`.
- Delete `C:\code\Astrolabe\target` after every build/test/check batch, including failure or interruption, and verify it is absent before any pause, stop, issue close, turn end, or handoff.
- `scripts/check-full.sh` bounds its workspace-test phase by default and exits `125` with a `DEFERRED[...]` continuation when the deadline is reached; that is incomplete evidence, never a passing aggregate. Use its printed continuation with `ASTROLABE_WORKSPACE_TEST_TIMEOUT_SECS=0` only when a full, unbounded native run is intentional.
- WSL-derived verification does not satisfy issue completion. Re-run required evidence natively and record the Windows execution context in the issue.
- Make and execute the technical, prioritization, and implementation decisions needed to reach ASTROLABE's intended end state. Prefer the most robust, durable, project-aligned solution over a locally easier workaround; do not pause for routine choices or leave known next steps undecided.
- For the complete Rust formatter, run `python scripts/native-cargo-fmt.py --all -- --check`. Do not run bare `cargo fmt --all` on native Windows: upstream cargo-fmt submits the Calyx graph as one Windows-overlimit process.
- Treat `vendor/calyx` and `vendor/codebase-memory-mcp` as pinned upstream sources. Do not edit them except through the documented patch flow.
