# Astrolabe Agent Context

`CLAUDE.md` is the repository operating manual and must be read before doing any work. GitHub issues are the state of record.

The execution boundary is non-negotiable:

- Work only from the canonical checkout at `C:\code\Astrolabe`.
- Use native Windows processes only. Never invoke WSL, `wsl.exe`, a WSL distribution, `C:\Windows\System32\bash.exe`, or `/mnt/c/...` paths.
- Native Git for Windows Bash is allowed only when a repository POSIX script requires it; verify the executable resolves under `C:\Program Files\Git\`, not Windows System32.
- Keep repository-controlled outputs inside the workspace, normally in `target/`.
- Delete `C:\code\Astrolabe\target` after every build/test/check batch, including failure or interruption, and verify it is absent before any pause, stop, issue close, turn end, or handoff.
- WSL-derived verification does not satisfy issue completion. Re-run required evidence natively and record the Windows execution context in the issue.
- Treat `vendor/calyx` and `vendor/codebase-memory-mcp` as pinned upstream sources. Do not edit them except through the documented patch flow.
