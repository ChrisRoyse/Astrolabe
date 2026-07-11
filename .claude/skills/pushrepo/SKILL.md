---
name: pushrepo
description: Commits and pushes all repository changes with ASTROLABE discipline — issue-referenced commit body, hygiene sweep (no target/, .tmp, scratch, or vendor drift staged), secret-scanner awareness, and pushed-state readback. Replaces the former pushrepo command, which invoked a validation hook that does not exist in this repository.
disable-model-invocation: true
allowed-tools: Bash(git status *), Bash(git diff *), Bash(git log *), Bash(git add *), Bash(git commit *), Bash(git push *), Bash(git rev-parse *)
---

# Commit and push (validated)

1. **Review reality:** `git status --short` and `git diff` — read what actually changed; never stage blind.
2. **Hygiene sweep — must NOT be staged:** `target/`, `.tmp/`, `.sccache/`, `.toolchains/`, test databases, logs, fixtures outside their tracked homes, or any `vendor/` modification (vendor changes go through astro-vendor-patch only; `git status --porcelain vendor/` must be empty).
3. **Commit message:** short imperative subject; body **must** reference the driving issue (`Refs #N`, or `Closes #N` only when that issue's gates have passed). Match recent `git log --oneline` style. End with `Co-Authored-By:` trailer per repo convention.
4. **Secret scanner:** long hex tokens in committed Calyx ledger payloads must live under allowlisted field names (`*_sha256`/`*_hash`/`*_digest`) or the commit fails closed. That failure is correct — rename the field; never bypass with `--no-verify`.
5. **Push** to the current branch. No `--force` on `main`, ever.
6. **Readback (FSV):** `git status` clean + `git log origin/<branch> -1 --format=%H` equals local `git rev-parse HEAD`. A push you did not read back is not pushed.

If any step fails, stop and report the exact failure — no partial pushes, no `--no-verify`, no bypassing hooks.
