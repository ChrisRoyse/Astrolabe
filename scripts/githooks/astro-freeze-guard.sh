# #519/#424: shared mutation-lease guard for the ASTROLABE git hooks.
#
# The launcher session lock (.tmp/astrolabe-launcher.lock, JSON: pid/issue/started/command,
# plus the evidence fingerprint) is an enforceable repository MUTATION LEASE. While it
# names a live PID, Git mutations must fail closed before mutating this checkout.
# Read-only operations do not reach these hooks; every registered worktree has its own lock.
# This guard never stops a process and never removes a lock.

astro_freeze_guard() {
    hook_name="$1"

    top=$(git rev-parse --show-toplevel 2>/dev/null) || return 0
    [ -n "$top" ] || return 0
    lock="$top/.tmp/astrolabe-launcher.lock"
    [ -f "$lock" ] || return 0

    owner_pid=$(sed -n 's/.*"pid"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$lock" | head -n 1)
    owner_issue=$(sed -n 's/.*"issue"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$lock" | head -n 1)
    owner_started=$(sed -n 's/.*"started"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$lock" | head -n 1)

    if [ -z "$owner_pid" ]; then
        echo "GIT_FREEZE[ASTRO_GIT_MUTATION_LEASE_UNREADABLE]: {code=ASTRO_GIT_MUTATION_LEASE_UNREADABLE; message=\"$hook_name: launcher evidence lock $lock exists but its owner pid is unreadable; refusing the Git mutation fail-closed\"; remediation=\"verify no launcher session is live, post PID-probe evidence to the owning issue, remove the malformed lock manually, then retry\"}" >&2
        return 1
    fi

    # Exact-PID liveness probe; MSYS2_ARG_CONV_EXCL prevents /FI switches becoming paths.
    probe_out=$(MSYS2_ARG_CONV_EXCL='*' tasklist.exe /FI "PID eq $owner_pid" /NH /FO CSV 2>/dev/null)
    probe_rc=$?
    if [ $probe_rc -ne 0 ] || [ -z "$probe_out" ]; then
        echo "GIT_FREEZE[ASTRO_GIT_MUTATION_LEASE_UNEVALUABLE]: {code=ASTRO_GIT_MUTATION_LEASE_UNEVALUABLE; message=\"$hook_name: could not evaluate liveness of launcher lock owner pid $owner_pid (tasklist rc=$probe_rc); refusing the Git mutation fail-closed\"; remediation=\"re-run once the process state is readable, or wait for the launcher session to finish\"}" >&2
        return 1
    fi

    case "$probe_out" in
        *"\"$owner_pid\""*)
            echo "GIT_FREEZE[ASTRO_GIT_MUTATION_LEASE_HELD]: {code=ASTRO_GIT_MUTATION_LEASE_HELD; message=\"$hook_name: a LIVE launcher evidence session owns this checkout (pid=$owner_pid, issue=#${owner_issue:-unknown}, started=${owner_started:-unknown}); Git mutation refused before HEAD/index/worktree changed (#424/#519)\"; remediation=\"wait for the owner's lock at $lock to release, or do the mutation in an independent registered worktree under .claude/worktrees/\"}" >&2
            return 1
            ;;
        *)
            return 0
            ;;
    esac
}
