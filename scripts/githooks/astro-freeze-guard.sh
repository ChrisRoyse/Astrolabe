# #519/#424: shared mutation-lease guard for the ASTROLABE git hooks.
#
# The strict authoritative v2 launcher manifest is an enforceable repository MUTATION LEASE.
# While its exact process identity is live,
# Git mutations must fail closed before mutating this checkout.
# Read-only operations do not reach these hooks; every registered worktree has its own lock.
# This guard never stops a process and never removes a lock.

astro_freeze_guard() {
    hook_name="$1"

    if ! top=$(git rev-parse --show-toplevel 2>/dev/null) || [ -z "$top" ]; then
        echo "GIT_FREEZE[ASTRO_GIT_MUTATION_LEASE_UNEVALUABLE]: {code=ASTRO_GIT_MUTATION_LEASE_UNEVALUABLE; message=\"$hook_name: could not resolve the operating worktree before mutation; refusing fail-closed\"; remediation=\"repair Git worktree metadata and retry\"}" >&2
        return 1
    fi
    lock="$top/.tmp/astrolabe-launcher.lock"

    # Route every hook through the same full schema/tick/fingerprint classifier used by the
    # launcher and explicit reclaim. This avoids a second JSON parser and keeps process-query
    # failure distinct from verified absence.
    lock_windows=$(cygpath -aw "$lock" 2>/dev/null)
    classifier_windows=$(cygpath -aw "$top/scripts/launcher-lock-status.ps1" 2>/dev/null)
    if [ -z "$lock_windows" ] || [ -z "$classifier_windows" ]; then
        echo "GIT_FREEZE[ASTRO_GIT_MUTATION_LEASE_UNEVALUABLE]: {code=ASTRO_GIT_MUTATION_LEASE_UNEVALUABLE; message=\"$hook_name: could not resolve native Windows paths for launcher-lock classification; refusing the Git mutation fail-closed\"; remediation=\"repair the Git for Windows path bridge and retry\"}" >&2
        return 1
    fi
    probe_out=$(MSYS2_ARG_CONV_EXCL='*' powershell.exe \
        -NoProfile -NonInteractive -ExecutionPolicy Bypass \
        -File "$classifier_windows" -LockPath "$lock_windows" 2>&1)
    probe_rc=$?
    case "$probe_rc" in
        0)
            return 0
            ;;
        20)
            echo "GIT_FREEZE[ASTRO_GIT_MUTATION_LEASE_HELD]: {code=ASTRO_GIT_MUTATION_LEASE_HELD; message=\"$hook_name: exact live launcher evidence owner holds this checkout; classifier=$probe_out\"; remediation=\"wait for the owner's lock at $lock to release, or mutate an independent registered worktree\"}" >&2
            return 1
            ;;
        21)
            echo "GIT_FREEZE[ASTRO_GIT_MUTATION_LEASE_UNREADABLE]: {code=ASTRO_GIT_MUTATION_LEASE_UNREADABLE; message=\"$hook_name: launcher lock failed authoritative schema validation; classifier=$probe_out\"; remediation=\"preserve the lock and use the tracker-evidenced explicit reclaim path\"}" >&2
            return 1
            ;;
        24)
            echo "GIT_FREEZE[ASTRO_GIT_MUTATION_LEASE_TRANSITION]: {code=ASTRO_GIT_MUTATION_LEASE_TRANSITION; message=\"$hook_name: interrupted launcher claim/cleanup state exists; classifier=$probe_out\"; remediation=\"preserve the transition and use the tracker-evidenced explicit archive path\"}" >&2
            return 1
            ;;
        *)
            echo "GIT_FREEZE[ASTRO_GIT_MUTATION_LEASE_UNEVALUABLE]: {code=ASTRO_GIT_MUTATION_LEASE_UNEVALUABLE; message=\"$hook_name: launcher lock classification failed closed (exit=$probe_rc); classifier=$probe_out\"; remediation=\"preserve the lock and repair the native classifier/process query before retrying\"}" >&2
            return 1
            ;;
    esac
}
