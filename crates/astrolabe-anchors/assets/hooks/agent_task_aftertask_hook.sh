#!/usr/bin/env bash
# ASTROLABE opt-in agent-task afterTask / Stop hook (blueprint 06 §2.4, 15 §4).
#
# Purpose: after an agent session ends, PROMPT (never perform) the
#   anchor_outcome{kind:"agent_task", success, session, context_pack_id}
# call that records whether the session's edits survived. This hook is advisory
# and OPT-IN: install it only if you want the flywheel intake prompt.
#
# Contract (CBM never-block / silent-fail — enforced here, and again by the
# astrolabe_anchors::hook harness that runs it):
#   * It NEVER blocks the agent: it always exits 0, even on any internal error.
#   * It is SILENT on timeout: a self-imposed budget bounds its own work, and if
#     that budget is exceeded the background work is abandoned without output.
#   * It emits at most a single-line JSON suggestion on stdout; it performs no
#     network or vault mutation of its own.
#
# Inputs (all optional, via environment):
#   ASTRO_AGENT           agent identifier (default: "agent")
#   ASTRO_SESSION         session identifier (default: "$$")
#   ASTRO_PACK_ID         served context_pack_id (suggestion is skipped if unset)
#   ASTRO_TASK_SUCCESS    "1"/"true" success, else failure (default: "0")
#   ASTRO_HOOK_BUDGET_SEC self-timeout budget seconds (default: "2")
#
# Exit status is ALWAYS 0.

set +e  # never abort the agent on a hook error

emit_suggestion() {
  agent="${ASTRO_AGENT:-agent}"
  session="${ASTRO_SESSION:-$$}"
  pack_id="${ASTRO_PACK_ID:-}"
  success_raw="${ASTRO_TASK_SUCCESS:-0}"

  # No pack id: nothing to attribute an outcome to. Stay silent.
  if [ -z "${pack_id}" ]; then
    return 0
  fi

  case "${success_raw}" in
    1|true|TRUE|yes|YES) success="true" ;;
    *) success="false" ;;
  esac

  # A single-line JSON prompt the agent runtime can forward to anchor_outcome.
  printf '{"suggest":"anchor_outcome","kind":"agent_task","agent":"%s","session":"%s","context_pack_id":"%s","success":%s}\n' \
    "${agent}" "${session}" "${pack_id}" "${success}"
}

budget="${ASTRO_HOOK_BUDGET_SEC:-2}"

# Run the suggestion under a self-imposed budget so a wedged hook can never hang
# the agent. `timeout` is used when available; otherwise a background watchdog
# bounds the work. Either way we exit 0 and stay silent past the budget.
if command -v timeout >/dev/null 2>&1; then
  timeout "${budget}s" bash -c 'emit_suggestion' 2>/dev/null
  # timeout returns 124 on expiry; swallow every status.
else
  emit_suggestion &
  worker=$!
  ( sleep "${budget}" 2>/dev/null; kill "${worker}" 2>/dev/null ) &
  watchdog=$!
  wait "${worker}" 2>/dev/null
  kill "${watchdog}" 2>/dev/null
fi

exit 0
