#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${1:-$ROOT/target/debug/astrolabe}"

case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    # #253: the parent-death watchdog is now implemented natively on Windows
    # (astrolabe-bridge ParentDeathWatch: OpenProcess(SYNCHRONIZE) + WaitForSingleObject on
    # the parent handle). This Unix FIFO/kill/ps harness cannot exercise it, so delegate to
    # the native PowerShell test, which holds astrolabe's stdin open (a named pipe owned by
    # the grandparent) while the parent is killed -- isolating the watchdog from the
    # stdin-EOF shutdown path so a PASS proves the watchdog, not EOF.
    win_bin="$BIN"
    [[ -f "$win_bin" ]] || win_bin="${BIN}.exe"
    if [[ ! -f "$win_bin" ]]; then
      echo "missing astrolabe binary: $win_bin" >&2
      exit 2
    fi
    if command -v powershell.exe >/dev/null 2>&1; then PS_EXE=powershell.exe; else PS_EXE=pwsh.exe; fi
    "$PS_EXE" -NoProfile -ExecutionPolicy Bypass \
      -File "$(cygpath -w "$ROOT/scripts/check-astrolabe-watchdog-windows.ps1")" \
      -Astrolabe "$(cygpath -w "$win_bin")"
    exit $?
    ;;
esac

if [[ ! -x "$BIN" ]]; then
  echo "missing astrolabe binary: $BIN" >&2
  exit 2
fi

tmpdir="$(mktemp -d)"
wrapper_pid=""
cleanup() {
  if [[ -s "$tmpdir/child.pid" ]]; then
    child_pid="$(cat "$tmpdir/child.pid" 2>/dev/null || true)"
    [[ -n "${child_pid:-}" ]] && kill "$child_pid" 2>/dev/null || true
  fi
  [[ -n "$wrapper_pid" ]] && kill "$wrapper_pid" 2>/dev/null || true
  rm -rf "$tmpdir"
}
trap cleanup EXIT

cat >"$tmpdir/wrapper.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
exec 3<>"${FIFO}"
"${ASTROLABE_BINARY}" <&3 >/dev/null 2>"${TMPDIR_PATH}/child.err" &
echo "$!" >"${TMPDIR_PATH}/child.pid"
wait
SH
chmod +x "$tmpdir/wrapper.sh"
mkfifo "$tmpdir/stdin"

ASTROLABE_BINARY="$BIN" FIFO="$tmpdir/stdin" TMPDIR_PATH="$tmpdir" \
  "$tmpdir/wrapper.sh" &
wrapper_pid=$!

for _ in {1..50}; do
  [[ -s "$tmpdir/child.pid" ]] && break
  sleep 0.1
done

if [[ ! -s "$tmpdir/child.pid" ]]; then
  echo "child pid file was not written" >&2
  [[ -s "$tmpdir/child.err" ]] && cat "$tmpdir/child.err" >&2
  exit 3
fi

child_pid="$(cat "$tmpdir/child.pid")"
if ! kill -0 "$child_pid" 2>/dev/null; then
  echo "astrolabe child did not start" >&2
  exit 3
fi

for _ in {1..50}; do
  if [[ -s "$tmpdir/child.err" ]] && grep -q "server.start" "$tmpdir/child.err"; then
    break
  fi
  sleep 0.1
done
if ! grep -q "server.start" "$tmpdir/child.err" 2>/dev/null; then
  echo "astrolabe child did not reach watchdog-ready startup point" >&2
  [[ -s "$tmpdir/child.err" ]] && cat "$tmpdir/child.err" >&2
  exit 3
fi

kill -9 "$wrapper_pid"
wait "$wrapper_pid" 2>/dev/null || true

deadline=$((SECONDS + 15))
while (( SECONDS < deadline )); do
  if ! kill -0 "$child_pid" 2>/dev/null; then
    echo "ok: astrolabe child $child_pid exited after parent death"
    exit 0
  fi
  child_state="$(ps -p "$child_pid" -o stat= 2>/dev/null | tr -d '[:space:]' || true)"
  if [[ "$child_state" == Z* ]]; then
    echo "ok: astrolabe child $child_pid exited after parent death (zombie awaiting reap)"
    exit 0
  fi
  sleep 0.2
done

echo "astrolabe child $child_pid survived parent death" >&2
[[ -s "$tmpdir/child.err" ]] && cat "$tmpdir/child.err" >&2
exit 1
