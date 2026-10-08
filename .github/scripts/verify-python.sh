#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
# An omitted base is the full gate; explicit bases use the reviewed selector.
uv sync --locked --python 3.14
run_check() {
  label="$1"; shift
  started=$SECONDS
  "$@" && result=0 || result=$?
  printf '%s: %ss (exit %s)\n' "$label" "$((SECONDS-started))" "$result"
  return "$result"
}
run_check Ruff uv run --no-sync ruff check . & lint_pid=$!
run_check Typecheck uv run --no-sync basedpyright & types_pid=$!
run_check Tests uv run --no-sync python test_selection.py --run --base "${1:-}" & tests_pid=$!
result=0
wait "$lint_pid" || result=1
wait "$types_pid" || result=1
wait "$tests_pid" || result=1
exit "$result"
