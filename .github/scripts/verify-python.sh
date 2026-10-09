#!/usr/bin/env bash
set -euo pipefail
usage() {
  echo 'usage: bash .github/scripts/verify-python.sh [base | --base revision] [--jobs 1|2|4]'
  echo 'Omit base for all tests; origin/main selects reviewed changed-test cohorts.'
  echo 'Shared changes fall back to all tests. Ruff, types and tests must all pass.'
}
verify_base=''
verify_jobs=2
base_selected=false
while (( $# )); do
  case "$1" in
    --help|-h) usage; exit 0;;
    --base)
      if (( $# < 2 )) || [[ "$base_selected" == true || "$2" == -* ]]; then usage >&2; exit 2; fi
      verify_base="$2"; base_selected=true; shift 2;;
    --jobs)
      if (( $# < 2 )) || [[ "$2" != 1 && "$2" != 2 && "$2" != 4 ]]; then usage >&2; exit 2; fi
      verify_jobs="$2"; shift 2;;
    -*) usage >&2; exit 2;;
    *)
      if [[ "$base_selected" == true ]]; then usage >&2; exit 2; fi
      verify_base="$1"; base_selected=true; shift;;
  esac
done
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
# An omitted base is the full gate; explicit bases use the reviewed selector.
export UV_PYTHON="${STANDARDS_PYTHON:-3.15}"
uv sync --locked --python "$UV_PYTHON"
run_check() {
  label="$1"; shift
  started=$SECONDS
  "$@" && result=0 || result=$?
  printf '%s: %ss (exit %s)\n' "$label" "$((SECONDS-started))" "$result"
  return "$result"
}
run_check Ruff uv run --no-sync ruff check . & lint_pid=$!
run_check Typecheck uv run --no-sync basedpyright & types_pid=$!
run_check Tests uv run --no-sync python test_selection.py --run --base "$verify_base" --jobs "$verify_jobs" & tests_pid=$!
result=0
wait "$lint_pid" || result=1
wait "$types_pid" || result=1
wait "$tests_pid" || result=1
exit "$result"
