#!/usr/bin/env bash
set -euo pipefail

run_check() {
  label="$1"
  shift
  started=$SECONDS
  "$@" && result=0 || result=$?
  printf '%s: %ss (exit %s)\n' "$label" "$((SECONDS - started))" "$result" >>"$GITHUB_STEP_SUMMARY"
  return "$result"
}

case "${1:-}" in
  python)
    run_check Ruff uv run --no-sync ruff check . &
    lint_pid=$!
    run_check Typecheck uv run --no-sync basedpyright &
    types_pid=$!
    run_check Tests uv run --no-sync python test_selection.py --run --base "$TEST_BASE" --report "$RUNNER_TEMP/test-plan.json" --summary "$GITHUB_STEP_SUMMARY" &
    tests_pid=$!
    result=0
    wait "$lint_pid" || result=1
    wait "$types_pid" || result=1
    wait "$tests_pid" || result=1
    exit "$result"
    ;;
  smoke)
    bash .github/scripts/smoke-interfaces.sh
    mkdir -p "$FIXTURE_ROOT/.repo-standards"
    cp tests/fixtures/smoke/.repo-standards/repository.toml "$FIXTURE_ROOT/.repo-standards/repository.toml"
    git -C "$FIXTURE_ROOT" init --quiet
    git -C "$FIXTURE_ROOT" add .
    git -C "$FIXTURE_ROOT" -c user.name='Repository Lint' -c user.email='repository-lint@example.invalid' commit --quiet -m fixture
    "$SMOKE_ENV/bin/repo-standards" report "$FIXTURE_ROOT" --format json >"$REPORT_PATH"
    "$SMOKE_ENV/bin/python" ci_smoke_report.py "$REPORT_PATH"
    ;;
  dependencies)
    uv sync --locked --python 3.15 --no-dev &
    python_pid=$!
    npm --prefix apps/docs ci --ignore-scripts --no-audit --no-fund &
    node_pid=$!
    result=0
    wait "$python_pid" || result=1
    wait "$node_pid" || result=1
    exit "$result"
    ;;
  bind)
    shift
    head_sha=$(git rev-parse HEAD)
    test "$head_sha" = "$GITHUB_SHA"
    printf '%s\n' "$GITHUB_SHA" >"$1/SOURCE_COMMIT"
    ;;
  *)
    printf 'usage: ci-workflow.sh python|smoke|dependencies|bind DIRECTORY\n' >&2
    exit 2
    ;;
esac
