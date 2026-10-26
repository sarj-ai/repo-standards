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
    npm --prefix apps/site ci --ignore-scripts --no-audit --no-fund &
    node_pid=$!
    result=0
    wait "$python_pid" || result=1
    wait "$node_pid" || result=1
    exit "$result"
    ;;
  compiler)
    compiler_version="$(npm --prefix apps/site exec --offline -- tsc --version)"
    test "$compiler_version" = 'Version 7.0.2'
    ;;
  bind)
    shift
    head_sha=$(git rev-parse HEAD)
    test "$head_sha" = "$GITHUB_SHA"
    printf '%s\n' "$GITHUB_SHA" >"$1/SOURCE_COMMIT"
    ;;
  credentials)
    test -n "$CLOUDFLARE_ACCOUNT_ID" || {
      echo "CLOUDFLARE_ACCOUNT_ID is not configured"
      exit 1
    }
    test -n "$CLOUDFLARE_API_TOKEN" || {
      echo "CLOUDFLARE_API_TOKEN is not configured"
      exit 1
    }
    ;;
  wait-main)
    deadline=$((SECONDS + 840))
    for workflow in ci.yml standards.yml; do
      while ((SECONDS < deadline)); do
        response="$(gh api --method GET "repos/$GITHUB_REPOSITORY/actions/workflows/$workflow/runs" -f head_sha="$TARGET_SHA" -f event=push -f per_page=100)"
        run="$(jq -c --arg sha "$TARGET_SHA" --arg repo "$GITHUB_REPOSITORY" '[.workflow_runs[] | select(.head_sha == $sha and .event == "push" and .head_branch == "main" and .head_repository.full_name == $repo)] | max_by(.id) // empty' <<<"$response")"
        conclusion="$(jq -r '.conclusion // empty' <<<"${run:-null}")"
        if [[ "$conclusion" == success ]]; then
          echo "$workflow succeeded at $TARGET_SHA"
          break
        fi
        if [[ -n "$conclusion" ]]; then
          echo "::error::$workflow concluded $conclusion at $TARGET_SHA"
          exit 1
        fi
        sleep 3
      done
      ((SECONDS < deadline)) || {
        echo "::error::exact main checks timed out"
        exit 1
      }
    done
    ;;
  *)
    printf 'usage: ci-workflow.sh python|smoke|dependencies|compiler|credentials|wait-main|bind DIRECTORY\n' >&2
    exit 2
    ;;
esac
