#!/usr/bin/env bash
set -euo pipefail
cli="$SMOKE_ENV/bin/repo-standards"
work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/repo-interfaces.XXXXXX")"
trap 'rm -rf "$work"' EXIT
run_checks() {
  "$cli" "$@" > "$work/$1.log" 2>&1
}
# Bound to two processes; every public interface still starts a clean CLI.
run_checks --help & help_pid=$!
run_checks --version & version_pid=$!
result=0
wait "$help_pid" || result=1
wait "$version_pid" || result=1
(
  run_checks capabilities
  "$cli" pull-request commits --help
  "$cli" pull-request documentation --help
  "$cli" pull-request size --help
) > "$work/pull-request.log" 2>&1 & pull_pid=$!
(
  run_checks schema
  "$cli" rest --help
  "$SMOKE_ENV/bin/python" -c 'import repo_standards, repo_standards.catalog, repo_standards.pull_request, repo_standards.repository'
) > "$work/schema-rest.log" 2>&1 & schema_pid=$!
wait "$pull_pid" || result=1
wait "$schema_pid" || result=1
cat "$work"/*.log
exit "$result"
