#!/usr/bin/env bash
set -euo pipefail

base=${INPUT_BASE:-$PR_BASE_SHA}
head=${INPUT_HEAD:-${PR_HEAD_SHA:-$EVENT_SHA}}
test -n "$base" || {
  echo "A base revision is required outside pull_request events; pass base explicitly." >&2
  exit 2
}
test -n "$head" || {
  echo "A head revision is required." >&2
  exit 2
}
report_path=$(mktemp "$RUNNER_TEMP/repo-standards-pr-size.XXXXXX.json")
uv run --project "$GITHUB_ACTION_PATH" --no-sync repo-standards pull-request size "$INPUT_ROOT" \
  --base "$base" --head "$head" \
  --generated-attribute "$INPUT_GENERATED_ATTRIBUTE" --report-path "$report_path" >/dev/null
values=$(
  uv run --project "$GITHUB_ACTION_PATH" --no-sync python -I - "$report_path" <<'PYTHON'
import json, sys
with open(sys.argv[1], encoding="utf-8") as stream:
    payload = json.load(stream)
summary = payload["summary"]
report = {key: value for key, value in payload.items() if key not in {"categories", "directories", "files"}}
print(summary["counted_lines"], summary["excluded_lines"], summary["total_lines"],
      json.dumps(report, sort_keys=True, separators=(",", ":")), sep="\t")
PYTHON
)
IFS=$'\t' read -r counted excluded total report <<<"$values"
echo "counted-lines=$counted" >>"$GITHUB_OUTPUT"
echo "excluded-lines=$excluded" >>"$GITHUB_OUTPUT"
echo "total-lines=$total" >>"$GITHUB_OUTPUT"
echo "report-json=$report" >>"$GITHUB_OUTPUT"
echo "report-path=$report_path" >>"$GITHUB_OUTPUT"
printf '## Pull-request size\n\n- Counted: %s lines\n- Excluded: %s lines\n- Total: %s lines\n' \
  "$counted" "$excluded" "$total" >>"$GITHUB_STEP_SUMMARY"
