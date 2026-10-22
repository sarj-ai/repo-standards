#!/usr/bin/env bash
set -euo pipefail

arguments=(
  --root "$INPUT_ROOT"
  --manifest-path "$INPUT_MANIFEST_PATH"
  --required-check-app-id "$INPUT_REQUIRED_CHECK_APP_ID"
  --policy-workflow-path "$INPUT_POLICY_WORKFLOW_PATH"
)
if [[ -n "$INPUT_MERGE_GROUP_HEAD_SHA" ]]; then
  arguments+=(
    --merge-group-head-sha "$INPUT_MERGE_GROUP_HEAD_SHA"
    --merge-group-head-ref "$INPUT_MERGE_GROUP_HEAD_REF"
  )
elif [[ -n "$INPUT_PR_NUMBER" ]]; then
  arguments+=(--pr-number "$INPUT_PR_NUMBER")
else
  echo "pr-number or merge-group-head-sha is required" >&2
  exit 2
fi
if [[ "$INPUT_REVIEW_OPTIONAL_ENABLED" == "true" ]]; then
  arguments+=(--review-optional-enabled)
elif [[ "$INPUT_REVIEW_OPTIONAL_ENABLED" != "false" ]]; then
  echo "review-optional-enabled must be true or false" >&2
  exit 2
fi
uv run --project "$GITHUB_ACTION_PATH/.." --no-sync \
  python -I -m repo_standards.github_review_policy "${arguments[@]}"
