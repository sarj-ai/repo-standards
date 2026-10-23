#!/usr/bin/env bash
set -euo pipefail

base=${INPUT_BASE:-$PR_BASE_SHA}
head=${INPUT_HEAD:-$PR_HEAD_SHA}
test -n "$base" || {
  echo "A trusted base revision is required." >&2
  exit 2
}
test -n "$head" || {
  echo "A head revision is required." >&2
  exit 2
}
uv run --project "$GITHUB_ACTION_PATH/.." --no-sync repo-standards \
  pull-request documentation "$INPUT_ROOT" --base "$base" --head "$head"
