#!/usr/bin/env bash
set -euo pipefail

body_file="$(mktemp "$RUNNER_TEMP/repo-standards-pr-body.XXXXXX")"
trap 'rm -f "$body_file"' EXIT
jq -erj '.pull_request.body // "" | strings' "$GITHUB_EVENT_PATH" >"$body_file"
# Preserve trailing newlines so validation sees the exact event title.
title="$(jq -erj '.pull_request.title | strings' "$GITHUB_EVENT_PATH" && printf '.')"
title="${title%.}"
uv run --project "$GITHUB_ACTION_PATH/.." --no-sync repo-standards \
  pull-request text "$body_file" --title="$title" --format json |
  jq -r '.warnings[] | "::warning title=PR text::" + .code + ": " + ((.message // "") + " " + .remediation | ltrimstr(" "))'
