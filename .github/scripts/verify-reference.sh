#!/usr/bin/env bash
set -euo pipefail

# Generate once; every gate below checks those same source-derived artifacts.
export UV_NO_DEV=true
cd "$(dirname "${BASH_SOURCE[0]}")/../../apps/docs"
npm run catalog
npm exec --offline -- eslint . --max-warnings 0 & lint_pid=$!
npm test & tests_pid=$!
npm run typecheck & types_pid=$!
result=0
wait "$lint_pid" || result=1
wait "$tests_pid" || result=1
wait "$types_pid" || result=1
if [[ "$result" != 0 ]]; then exit "$result"; fi
npm exec --offline -- astro build
node scripts/finalize-cloudflare-artifacts.ts
