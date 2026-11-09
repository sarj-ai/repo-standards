#!/usr/bin/env bash
set -euo pipefail

# Generate once; every gate below checks those same source-derived artifacts.
export UV_NO_DEV=true
cd "$(dirname "${BASH_SOURCE[0]}")/../../apps/site"
npm run catalog
npm exec --offline -- astro sync
uvx --no-config --isolated --python 3.14 --from sarj-standards-bootstrap code-standards --root ../.. check --trust-repository-code apps/site &
lint_pid=$!
npm test &
tests_pid=$!
npm run typecheck &
types_pid=$!
result=0
wait "$lint_pid" || result=1
wait "$tests_pid" || result=1
wait "$types_pid" || result=1
if [[ "$result" != 0 ]]; then exit "$result"; fi
npm exec --offline -- astro build
node scripts/finalize-cloudflare-artifacts.ts
