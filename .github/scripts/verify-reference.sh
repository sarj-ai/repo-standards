#!/usr/bin/env bash
set -euo pipefail

# Generate once; every gate below checks those same source-derived artifacts.
export UV_NO_DEV=true
cd "$(dirname "${BASH_SOURCE[0]}")/../../apps/docs"
npm run catalog
npm exec --offline -- eslint . --max-warnings 0
npm test
npm run typecheck
npm exec --offline -- astro build
node scripts/finalize-cloudflare-artifacts.ts
