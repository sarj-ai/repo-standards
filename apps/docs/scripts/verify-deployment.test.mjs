import assert from 'node:assert/strict';
import test from 'node:test';

import { verifyDeployment } from './verify-deployment.mjs';

const COMMIT = 'a'.repeat(40);
const DIGEST = 'catalog-digest';

function response(value, status = 200) {
  return new globalThis.Response(JSON.stringify(value), {
    headers: { 'Content-Type': 'application/json' },
    status,
  });
}

test('accepts matching deployment identity and catalog digest', async () => {
  const requests = [];
  const health = await verifyDeployment({
    expectedCommit: COMMIT,
    request: async (url, options) => {
      requests.push([url.pathname, url.search, options.cache]);
      return url.pathname.endsWith('/health.json')
        ? response({ commit: COMMIT, catalogDigest: DIGEST })
        : response({ provenance: { content_digest: DIGEST } });
    },
  });

  assert.equal(health.commit, COMMIT);
  assert.deepEqual(requests, [
    ['/health.json', `?commit=${COMMIT}&attempt=1`, 'no-store'],
    ['/api/v7/catalog.json', `?commit=${COMMIT}&attempt=1`, 'no-store'],
  ]);
});

test('retries a stale deployment before accepting the expected commit', async () => {
  let attempt = 0;
  const pauses = [];
  await verifyDeployment({
    attempts: 2,
    expectedCommit: COMMIT,
    pause: async (milliseconds) => pauses.push(milliseconds),
    request: async (url) => {
      if (url.pathname.endsWith('/health.json')) attempt += 1;
      return url.pathname.endsWith('/health.json')
        ? response({ commit: attempt === 1 ? 'b'.repeat(40) : COMMIT, catalogDigest: DIGEST })
        : response({ provenance: { content_digest: DIGEST } });
    },
  });

  assert.deepEqual(pauses, [3000]);
});

test('fails closed after the retry budget is exhausted', async () => {
  await assert.rejects(
    verifyDeployment({
      attempts: 2,
      expectedCommit: COMMIT,
      pause: async () => undefined,
      request: async () => response({}, 503),
    }),
    /reference endpoints are unavailable/u,
  );
});

test('rejects ambiguous deployment identities before network access', async () => {
  await assert.rejects(
    verifyDeployment({ expectedCommit: 'main', request: async () => response({}) }),
    /full lowercase Git commit SHA/u,
  );
});
