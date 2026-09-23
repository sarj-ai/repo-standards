import assert from 'node:assert/strict';
import test from 'node:test';

import { verifyDeployment } from './verify-deployment.ts';

const COMMIT = 'a'.repeat(40);
const DIGEST = 'catalog-digest';

function response(value: unknown, status = 200): Response {
  return new globalThis.Response(JSON.stringify(value), {
    headers: { 'Content-Type': 'application/json' },
    status,
  });
}

void test('accepts matching deployment identity and catalog digest', async () => {
  const requests: [string, string, RequestCache | undefined][] = [];
  const health = await verifyDeployment({
    expectedCommit: COMMIT,
    request: (url, options) => {
      requests.push([url.pathname, url.search, options.cache]);
      return url.pathname.endsWith('/health.json')
        ? response({ commit: COMMIT, catalogDigest: DIGEST })
        : response({ provenance: { "content_digest": DIGEST } });
    },
  });

  assert.equal(health.commit, COMMIT);
  assert.deepEqual(requests, [
    ['/health.json', `?commit=${COMMIT}&attempt=1`, 'no-store'],
    ['/api/catalog.json', `?commit=${COMMIT}&attempt=1`, 'no-store'],
  ]);
});

void test('retries a stale deployment before accepting the expected commit', async () => {
  let attempt = 0;
  const pauses: number[] = [];
  await verifyDeployment({
    attempts: 2,
    expectedCommit: COMMIT,
    pause: (milliseconds) => {
      pauses.push(milliseconds);
    },
    request: (url) => {
      if (url.pathname.endsWith('/health.json')) attempt += 1;
      return url.pathname.endsWith('/health.json')
        ? response({ commit: attempt === 1 ? 'b'.repeat(40) : COMMIT, catalogDigest: DIGEST })
        : response({ provenance: { "content_digest": DIGEST } });
    },
  });

  assert.deepEqual(pauses, [3000]);
});

void test('fails closed after the retry budget is exhausted', async () => {
  await assert.rejects(
    verifyDeployment({
      attempts: 2,
      expectedCommit: COMMIT,
      pause: () => undefined,
      request: () => response({}, 503),
    }),
    /reference endpoints are unavailable/u,
  );
});

void test('rejects ambiguous deployment identities before network access', async () => {
  await assert.rejects(
    verifyDeployment({ expectedCommit: 'main', request: () => response({}) }),
    /full lowercase Git commit SHA/u,
  );
});

void test('rejects malformed deployment payloads', async () => {
  await assert.rejects(
    verifyDeployment({
      attempts: 1,
      expectedCommit: COMMIT,
      request: (url) => response(url.pathname.endsWith('/health.json') ? {} : {
        provenance: { "content_digest": DIGEST },
      }),
    }),
    /health endpoint returned an invalid payload/u,
  );
});
