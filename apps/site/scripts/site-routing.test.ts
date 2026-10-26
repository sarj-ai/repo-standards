import assert from 'node:assert/strict';
import test from 'node:test';

import { SITE_BASE_PATH, SITE_ORIGIN, legacyRedirect } from '../src/lib/site.ts';
import worker from '../src/worker.ts';

void test('legacy URLs retain paths and queries without repeating the project prefix', () => {
  const paths = ['/', '/rules/example/?keep=1&next=two', SITE_BASE_PATH, SITE_BASE_PATH.slice(0, -1), `${SITE_BASE_PATH}api/catalog.json?keep=1`, '//rules/example/?keep=1'];
  for (const path of paths) {
    const actual = legacyRedirect(`https://repo-standards.sarj.ai${path}`);
    assert.notEqual(actual, undefined);
    const destination = new globalThis.URL(actual ?? '');
    assert.equal(destination.origin, SITE_ORIGIN);
    assert.ok(destination.pathname.startsWith(SITE_BASE_PATH));
    assert.equal(destination.search, new globalThis.URL(`https://repo-standards.sarj.ai${path}`).search);
    assert.equal(destination.pathname.indexOf(SITE_BASE_PATH, SITE_BASE_PATH.length), -1);
  }
  assert.equal(legacyRedirect(`https://repo-standards.sarj.ai/`), `${SITE_ORIGIN}${SITE_BASE_PATH}`);
});

void test('the canonical hostname forwards the original request to native assets', async () => {
  const request = new globalThis.Request(`${SITE_ORIGIN}${SITE_BASE_PATH}api/catalog.json?keep=two`);
  const response = new globalThis.Response('native asset');
  let observed: Request | undefined;
  const result = await worker.fetch(request, {
    ASSETS: { fetch: (candidate) => {
      observed = candidate;
      return Promise.resolve(response);
    } },
  });
  assert.equal(result, response);
  assert.equal(observed, request);
  assert.equal(legacyRedirect(request.url), undefined);
});

void test('the legacy hostname redirects before accessing assets', async () => {
  const result = await worker.fetch(new globalThis.Request('https://repo-standards.sarj.ai/cli/?keep=two'), {
    ASSETS: { fetch: () => {
      throw new Error('Legacy URLs must not fetch assets');
    } },
  });
  assert.equal(result.status, 301);
  assert.equal(result.headers.get('location'), `${SITE_ORIGIN}${SITE_BASE_PATH}cli/?keep=two`);
});
