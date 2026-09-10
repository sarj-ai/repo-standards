import { pathToFileURL } from 'node:url';

const DEFAULT_BASE_URL = 'https://repo-standards.sarj.ai/';
const DEFAULT_ATTEMPTS = 10;
const RETRY_DELAY_MS = 3000;

function sleep(milliseconds) {
  return new Promise((resolve) => globalThis.setTimeout(resolve, milliseconds));
}

export async function verifyDeployment({
  expectedCommit,
  baseUrl = DEFAULT_BASE_URL,
  attempts = DEFAULT_ATTEMPTS,
  request = globalThis.fetch,
  pause = sleep,
}) {
  if (!/^[0-9a-f]{40}$/u.test(expectedCommit)) {
    throw new TypeError('EXPECTED_COMMIT must be a full lowercase Git commit SHA');
  }
  if (!Number.isSafeInteger(attempts) || attempts < 1) {
    throw new TypeError('attempts must be a positive safe integer');
  }

  let lastError;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      return await deploymentAtAttempt({ expectedCommit, baseUrl, attempt, request });
    } catch (error) {
      lastError = error;
      if (attempt < attempts) await pause(RETRY_DELAY_MS);
    }
  }
  throw lastError;
}

async function deploymentAtAttempt({ expectedCommit, baseUrl, attempt, request }) {
  const query = `?commit=${expectedCommit}&attempt=${String(attempt)}`;
  const [healthResponse, catalogResponse] = await Promise.all([
    request(new globalThis.URL(`health.json${query}`, baseUrl), { cache: 'no-store' }),
    request(new globalThis.URL(`api/v7/catalog.json${query}`, baseUrl), { cache: 'no-store' }),
  ]);
  if (!healthResponse.ok || !catalogResponse.ok) {
    throw new Error('reference endpoints are unavailable');
  }
  const health = await healthResponse.json();
  const catalog = await catalogResponse.json();
  if (health.commit !== expectedCommit) throw new Error('deployed commit does not match');
  if (health.catalogDigest !== catalog.provenance?.content_digest) {
    throw new Error('deployed catalog digest does not match');
  }
  return health;
}

async function main() {
  const health = await verifyDeployment({
    expectedCommit: globalThis.process.env.EXPECTED_COMMIT ?? '',
  });
  globalThis.process.stdout.write(`verified ${health.commit}\n`);
}

if (
  globalThis.process.argv[1] !== undefined
  && import.meta.url === pathToFileURL(globalThis.process.argv[1]).href
) {
  await main();
}
