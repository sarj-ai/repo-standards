import { pathToFileURL } from 'node:url';

const DEFAULT_BASE_URL = 'https://repo-standards.sarj.ai/';
const DEFAULT_ATTEMPTS = 10;
const RETRY_DELAY_MS = 3000;

interface DeploymentHealth {
  readonly catalogDigest: string;
  readonly commit: string;
}

interface DeploymentCatalog {
  readonly provenance: { readonly content_digest: string };
}

type Pause = (milliseconds: number) => Promise<void> | void;
type Request = (url: URL, init: RequestInit) => Promise<Response> | Response;

interface VerificationOptions {
  readonly attempts?: number;
  readonly baseUrl?: string;
  readonly expectedCommit: string;
  readonly pause?: Pause;
  readonly request?: Request;
}

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => globalThis.setTimeout(resolve, milliseconds));
}

export async function verifyDeployment({
  expectedCommit,
  baseUrl = DEFAULT_BASE_URL,
  attempts = DEFAULT_ATTEMPTS,
  request = globalThis.fetch,
  pause = sleep,
}: VerificationOptions): Promise<DeploymentHealth> {
  if (!/^[0-9a-f]{40}$/u.test(expectedCommit)) {
    throw new TypeError('EXPECTED_COMMIT must be a full lowercase Git commit SHA');
  }
  if (!Number.isSafeInteger(attempts) || attempts < 1) {
    throw new TypeError('attempts must be a positive safe integer');
  }

  let lastError: unknown = new Error('deployment verification did not run');
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

interface AttemptOptions {
  readonly attempt: number;
  readonly baseUrl: string;
  readonly expectedCommit: string;
  readonly request: Request;
}

async function deploymentAtAttempt({
  expectedCommit,
  baseUrl,
  attempt,
  request,
}: AttemptOptions): Promise<DeploymentHealth> {
  const query = `?commit=${expectedCommit}&attempt=${String(attempt)}`;
  const [healthResponse, catalogResponse] = await Promise.all([
    request(new globalThis.URL(`health.json${query}`, baseUrl), { cache: 'no-store' }),
    request(new globalThis.URL(`api/v7/catalog.json${query}`, baseUrl), { cache: 'no-store' }),
  ]);
  if (!healthResponse.ok || !catalogResponse.ok) {
    throw new Error('reference endpoints are unavailable');
  }
  const health = parseHealth(await healthResponse.json());
  const catalog = parseCatalog(await catalogResponse.json());
  if (health.commit !== expectedCommit) throw new Error('deployed commit does not match');
  if (health.catalogDigest !== catalog.provenance.content_digest) {
    throw new Error('deployed catalog digest does not match');
  }
  return health;
}

function parseHealth(value: unknown): DeploymentHealth {
  if (
    !isRecord(value)
    || typeof value.commit !== 'string'
    || typeof value.catalogDigest !== 'string'
  ) {
    throw new Error('health endpoint returned an invalid payload');
  }
  return { catalogDigest: value.catalogDigest, commit: value.commit };
}

function parseCatalog(value: unknown): DeploymentCatalog {
  if (
    !isRecord(value)
    || !isRecord(value.provenance)
    || typeof value.provenance.content_digest !== 'string'
  ) {
    throw new Error('catalog endpoint returned an invalid payload');
  }
  return { provenance: { content_digest: value.provenance.content_digest } };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

async function main(): Promise<void> {
  const health = await verifyDeployment({
    expectedCommit: globalThis.process.env.EXPECTED_COMMIT ?? '',
  });
  globalThis.process.stdout.write(`verified ${health.commit}\n`);
}

if (import.meta.url === pathToFileURL(globalThis.process.argv[1]).href) {
  await main();
}
