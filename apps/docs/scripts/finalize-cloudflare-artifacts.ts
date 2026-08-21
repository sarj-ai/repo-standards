import { createHash } from 'node:crypto';
import { readFile, readdir, writeFile } from 'node:fs/promises';

const outputDirectory = new URL('../dist/', import.meta.url);
const htmlPaths = (await readdir(outputDirectory, { recursive: true }))
  .filter((path) => path.endsWith('.html'))
  .sort();
const outputPaths = await readdir(outputDirectory, { recursive: true });
const documents = await Promise.all(
  htmlPaths.map(
    async (path) => [path, await readFile(new URL(path, outputDirectory), 'utf8')] as const,
  ),
);
await verifySearchDiscovery(outputDirectory, documents);
const policy = extractPolicy(documents[0]?.[1] ?? '');
if (policy === undefined) throw new Error('Astro did not emit a Content Security Policy.');
verifyCompactReference(outputPaths, documents);

const hashes = new Set<string>();
for (const [, document] of documents) {
  for (const match of document.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gu)) {
    hashes.add(`'sha256-${createHash('sha256').update(match[1]).digest('base64')}'`);
  }
}

async function verifySearchDiscovery(
  directory: URL,
  pages: readonly (readonly [string, string])[],
): Promise<void> {
  const catalogValue: unknown = JSON.parse(
    await readFile(new URL('../src/generated/catalog.json', import.meta.url), 'utf8'),
  );
  const catalog = parseDiscoveryCatalog(catalogValue);
  const sitemapIndex = await readFile(new URL('sitemap-index.xml', directory), 'utf8');
  if (!sitemapIndex.includes('https://repo-standards.sarj.ai/sitemap-0.xml')) {
    throw new Error('Sitemap index does not reference the canonical repo-standards sitemap.');
  }
  const sitemap = await readFile(new URL('sitemap-0.xml', directory), 'utf8');
  const locations = new Set(
    [...sitemap.matchAll(/<loc>([^<]+)<\/loc>/gu)].map((match) => match[1]),
  );
  const expected = [
    'https://repo-standards.sarj.ai/review/',
    ...catalog.rules.map((rule: { slug: string }) => `https://repo-standards.sarj.ai/rules/${rule.slug}/`),
  ];
  for (const location of expected) {
    if (!locations.has(location)) throw new Error(`Indexable page is missing from the sitemap: ${location}`);
  }

  const pagesByPath = new Map(pages);
  for (const location of locations) {
    const url = new URL(location);
    if (url.origin !== 'https://repo-standards.sarj.ai') {
      throw new Error(`Cross-origin sitemap URL: ${location}`);
    }
    const path = url.pathname === '/' ? 'index.html' : `${url.pathname.slice(1)}index.html`;
    const document = pagesByPath.get(path);
    if (document === undefined) throw new Error(`Sitemap URL has no rendered page: ${location}`);
    if (/name="robots" content="[^"]*noindex/iu.test(document)) {
      throw new Error(`Sitemap URL is marked noindex: ${location}`);
    }
    if (!document.includes(`rel="canonical" href="${location}"`)) {
      throw new Error(`Sitemap URL is missing its self-canonical link: ${location}`);
    }
  }

  for (const rule of catalog.rules.filter((candidate: { review: { status: string } }) => candidate.review.status === 'pending')) {
    const path = `rules/${rule.slug}/index.html`;
    const document = pagesByPath.get(path) ?? '';
    if (!document.includes('Pending review') || !document.includes('not yet approved for enforcement')) {
      throw new Error(`Pending rule is missing search-visible review status: ${rule.slug}`);
    }
  }

  const notFound = pagesByPath.get('404.html') ?? '';
  if (!/name="robots" content="[^"]*noindex/iu.test(notFound)) {
    throw new Error('The 404 page must remain noindex.');
  }
}

interface DiscoveryCatalog {
  readonly rules: readonly DiscoveryRule[];
}

interface DiscoveryRule {
  readonly review: { readonly status: string };
  readonly slug: string;
}

function parseDiscoveryCatalog(value: unknown): DiscoveryCatalog {
  if (!isRecord(value) || !Array.isArray(value.rules)) {
    throw new Error('Generated catalog is missing its rule collection.');
  }
  const rules = value.rules.map((candidate) => {
    if (
      !isRecord(candidate)
      || typeof candidate.slug !== 'string'
      || !isRecord(candidate.review)
      || typeof candidate.review.status !== 'string'
    ) {
      throw new Error('Generated catalog contains an invalid rule descriptor.');
    }
    return { slug: candidate.slug, review: { status: candidate.review.status } };
  });
  return { rules };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}
const completePolicy = appendHashes(policy, [...hashes].sort());
for (const [path, document] of documents) {
  await writeFile(new URL(path, outputDirectory), document.replace(policyPattern(), ''), 'utf8');
}

const headersUrl = new URL('_headers', outputDirectory);
const headers = await readFile(headersUrl, 'utf8');
if (!headers.startsWith('/*\n')) throw new Error('Cloudflare headers must begin with /*.');
if (/^\s*X-Robots-Tag:/imu.test(headers)) {
  throw new Error('Indexing directives must be expressed per page, not as a global response header.');
}
await writeFile(
  headersUrl,
  headers.replace('/*\n', `/*\n  Content-Security-Policy: ${completePolicy}\n`),
  'utf8',
);

function policyPattern(): RegExp {
  return /<meta http-equiv="content-security-policy" content="([^"]+)">/u;
}

function extractPolicy(document: string): string | undefined {
  return policyPattern().exec(document)?.[1];
}

function appendHashes(policy: string, hashes: string[]): string {
  const pattern = /(script-src-elem [^;]*)(;)/u;
  const directive = pattern.exec(policy)?.[1];
  if (directive === undefined) throw new Error('Content Security Policy is missing script-src-elem.');
  const additions = hashes.filter((hash) => !directive.includes(hash));
  return policy.replace(pattern, `$1 ${additions.join(' ')}$2`);
}

function verifyCompactReference(
  paths: readonly string[],
  pages: readonly (readonly [string, string])[],
): void {
  const forbiddenPath = paths.find((path) => /(^|\/)pagefind(\/|$)|(^|\/)llms-full\.txt$/iu.test(path));
  if (forbiddenPath !== undefined) throw new Error(`Forbidden search or duplicate LLM artifact: ${forbiddenPath}`);
  const forbiddenMarkup = pages.find(([, document]) => /data-pagefind|pagefind-ui|aria-keyshortcuts=["'][^"']*(?:Meta|Control|Mod)\+K/iu.test(document));
  if (forbiddenMarkup !== undefined) throw new Error(`Search UI or Cmd/Ctrl-K shortcut found in ${forbiddenMarkup[0]}`);
}
