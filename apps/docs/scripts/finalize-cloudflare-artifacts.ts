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
const policy = extractPolicy(documents[0]?.[1] ?? '');
if (policy === undefined) throw new Error('Astro did not emit a Content Security Policy.');
verifyCompactReference(outputPaths, documents);

const hashes = new Set<string>();
for (const [, document] of documents) {
  for (const match of document.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gu)) {
    hashes.add(`'sha256-${createHash('sha256').update(match[1]).digest('base64')}'`);
  }
}
const completePolicy = appendHashes(policy, [...hashes].sort());
for (const [path, document] of documents) {
  await writeFile(new URL(path, outputDirectory), document.replace(policyPattern(), ''), 'utf8');
}

const headersUrl = new URL('_headers', outputDirectory);
const headers = await readFile(headersUrl, 'utf8');
if (!headers.startsWith('/*\n')) throw new Error('Cloudflare headers must begin with /*.');
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
