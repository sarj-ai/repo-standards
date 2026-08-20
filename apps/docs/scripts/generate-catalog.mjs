import { mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { env, exit, stderr } from 'node:process';

const appDirectory = resolve(import.meta.dirname, '..');
const repositoryDirectory = resolve(appDirectory, '../..');
const generatedDirectory = resolve(appDirectory, 'src/generated');
const result = spawnSync(
  'uv',
  ['run', '--project', repositoryDirectory, '--frozen', 'repo-standards', 'catalog'],
  {
    cwd: repositoryDirectory,
    encoding: 'utf8',
    env: {
      ...env,
      UV_CACHE_DIR: env.UV_CACHE_DIR ?? resolve(tmpdir(), 'repo-standards-uv'),
    },
  },
);
if (result.status !== 0) {
  stderr.write(result.stderr);
  exit(result.status ?? 1);
}
const parsed = JSON.parse(result.stdout);
mkdirSync(generatedDirectory, { recursive: true });
writeFileSync(resolve(generatedDirectory, 'catalog.json'), result.stdout, 'utf8');
writeFileSync(
  resolve(generatedDirectory, 'catalog.generated.ts'),
  `export const generatedCatalog = ${JSON.stringify(parsed)} as const;\n`,
  'utf8',
);
