import { env } from 'node:process';

export const sourceRevision = env.WORKERS_CI_COMMIT_SHA
  ?? env.GITHUB_SHA
  ?? 'main';
