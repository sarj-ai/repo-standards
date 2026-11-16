import { env } from "node:process";

import { z } from "astro/zod";

const RevisionSchema = z.string().optional();
export const settings = {
  WORKERS_CI_COMMIT_SHA: RevisionSchema.parse(env.WORKERS_CI_COMMIT_SHA),
  GITHUB_SHA: RevisionSchema.parse(env.GITHUB_SHA),
} as const;
