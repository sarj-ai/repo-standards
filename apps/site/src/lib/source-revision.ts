import { settings } from "./settings.ts";

export const sourceRevision =
  settings.WORKERS_CI_COMMIT_SHA ?? settings.GITHUB_SHA ?? "main";
