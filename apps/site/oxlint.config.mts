import { defineConfig, type OxlintConfig } from "oxlint";

import { createConfig, ignorePatterns } from "./oxlint.strict.mts";

const managed = createConfig({ testFrameworks: ["node"] });
const optInRules = new Set([
  "@sarj/no-unlocalized-jsx-attributes",
  "@sarj/no-unlocalized-jsx-text",
  "@sarj/no-unlocalized-toast",
]);

// Preserve the site's existing error-level Sarj policy and explicit opt-ins.
const sarjRules: NonNullable<OxlintConfig["rules"]> = Object.fromEntries(
  Object.entries(managed.rules ?? {})
    .filter(
      ([name, setting]) =>
        name.startsWith("@sarj/") &&
        !optInRules.has(name) &&
        setting !== "off" &&
        setting !== 0 &&
        (!Array.isArray(setting) || !["off", 0].includes(setting[0])),
    )
    .map(
      ([name, setting]): [
        string,
        NonNullable<OxlintConfig["rules"]>[string],
      ] => [
        name,
        Array.isArray(setting) ? ["error", ...setting.slice(1)] : "error",
      ],
    ),
);

export default defineConfig({
  extends: [managed],
  settings: managed.settings,
  ignorePatterns: [
    ...ignorePatterns,
    ".astro/**",
    "dist/**",
    "src/generated/**",
  ],
  rules: sarjRules,
  overrides: [
    {
      // These deployment validators run without the site's npm dependencies.
      // Their typeof checks validate raw JSON before any typed field access.
      files: [
        "scripts/finalize-cloudflare-artifacts.ts",
        "scripts/verify-deployment.ts",
      ],
      rules: { "@sarj/no-runtime-typeof": "off" },
    },
    {
      // The retry waits for each result; history workers each own one Git process.
      files: ["scripts/verify-deployment.ts", "src/lib/rule-introductions.ts"],
      rules: { "no-await-in-loop": "off" },
    },
    {
      // Astro generates these directories after lint; finalization validates their contents.
      files: ["astro.config.ts", "scripts/finalize-cloudflare-artifacts.ts"],
      rules: { "unicorn-js/no-missing-local-resource": "off" },
    },
    {
      files: ["**/*.astro"],
      rules: { "@sarj/prefer-shadcn-primitives": "off" },
    },
  ],
});
