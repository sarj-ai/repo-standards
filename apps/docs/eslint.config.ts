import js from '@eslint/js';
import sarj from '@sarj/eslint-plugin';
import type { ESLint } from 'eslint';
import { defineConfig } from 'eslint/config';
import astro from 'eslint-plugin-astro';
import tseslint from 'typescript-eslint';

const optInSarjRules = new Set([
  'no-unlocalized-jsx-attributes',
  'no-unlocalized-jsx-text',
  'no-unlocalized-toast',
]);
const sarjRules: Record<string, 'error'> = Object.fromEntries(
  Object.keys(sarj.rules)
    .filter((name) => !optInSarjRules.has(name))
    .sort()
    .map((name) => [`@sarj/${name}`, 'error'] as const),
);
const sarjPlugin: ESLint.Plugin = {
  meta: sarj.meta,
  // The plugin publishes readonly default options; ESLint's config type expects mutable arrays.
  rules: sarj.rules as unknown as NonNullable<ESLint.Plugin['rules']>,
};

export default defineConfig(
  { ignores: ['.astro/**', 'dist/**', 'src/generated/**'] },
  js.configs.recommended,
  ...tseslint.configs.strictTypeChecked.map((config) => ({
    ...config,
    files: ['**/*.{ts,mts,cts}'],
  })),
  {
    files: ['**/*.{ts,mts,cts}'],
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },
  ...astro.configs['flat/recommended'],
  {
    files: ['**/*.{astro,ts,mts,cts}'],
    plugins: { '@sarj': sarjPlugin },
    rules: sarjRules,
  },
  {
    files: ['**/*.astro'],
    rules: { '@sarj/prefer-shadcn-primitives': 'off' },
  },
);
