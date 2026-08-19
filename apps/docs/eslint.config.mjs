import js from '@eslint/js';
import sarj from '@sarj/eslint-plugin';
import { defineConfig } from 'eslint/config';
import astro from 'eslint-plugin-astro';
import tseslint from 'typescript-eslint';

const sarjRules = Object.fromEntries(
  Object.keys(sarj.rules)
    .sort()
    .map((name) => [`@sarj/${name}`, 'error']),
);

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
    files: ['**/*.{astro,ts,mts,cts,mjs}'],
    plugins: { '@sarj': sarj },
    rules: sarjRules,
  },
  {
    files: ['**/*.astro'],
    rules: { '@sarj/prefer-shadcn-primitives': 'off' },
  },
);
