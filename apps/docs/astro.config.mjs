import starlight from '@astrojs/starlight';
import { defineConfig } from 'astro/config';

export default defineConfig({
  site: 'https://repo-standards.sarj.ai',
  output: 'static',
  trailingSlash: 'always',
  compressHTML: true,
  markdown: { syntaxHighlight: 'prism' },
  security: {
    csp: {
      directives: [
        "base-uri 'self'",
        "connect-src 'self'",
        "default-src 'none'",
        "font-src 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
        "img-src 'self' data:",
        "object-src 'none'",
      ],
      scriptDirective: {
        resources: [
          { resource: "'self'", kind: 'element' },
          { resource: "'wasm-unsafe-eval'", kind: 'element' },
        ],
      },
      styleDirective: { resources: [{ resource: "'unsafe-inline'", kind: 'attribute' }] },
    },
  },
  integrations: [
    starlight({
      title: 'Sarj Repo Standards',
      description: 'Deterministic repository policy and contract analysis.',
      favicon: '/sarj-logo-light.png',
      disable404Route: true,
      customCss: ['./src/styles/global.css'],
      sidebar: [
        { label: 'About', link: '/' },
        { label: 'Rules', link: '/rules/' },
        { label: 'CLI', link: '/cli/' },
        { label: 'Schemas', link: '/schemas/' },
      ],
      social: [
        { icon: 'github', label: 'GitHub', href: 'https://github.com/sarj-ai/repo-standards' },
      ],
      pagefind: true,
      tableOfContents: false,
      credits: false,
      components: { PageTitle: './src/components/PageTitle.astro' },
    }),
  ],
});
