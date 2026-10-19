import sitemap from '@astrojs/sitemap';
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
        ],
      },
      styleDirective: { resources: [{ resource: "'unsafe-inline'", kind: 'attribute' }] },
    },
  },
  integrations: [
    sitemap(),
    starlight({
      title: 'Sarj Repo Standards',
      description: 'Deterministic repository policy and contract analysis.',
      favicon: '/favicon.ico',
      logo: {
        alt: 'Sarj',
        dark: './public/sarj-logo-dark.webp',
        light: './public/sarj-logo-light.webp',
        replacesTitle: true,
      },
      disable404Route: true,
      expressiveCode: {
        styleOverrides: {
          borderRadius: '4px',
          borderColor: 'var(--rs-line)',
          codeFontFamily: 'var(--rs-font-mono)',
          codeFontSize: '0.8125rem',
          codeLineHeight: '1.7',
          uiFontFamily: 'var(--rs-font-sans)',
          uiFontSize: '0.8125rem',
          frames: {
            editorActiveTabIndicatorTopColor: 'transparent',
            editorActiveTabIndicatorBottomColor: 'transparent',
            editorTabBarBorderBottomColor: 'var(--rs-line)',
            terminalTitlebarBorderBottomColor: 'var(--rs-line)',
          },
          textMarkers: {
            delBackground: 'var(--rs-diff-del-bg)',
            delBorderColor: 'var(--rs-diff-del-line)',
            delDiffIndicatorColor: 'var(--rs-report)',
            insBackground: 'var(--rs-diff-ins-bg)',
            insBorderColor: 'var(--rs-diff-ins-line)',
            insDiffIndicatorColor: 'var(--rs-pass)',
          },
        },
      },
      customCss: ['./src/styles/global.css'],
      sidebar: [
        { label: 'About', link: '/' },
        { label: 'Rules', link: '/rules/' },
        { label: 'Git policies', link: '/git-policies/' },
        { label: 'CLI', link: '/cli/' },
        { label: 'Schemas', link: '/schemas/' },
      ],
      social: [
        { icon: 'github', label: 'GitHub', href: 'https://github.com/sarj-ai/repo-standards' },
      ],
      pagefind: false,
      tableOfContents: false,
      credits: false,
      components: {
        PageTitle: './src/components/PageTitle.astro',
      },
    }),
  ],
});
