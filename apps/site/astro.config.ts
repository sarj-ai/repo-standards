import { rm } from "node:fs/promises";

import sitemap from "@astrojs/sitemap";
import starlight from "@astrojs/starlight";
import { defineConfig } from "astro/config";

import { SITE_BASE_PATH, SITE_ORIGIN } from "./src/lib/site.ts";

const ASSET_ROOT = new URL("dist/", import.meta.url);

export default defineConfig({
  site: SITE_ORIGIN,
  base: SITE_BASE_PATH,
  outDir: `./dist${SITE_BASE_PATH}`,
  output: "static",
  trailingSlash: "always",
  compressHTML: true,
  markdown: { syntaxHighlight: "prism" },
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
        resources: [{ resource: "'self'", kind: "element" }],
      },
      styleDirective: {
        resources: [{ resource: "'unsafe-inline'", kind: "attribute" }],
      },
    },
  },
  integrations: [
    {
      name: "repo-standards-clean-static-output",
      hooks: {
        "astro:build:start": () =>
          rm(ASSET_ROOT, { recursive: true, force: true }),
      },
    },
    sitemap(),
    starlight({
      title: "Sarj Repo Standards",
      description: "Deterministic repository policy and contract analysis.",
      favicon: "/favicon.ico",
      logo: {
        alt: "Sarj",
        dark: "./public/sarj-logo-dark.webp",
        light: "./public/sarj-logo-light.webp",
        replacesTitle: true,
      },
      disable404Route: true,
      customCss: ["./src/styles/global.css"],
      sidebar: [
        { label: "Overview", link: "/" },
        { label: "Getting started", link: "/getting-started/" },
        { label: "Rules", link: "/rules/" },
        { label: "Git policies", link: "/git-policies/" },
        { label: "CLI", link: "/cli/" },
        { label: "Schemas", link: "/schemas/" },
      ],
      social: [
        {
          icon: "github",
          label: "GitHub",
          href: "https://github.com/sarj-ai/repo-standards",
        },
      ],
      pagefind: false,
      tableOfContents: false,
      credits: false,
      components: {
        Search: "./src/components/disabled-feature.astro",
        TableOfContents: "./src/components/disabled-feature.astro",
        MobileTableOfContents: "./src/components/disabled-feature.astro",
        SiteTitle: "./src/components/project-navigation.astro",
        PageTitle: "./src/components/page-title.astro",
      },
    }),
  ],
});
