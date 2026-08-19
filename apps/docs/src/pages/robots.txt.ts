import type { APIRoute } from 'astro';

import { catalog } from '../lib/catalog';

const origin = catalog.product.website_url.replace(/\/$/u, '');
const body = `User-agent: *
Allow: /

Sitemap: ${origin}/sitemap-index.xml
`;

export const GET = (() => new Response(body, {
  headers: { 'Content-Type': 'text/plain; charset=utf-8' },
})) satisfies APIRoute;
