import type { APIRoute } from 'astro';

import { SITE_BASE_PATH, SITE_URL } from '../lib/site';

const origin = SITE_URL.replace(/\/$/u, '');
const body = `User-agent: *
Allow: ${SITE_BASE_PATH}

Sitemap: ${origin}/sitemap-index.xml
`;

export const GET = (() => new Response(body, {
  headers: { 'Content-Type': 'text/plain; charset=utf-8' },
})) satisfies APIRoute;
