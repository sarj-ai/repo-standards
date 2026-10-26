import type { APIRoute } from 'astro';

import { catalog, categoryHref } from '../lib/catalog';
import { SITE_ORIGIN, siteUrl } from '../lib/site';

const lines = [
  `# ${catalog.product.title}`,
  '',
  `> ${catalog.product.summary}`,
  '',
  '## Reference',
  '',
  `- [Rules](${siteUrl('/rules/')})`,
  `- [Git policies](${siteUrl('/git-policies/')})`,
  `- [CLI](${siteUrl('/cli/')})`,
  `- [Schemas](${siteUrl('/schemas/')})`,
  `- [Catalog JSON](${siteUrl('/api/catalog.json')})`,
  `- [Catalog schema](${siteUrl('/api/catalog.schema.json')})`,
  '',
  '## Rule categories',
  '',
  ...catalog.categories.map((category) => `- [${category.label}](${new URL(categoryHref(category["category_id"]), SITE_ORIGIN).href})`),
  '',
];

export const GET = (() => new Response(lines.join('\n'), {
  headers: { 'Content-Type': 'text/plain; charset=utf-8' },
})) satisfies APIRoute;
