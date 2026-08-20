import type { APIRoute } from 'astro';

import { catalog, categoryHref } from '../lib/catalog';

const origin = catalog.product.website_url.replace(/\/$/u, '');
const lines = [
  `# ${catalog.product.title}`,
  '',
  `> ${catalog.product.summary}`,
  '',
  '## Reference',
  '',
  `- [Rules](${origin}/rules/)`,
  `- [CLI](${origin}/cli/)`,
  `- [Schemas](${origin}/schemas/)`,
  `- [Catalog JSON](${origin}/api/v5/catalog.json)`,
  `- [Catalog schema](${origin}/api/v5/catalog.schema.json)`,
  '',
  '## Rule categories',
  '',
  ...catalog.categories.map((category) => `- [${category.label}](${origin}${categoryHref(category.category_id)})`),
  '',
  `Complete text: ${origin}/llms-full.txt`,
  '',
];

export const GET = (() => new Response(lines.join('\n'), {
  headers: { 'Content-Type': 'text/plain; charset=utf-8' },
})) satisfies APIRoute;
