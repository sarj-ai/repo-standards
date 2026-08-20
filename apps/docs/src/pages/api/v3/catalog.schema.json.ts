import type { APIRoute } from 'astro';

import { catalog } from '../../../lib/catalog';

const schema = catalog.schemas.find((candidate) => candidate.schema_id === 'catalog');
if (schema === undefined) throw new Error('Catalog schema is missing from the generated catalog.');

export const GET = (() => new Response(`${JSON.stringify(schema.document)}\n`, {
  headers: { 'Content-Type': 'application/schema+json; charset=utf-8' },
})) satisfies APIRoute;
