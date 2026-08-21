import type { APIRoute, GetStaticPaths } from 'astro';

import { catalog } from '../../../../lib/catalog';

export const getStaticPaths = (() => catalog.schemas.map((schema) => ({
  params: { id: schema.schema_id },
}))) satisfies GetStaticPaths;

export const GET = (({ params }) => {
  const schema = catalog.schemas.find((candidate) => candidate.schema_id === params.id);
  if (schema === undefined) return new Response('Not found', { status: 404 });
  return new Response(`${JSON.stringify(schema.document)}\n`, {
    headers: { 'Content-Type': 'application/schema+json; charset=utf-8' },
  });
}) satisfies APIRoute;
