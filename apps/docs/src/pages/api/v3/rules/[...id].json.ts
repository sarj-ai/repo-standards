import type { APIRoute, GetStaticPaths } from 'astro';

import { catalog } from '../../../../lib/catalog';

export const getStaticPaths = (() => catalog.rules.map((rule) => ({
  params: { id: rule.rule_id },
}))) satisfies GetStaticPaths;

export const GET = (({ params }) => {
  const rule = catalog.rules.find((candidate) => candidate.rule_id === params.id);
  if (rule === undefined) return new Response('Not found', { status: 404 });
  return new Response(`${JSON.stringify(rule)}\n`, {
    headers: { 'Content-Type': 'application/json; charset=utf-8' },
  });
}) satisfies APIRoute;
