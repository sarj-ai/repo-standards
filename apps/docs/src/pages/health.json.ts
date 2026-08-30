import type { APIRoute } from 'astro';

import { sourceRevision } from '../lib/source-revision';
import { catalog } from '../lib/catalog';

const payload = {
  status: 'ok',
  commit: sourceRevision,
  catalogVersion: catalog.catalog_version,
  catalogSchemaVersion: catalog.schema_version,
  catalogDigest: catalog.provenance.content_digest,
  rules: catalog.rules.length,
  commands: catalog.commands.length,
};

export const GET = (() => new Response(`${JSON.stringify(payload)}\n`, {
  headers: { 'Content-Type': 'application/json; charset=utf-8' },
})) satisfies APIRoute;
