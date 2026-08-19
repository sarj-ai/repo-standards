import type { APIRoute } from 'astro';

import { catalog, ruleHref } from '../lib/catalog';

const origin = catalog.product.website_url.replace(/\/$/u, '');
const lines = [
  `# ${catalog.product.title}`,
  '',
  catalog.product.summary,
  '',
  ...catalog.rules.flatMap((rule) => [
    `## ${rule.title}`,
    '',
    rule.summary,
    '',
    `Rule: ${rule.rule_id}. Version: ${String(rule.rule_version)}. Lifecycle: ${rule.lifecycle.status}. Severity: ${rule.default_severity}.`,
    '',
    `Detects: ${rule.detects}`,
    '',
    `Impact: ${rule.impact}`,
    '',
    `Fix: ${rule.remediation.summary}`,
    '',
    ...rule.examples.flatMap((example) => [
      `Flagged (${example.fixture_id}): ${example.flagged}`,
      '',
      `Passes: ${example.passes}`,
      '',
    ]),
    `Reference: ${origin}${ruleHref(rule)}`,
    '',
  ]),
];

export const GET = (() => new Response(lines.join('\n'), {
  headers: { 'Content-Type': 'text/plain; charset=utf-8' },
})) satisfies APIRoute;
