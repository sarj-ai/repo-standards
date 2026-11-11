import { changedLineMarks } from "@sarj/design/line-diff";

import type { Rule } from "./catalog";

export interface RuleExampleView {
  readonly exampleId: string;
  readonly title: string;
  readonly before: string;
  readonly after: string;
  readonly expectedSeverity: string;
  readonly language: string;
  readonly marks: {
    readonly before: { readonly range: string } | undefined;
    readonly after: { readonly range: string } | undefined;
  };
}

const DESCRIPTIONS = {
  "repository/artifacts/bespoke-iac-verifiers":
    "Keep verifiers in owned tools.",
  "repository/artifacts/local-residue": "Review tracked caches and bytecode.",
  "repository/artifacts/makefile-growth":
    "New or larger Makefiles need an exception.",
  "repository/artifacts/migration-consolidation":
    "Review multiple new SQL migrations per stream.",
  "repository/artifacts/operational-script-tests":
    "Review tests in operational directories.",
  "repository/artifacts/schema-derived-config-examples":
    "Generate config examples from schemas.",
  "repository/artifacts/terraform-examples": "Document inputs in variables.tf.",
  "repository/artifacts/terraform-test-files":
    "Replace .tftest files; preserve coverage.",
  "repository/artifacts/undeclared-images":
    "Declare each tracked image’s purpose.",
  "repository/artifacts/untyped-javascript":
    "Use TypeScript or declare required JS.",
  "repository/documentation/placement": "Keep Markdown in owned locations.",
  "repository/documentation/pull-request-template-sections":
    "Include required PR template headings.",
} as const satisfies Record<Rule["rule_id"], string>;

export function ruleDescription(rule: Rule): string {
  return DESCRIPTIONS[rule["rule_id"]];
}

export function ruleExamples(rule: Rule): readonly RuleExampleView[] {
  return rule.examples.map((example) => ({
    exampleId: example.id,
    title: example.title,
    before: example.before,
    after: example.after,
    expectedSeverity: example["expected_severity"],
    language: example.language,
    marks: changedLineMarks(example.before, example.after),
  }));
}
