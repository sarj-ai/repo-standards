import { changedLineMarks } from '@sarj/design/line-diff';

import type { Rule } from './catalog';

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

export function ruleDescription(rule: Rule): string {
  return rule.description;
}

export function ruleWhy(rule: Rule): string {
  return rule.why;
}

export function ruleFix(rule: Rule): string {
  return rule.fix;
}

export function ruleExamples(rule: Rule): readonly RuleExampleView[] {
  return rule.examples.map((example) => ({
    exampleId: example.id,
    title: example.title,
    before: example.before,
    after: example.after,
    expectedSeverity: example.expected_severity,
    language: example.language,
    marks: changedLineMarks(example.before, example.after),
  }));
}
