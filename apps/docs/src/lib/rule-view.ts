import { diffLines } from 'diff';

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

function changedLineMarks(before: string, after: string): RuleExampleView['marks'] {
  const beforeLines: number[] = [];
  const afterLines: number[] = [];
  let beforeLine = 1;
  let afterLine = 1;
  for (const change of diffLines(before, after)) {
    const count = change.count;
    if (change.removed) {
      addLines(beforeLines, beforeLine, count);
      beforeLine += count;
    } else if (change.added) {
      addLines(afterLines, afterLine, count);
      afterLine += count;
    } else {
      beforeLine += count;
      afterLine += count;
    }
  }
  return { before: lineSpec(beforeLines), after: lineSpec(afterLines) };
}

function addLines(output: number[], first: number, count: number): void {
  for (let offset = 0; offset < count; offset += 1) output.push(first + offset);
}

function lineSpec(lines: readonly number[]): { readonly range: string } | undefined {
  if (lines.length === 0) return undefined;
  const ranges: string[] = [];
  let first = lines[0] ?? 1;
  let last = first;
  for (const line of lines.slice(1)) {
    if (line === last + 1) {
      last = line;
      continue;
    }
    ranges.push(first === last ? String(first) : `${String(first)}-${String(last)}`);
    first = line;
    last = line;
  }
  ranges.push(first === last ? String(first) : `${String(first)}-${String(last)}`);
  return { range: ranges.join(',') };
}
