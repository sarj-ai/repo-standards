import { diffLines } from 'diff';

import type { Rule } from './catalog';

type UnknownRecord = Readonly<Record<string, unknown>>;

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
  return textField(rule, 'description') ?? textField(rule, 'summary') ?? rule.title;
}

export function ruleWhy(rule: Rule): string {
  return textField(rule, 'why') ?? textField(rule, 'impact') ?? ruleDescription(rule);
}

export function ruleFix(rule: Rule): string {
  const direct = textField(rule, 'fix');
  if (direct !== undefined) return direct;
  const remediation = field(rule, 'remediation');
  return isRecord(remediation) && typeof remediation.summary === 'string'
    ? remediation.summary
    : 'Update the repository so it satisfies this rule.';
}

export function ruleExamples(rule: Rule): readonly RuleExampleView[] {
  const rawExamples = field(rule, 'examples');
  if (!Array.isArray(rawExamples)) return [];
  return rawExamples.flatMap((value, index) => {
    if (!isRecord(value)) return [];
    const before = textField(value, 'before') ?? textField(value, 'flagged');
    const after = textField(value, 'after') ?? textField(value, 'passes');
    if (before === undefined || after === undefined) return [];
    const exampleId = textField(value, 'example_id') ?? textField(value, 'fixture_id') ?? `case-${String(index + 1)}`;
    return [{
      exampleId,
      title: textField(value, 'title') ?? `Case ${String(index + 1)}`,
      before,
      after,
      expectedSeverity: textField(value, 'expected_severity') ?? textField(value, 'severity') ?? 'error',
      language: textField(value, 'language') ?? inferLanguage(before),
      marks: changedLineMarks(before, after),
    }];
  });
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

function inferLanguage(value: string): string {
  const trimmed = value.trimStart();
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) return 'json';
  if (trimmed.startsWith('openapi:') || trimmed.startsWith('components:')) return 'yaml';
  if (trimmed.includes('[tool.') || trimmed.includes('[project')) return 'toml';
  return 'text';
}

function field(value: UnknownRecord, name: string): unknown {
  return value[name];
}

function textField(value: UnknownRecord, name: string): string | undefined {
  const candidate = field(value, name);
  return typeof candidate === 'string' && candidate.length > 0 ? candidate : undefined;
}

function isRecord(value: unknown): value is UnknownRecord {
  return typeof value === 'object' && value !== null;
}
