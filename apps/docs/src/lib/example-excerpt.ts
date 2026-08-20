interface ExampleExcerpt {
  readonly flagged: string;
  readonly passes: string;
  readonly compacted: boolean;
}

type Difference = { readonly path: string; readonly flagged: unknown; readonly passes: unknown };
const INVALID_JSON = Symbol('invalid-json');

export function exampleExcerpt(flagged: string, passes: string, language: string): ExampleExcerpt {
  if (language !== 'json' || (flagged.length <= 520 && passes.length <= 520)) {
    return { flagged, passes, compacted: false };
  }
  const left = parsedJson(flagged);
  const right = parsedJson(passes);
  if (left === INVALID_JSON || right === INVALID_JSON) return { flagged, passes, compacted: false };
  const differences: Difference[] = [];
  collectDifferences(left, right, '', differences);
  if (differences.length === 0) return { flagged, passes, compacted: false };
  const prefix = sharedPathPrefix(differences.map((item) => item.path));
  const flaggedExcerpt = Object.fromEntries(differences.map((item) => [item.path.slice(prefix.length), excerptValue(item.flagged)]));
  const passesExcerpt = Object.fromEntries(differences.map((item) => [item.path.slice(prefix.length), excerptValue(item.passes)]));
  return {
    flagged: JSON.stringify(flaggedExcerpt, null, 2),
    passes: JSON.stringify(passesExcerpt, null, 2),
    compacted: true,
  };
}

function sharedPathPrefix(paths: readonly string[]): string {
  if (paths.length < 2) return '';
  const segments = paths[0]?.split('.') ?? [];
  let count = segments.length - 1;
  for (const path of paths.slice(1)) {
    const candidate = path.split('.');
    let shared = 0;
    while (shared < count && candidate[shared] === segments[shared]) shared += 1;
    count = shared;
    if (count === 0) return '';
  }
  return `${segments.slice(0, count).join('.')}.`;
}

function parsedJson(value: string): unknown {
  try {
    return JSON.parse(value) as unknown;
  } catch {
    return INVALID_JSON;
  }
}

function collectDifferences(flagged: unknown, passes: unknown, path: string, output: Difference[]): void {
  if (output.length >= 6 || Object.is(flagged, passes)) return;
  if (typeof flagged === 'string' && typeof passes === 'string') {
    const nestedFlagged = parsedJson(flagged);
    const nestedPasses = parsedJson(passes);
    if (nestedFlagged !== INVALID_JSON && nestedPasses !== INVALID_JSON) {
      collectDifferences(nestedFlagged, nestedPasses, path, output);
      return;
    }
  }
  if (Array.isArray(flagged) && Array.isArray(passes)) {
    for (let index = 0; index < Math.max(flagged.length, passes.length); index += 1) {
      collectDifferences(flagged[index], passes[index], `${path}[${String(index)}]`, output);
    }
    return;
  }
  if (flagged !== null && passes !== null && typeof flagged === 'object' && typeof passes === 'object') {
    const left = flagged as Record<string, unknown>;
    const right = passes as Record<string, unknown>;
    for (const key of [...new Set([...Object.keys(left), ...Object.keys(right)])].toSorted()) {
      collectDifferences(left[key], right[key], path === '' ? key : `${path}.${key}`, output);
    }
    return;
  }
  output.push({ path: path || 'value', flagged, passes });
}

function excerptValue(value: unknown): unknown {
  if (value === undefined) return '<missing>';
  const rendered = typeof value === 'string' ? value : JSON.stringify(value);
  if (rendered.length <= 20) return value;
  return `${rendered.slice(0, 17)}…`;
}
