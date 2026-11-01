import rawCatalogJson from '../generated/catalog.json?raw';
import { resolve } from 'node:path';
import { readFile, readdir } from 'node:fs/promises';
import { generatedCatalog } from '../generated/catalog.generated';
import { siteHref } from './site';
import { ruleIntroductions, type RuleIntroduction } from './rule-introductions';

export const catalog = generatedCatalog;
export const catalogJson = rawCatalogJson;
const repositoryDirectory = resolve(process.cwd(), '../..');
const policyDirectory = 'src/repo_standards/policy_sarj';
const definitions = await Promise.all((await readdir(resolve(repositoryDirectory, policyDirectory)))
  .filter((name) => name.endsWith('.py'))
  .map(async (name) => {
    const path = `${policyDirectory}/${name}`;
    return { path, source: await readFile(resolve(repositoryDirectory, path), 'utf8') };
  }));
const introductions = await ruleIntroductions(repositoryDirectory, catalog.rules.flatMap((rule) => {
  const id = rule["rule_id"];
  const paths = new Set([rule.source.path, ...definitions.filter((file) => file.source.includes(id)).map((file) => file.path)]);
  return [...paths].map((path) => ({ id, path, marker: id }));
}));
export type Rule = Catalog['rules'][number];
export type Parameter = Command['options'][number] | Command['arguments'][number];

type Catalog = typeof catalog;
type Category = Catalog['categories'][number];
type Topic = Category['topics'][number];
type Command = Catalog['commands'][number];

export interface RuleView {
  readonly rule: Rule;
  readonly href: string;
  readonly category: string;
  readonly introduction: RuleIntroduction | null;
}

interface TopicView {
  readonly topic: Topic;
  readonly rules: readonly RuleView[];
}

export interface CategoryView {
  readonly category: Category;
  readonly topics: readonly TopicView[];
  readonly ruleCount: number;
}

function ruleHref(rule: Rule): string {
  return siteHref(`/rules/${encodeURIComponent(rule.slug)}/`);
}

function categoryPath(value: string): string {
  return `/rules/categories/${encodeURIComponent(value)}/`;
}

export function categoryHref(value: string): string {
  return siteHref(categoryPath(value));
}

export const referenceCatalog: readonly CategoryView[] = catalog.categories
  .toSorted((left, right) => left.order - right.order)
  .map((categoryValue) => {
    const topics = categoryValue.topics
      .toSorted((left, right) => left.order - right.order)
      .map((topicValue) => {
        const rules = catalog.rules
          .filter((rule) => rule["topic_id"] === topicValue["topic_id"])
          .toSorted((left, right) => left.title.localeCompare(right.title, 'en'))
          .map((rule) => ({
            rule,
            href: ruleHref(rule),
            category: categoryValue.label,
            introduction: introductions.get(rule["rule_id"]) ?? null,
          }));
        if (rules.length === 0) throw new TypeError(`Rule topic has no rules: ${topicValue["topic_id"]}`);
        return { topic: topicValue, rules };
      });
    return {
      category: categoryValue,
      topics,
      ruleCount: topics.reduce((total, topicValue) => total + topicValue.rules.length, 0),
    };
  });

export function rulePage(rule: Rule) {
  const categoryValue = referenceCatalog.find((item) =>
    item.topics.some((topic) => topic.topic["topic_id"] === rule["topic_id"]));
  const topicValue = categoryValue?.topics.find((item) => item.topic["topic_id"] === rule["topic_id"]);
  const peerRules = referenceCatalog.flatMap((category) => category.topics)
    .flatMap((topic) => topic.rules);
  const index = peerRules.findIndex((item) => item.rule["rule_id"] === rule["rule_id"]);
  if (categoryValue === undefined || topicValue === undefined || index < 0) {
    throw new TypeError(`Rule is not present in the reference catalog: ${rule["rule_id"]}`);
  }
  return {
    category: categoryValue,
    topic: topicValue,
    current: peerRules[index],
    previous: index > 0 ? peerRules[index - 1] : undefined,
    next: index < peerRules.length - 1 ? peerRules[index + 1] : undefined,
  };
}

export function referenceSidebar() {
  return [
    { label: 'About', link: '/' },
    {
      label: 'Rules',
      items: [
        { label: `All (${String(catalog.rules.length)})`, link: '/rules/' },
        ...referenceCatalog
          .map((value) => ({
            label: value.category.label,
            link: categoryPath(value.category["category_id"]),
            attrs: { 'data-sidebar-category': value.category["category_id"] },
          })),
      ],
    },
    { label: 'Git policies', link: '/git-policies/' },
    { label: 'CLI', link: '/cli/' },
    { label: 'Schemas', link: '/schemas/' },
  ];
}
