import rawCatalogJson from '../generated/catalog.json?raw';
import rawCatalogV2Json from '../generated/catalog-v2.json?raw';
import { generatedCatalog } from '../generated/catalog.generated';
import { generatedCatalogV2 } from '../generated/catalog-v2.generated';

export const catalog = generatedCatalog;
export const catalogJson = rawCatalogJson;
export const catalogV2Json = rawCatalogV2Json;
export const catalogV2 = generatedCatalogV2;
export type Catalog = typeof catalog;
export type Rule = Catalog['rules'][number];
export type Category = Catalog['categories'][number];
export type Topic = Category['topics'][number];
export type Command = Catalog['commands'][number];
export type Parameter = Command['options'][number] | Command['arguments'][number];

export interface RuleView {
  readonly rule: Rule;
  readonly href: string;
  readonly searchText: string;
}

export interface TopicView {
  readonly topic: Topic;
  readonly rules: readonly RuleView[];
}

export interface CategoryView {
  readonly category: Category;
  readonly topics: readonly TopicView[];
  readonly ruleCount: number;
}

export function ruleHref(rule: Rule): string {
  const [first, ...rest] = rule.rule_id.split('/');
  if (rest.length < 2 || [first, ...rest].some((part) => part === '' || part === '.' || part === '..')) {
    throw new TypeError(`Invalid rule route id: ${rule.rule_id}`);
  }
  return `/rules/${encodeURIComponent(first)}/${rest.map(encodeURIComponent).join('/')}/`;
}

export function categoryHref(value: string): string {
  return `/rules/categories/${encodeURIComponent(value)}/`;
}

export const referenceCatalog: readonly CategoryView[] = catalog.categories
  .toSorted((left, right) => left.order - right.order)
  .map((categoryValue) => {
    const topics = categoryValue.topics
      .toSorted((left, right) => left.order - right.order)
      .map((topicValue) => {
        const rules = catalog.rules
          .filter((rule) => rule.category_id === categoryValue.category_id && rule.topic_id === topicValue.topic_id)
          .toSorted((left, right) => left.title.localeCompare(right.title, 'en'))
          .map((rule) => ({
            rule,
            href: ruleHref(rule),
            searchText: `${rule.title} ${rule.summary} ${rule.rule_id} ${categoryValue.label} ${topicValue.label} ${rule.tags.join(' ')}`.toLocaleLowerCase('en'),
          }));
        if (rules.length === 0) throw new TypeError(`Rule topic has no rules: ${topicValue.topic_id}`);
        return { topic: topicValue, rules };
      });
    return {
      category: categoryValue,
      topics,
      ruleCount: topics.reduce((total, topicValue) => total + topicValue.rules.length, 0),
    };
  });

function hasReviewStatus(rule: { readonly review: { readonly status: string } }, status: string): boolean {
  return rule.review.status === status;
}

export const approvedRules = catalog.rules.filter((rule) => hasReviewStatus(rule, 'approved'));
export const pendingRules = catalog.rules.filter((rule) => hasReviewStatus(rule, 'pending'));
const approvedRuleIds = new Set(approvedRules.map((rule) => rule.rule_id));

export function rulePage(rule: Rule) {
  const categoryValue = referenceCatalog.find((item) => item.category.category_id === rule.category_id);
  const topicValue = categoryValue?.topics.find((item) => item.topic.topic_id === rule.topic_id);
  const index = topicValue?.rules.findIndex((item) => item.rule.rule_id === rule.rule_id) ?? -1;
  if (categoryValue === undefined || topicValue === undefined || index < 0) {
    throw new TypeError(`Rule is not present in the reference catalog: ${rule.rule_id}`);
  }
  return {
    category: categoryValue,
    topic: topicValue,
    current: topicValue.rules[index],
    previous: index > 0 ? topicValue.rules[index - 1] : undefined,
    next: index < topicValue.rules.length - 1 ? topicValue.rules[index + 1] : undefined,
  };
}

export function referenceSidebar() {
  return [
    { label: 'Overview', link: '/' },
    {
      label: 'Rules',
      items: [
        { label: `Approved (${String(approvedRules.length)})`, link: '/rules/' },
        { label: `Review (${String(pendingRules.length)})`, link: '/review/' },
        ...referenceCatalog
          .filter((value) => value.topics.some((topic) => topic.rules.some(({ rule }) => approvedRuleIds.has(rule.rule_id))))
          .map((value) => ({
            label: value.category.label,
            link: categoryHref(value.category.category_id),
          })),
      ],
    },
    { label: 'CLI', link: '/cli/' },
    { label: 'Schemas', link: '/schemas/' },
  ];
}
