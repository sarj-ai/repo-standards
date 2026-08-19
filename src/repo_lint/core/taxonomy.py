from __future__ import annotations

from dataclasses import dataclass

from repo_lint.core.models import RuleCategoryId, RuleTaxonomy, RuleTopicId


@dataclass(frozen=True, slots=True)
class RuleTopic:
    topic_id: RuleTopicId
    label: str
    order: int


@dataclass(frozen=True, slots=True)
class RuleCategory:
    category_id: RuleCategoryId
    label: str
    order: int
    topics: tuple[RuleTopic, ...]


ARCHITECTURE = RuleCategoryId("architecture")
DELIVERY = RuleCategoryId("delivery")
CHANGE_SAFETY = RuleCategoryId("change-safety")
API_CONTRACTS = RuleCategoryId("api-contracts")

DEPENDENCY_BOUNDARIES = RuleTopicId("dependency-boundaries")
REPOSITORY_LAYOUT = RuleTopicId("repository-layout")
NAMING = RuleTopicId("naming")
REUSE = RuleTopicId("reuse")
COMPONENT_SCHEMA = RuleTopicId("component-schema")
GITHUB_ACTIONS = RuleTopicId("github-actions")
REPOSITORY_GOVERNANCE = RuleTopicId("repository-governance")
RELEASE_FLOW = RuleTopicId("release-flow")
MIGRATIONS = RuleTopicId("migrations")
BASELINES = RuleTopicId("baselines")
EXCEPTIONS = RuleTopicId("exceptions")
API_SECURITY = RuleTopicId("api-security")
HTTP_SEMANTICS = RuleTopicId("http-semantics")
GENERATED_ARTIFACTS = RuleTopicId("generated-artifacts")
ERROR_CONTRACTS = RuleTopicId("error-contracts")
API_LIFECYCLE = RuleTopicId("api-lifecycle")
REFERENCES = RuleTopicId("references")

CATEGORIES = (
    RuleCategory(
        category_id=ARCHITECTURE,
        label="Architecture & ownership",
        order=10,
        topics=(
            RuleTopic(DEPENDENCY_BOUNDARIES, "Dependency boundaries", 10),
            RuleTopic(REPOSITORY_LAYOUT, "Repository layout", 20),
            RuleTopic(NAMING, "Naming", 30),
            RuleTopic(REUSE, "Reuse", 40),
            RuleTopic(COMPONENT_SCHEMA, "Component schema", 50),
        ),
    ),
    RuleCategory(
        category_id=DELIVERY,
        label="Delivery & CI",
        order=20,
        topics=(
            RuleTopic(GITHUB_ACTIONS, "GitHub Actions", 10),
            RuleTopic(REPOSITORY_GOVERNANCE, "Repository governance", 20),
            RuleTopic(RELEASE_FLOW, "Release flow", 30),
        ),
    ),
    RuleCategory(
        category_id=CHANGE_SAFETY,
        label="Change safety",
        order=30,
        topics=(
            RuleTopic(MIGRATIONS, "Migrations", 10),
            RuleTopic(BASELINES, "Baselines", 20),
            RuleTopic(EXCEPTIONS, "Exceptions", 30),
        ),
    ),
    RuleCategory(
        category_id=API_CONTRACTS,
        label="API contracts",
        order=40,
        topics=(
            RuleTopic(API_SECURITY, "API security", 10),
            RuleTopic(HTTP_SEMANTICS, "HTTP semantics", 20),
            RuleTopic(GENERATED_ARTIFACTS, "Generated artifacts", 30),
            RuleTopic(ERROR_CONTRACTS, "Error contracts", 40),
            RuleTopic(API_LIFECYCLE, "API lifecycle", 50),
            RuleTopic(REFERENCES, "References", 60),
        ),
    ),
)


def taxonomy(category_id: RuleCategoryId, topic_id: RuleTopicId, *tags: str) -> RuleTaxonomy:
    return RuleTaxonomy(category_id=category_id, topic_id=topic_id, tags=tuple(sorted(tags)))
