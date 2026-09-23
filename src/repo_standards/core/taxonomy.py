from __future__ import annotations

from dataclasses import dataclass

from repo_standards.core.models import RuleCategoryId, RuleTaxonomy, RuleTopicId


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


CHANGE_SAFETY = RuleCategoryId("repository")
API_CONTRACTS = RuleCategoryId("api-contracts")

ARTIFACTS = RuleTopicId("artifacts")
DOCUMENTATION = RuleTopicId("documentation")
HTTP_SEMANTICS = RuleTopicId("http-semantics")
GENERATED_ARTIFACTS = RuleTopicId("generated-artifacts")
ERROR_CONTRACTS = RuleTopicId("error-contracts")
REFERENCES = RuleTopicId("references")

CATEGORIES = (
    RuleCategory(
        category_id=CHANGE_SAFETY,
        label="Repository changes",
        order=20,
        topics=(
            RuleTopic(ARTIFACTS, "Artifacts", 10),
            RuleTopic(DOCUMENTATION, "Documentation", 20),
        ),
    ),
    RuleCategory(
        category_id=API_CONTRACTS,
        label="API contracts",
        order=30,
        topics=(
            RuleTopic(REFERENCES, "References", 10),
            RuleTopic(HTTP_SEMANTICS, "HTTP", 20),
            RuleTopic(ERROR_CONTRACTS, "Errors", 30),
            RuleTopic(GENERATED_ARTIFACTS, "Generated artifacts", 40),
        ),
    ),
)


def taxonomy(category_id: RuleCategoryId, topic_id: RuleTopicId) -> RuleTaxonomy:
    return RuleTaxonomy(category_id=category_id, topic_id=topic_id)
