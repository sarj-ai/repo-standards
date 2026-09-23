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

ARTIFACTS = RuleTopicId("artifacts")
DOCUMENTATION = RuleTopicId("documentation")

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
)


def taxonomy(category_id: RuleCategoryId, topic_id: RuleTopicId) -> RuleTaxonomy:
    return RuleTaxonomy(category_id=category_id, topic_id=topic_id)
