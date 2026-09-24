from __future__ import annotations

from dataclasses import dataclass

from repo_standards.core.models import RuleCategoryId, RuleTaxonomy


@dataclass(frozen=True, slots=True)
class RuleTopic:
    topic_id: str
    label: str
    order: int


@dataclass(frozen=True, slots=True)
class RuleCategory:
    category_id: RuleCategoryId
    label: str
    order: int
    topics: tuple[RuleTopic, ...]


CHANGE_SAFETY = RuleCategoryId("repository")

ARTIFACTS = "artifacts"
DOCUMENTATION = "documentation"

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


def taxonomy(category_id: RuleCategoryId, topic: str) -> RuleTaxonomy:
    return RuleTaxonomy(category_id=category_id, topic=topic)
