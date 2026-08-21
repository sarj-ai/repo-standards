from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Literal

from repo_standards.core.models import EvidenceLevel, PolicyId, RuleId


PROFILE_ID = "sarj/public"


class RuleMaturity(StrEnum):
    """Promotion state recorded independently from diagnostic severity."""

    WARNING = "warning"
    STABLE_ERROR = "stable-error"


class RuleClassification(StrEnum):
    """Reason a rule is safe to enforce at its declared severity."""

    SCHEMA = "schema-contradiction"
    OBJECTIVE = "objective-boundary"
    JUDGMENT = "judgment-heavy"
    OPERATIONAL = "operational-guidance"


@dataclass(frozen=True, slots=True)
class RuleGovernance:
    rule_id: RuleId
    maturity: RuleMaturity
    classification: RuleClassification
    evidence: EvidenceLevel
    upstream: tuple[str, ...]
    precedence: int


@dataclass(frozen=True, slots=True)
class LiteralSegment:
    value: str


@dataclass(frozen=True, slots=True)
class ChoiceSegment:
    values: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class FieldSegment:
    field: Literal["product", "capability"]


@dataclass(frozen=True, slots=True)
class TokenSegment:
    label: str


@dataclass(frozen=True, slots=True)
class OwnershipSegment:
    """The declared product, or ``shared`` when the product is absent."""


@dataclass(frozen=True, slots=True)
class OptionalTail:
    """Zero or more canonical path segments; valid only as the final segment."""


PathSegment = (
    LiteralSegment | ChoiceSegment | FieldSegment | TokenSegment | OwnershipSegment | OptionalTail
)


@dataclass(frozen=True, slots=True)
class PathTemplate:
    component_kind: str
    segments: tuple[PathSegment, ...]
    operational: bool = False


@dataclass(frozen=True, slots=True)
class ProfileDescriptor:
    profile_id: str
    title: str
    product_registry_mode: Literal["open"]
    repository_overrides: bool
    target_repository_plugins: bool


@dataclass(frozen=True, slots=True)
class PolicySpec:
    schema_version: int
    policy_id: PolicyId
    policy_version: int
    profile: ProfileDescriptor
    component_kinds: tuple[str, ...]
    edge_kinds: tuple[str, ...]
    path_templates: tuple[PathTemplate, ...]
    rule_governance: tuple[RuleGovernance, ...]

    @property
    def profile_id(self) -> str:
        """Return the selected profile's stable ID."""
        return self.profile.profile_id


PATH_TEMPLATES = (
    PathTemplate(
        "application",
        (LiteralSegment("applications"), FieldSegment("product"), TokenSegment("component")),
    ),
    PathTemplate(
        "product-library",
        (
            LiteralSegment("libraries"),
            ChoiceSegment(("kotlin", "python", "swift", "typescript")),
            FieldSegment("product"),
            FieldSegment("capability"),
        ),
    ),
    PathTemplate(
        "shared-library",
        (
            LiteralSegment("libraries"),
            ChoiceSegment(("kotlin", "python", "swift", "typescript")),
            LiteralSegment("shared"),
            FieldSegment("capability"),
        ),
    ),
    PathTemplate(
        "foundation-service",
        (LiteralSegment("foundation"), LiteralSegment("components"), TokenSegment("component")),
    ),
    PathTemplate(
        "contract",
        (LiteralSegment("contracts"), OwnershipSegment(), TokenSegment("contract")),
    ),
    PathTemplate(
        "generated-client",
        (
            LiteralSegment("clients"),
            LiteralSegment("generated"),
            FieldSegment("product"),
            FieldSegment("capability"),
            ChoiceSegment(("python", "typescript")),
        ),
    ),
    PathTemplate(
        "migration-set",
        (LiteralSegment("migrations"), FieldSegment("product"), TokenSegment("store")),
    ),
    PathTemplate(
        "terraform-root",
        (
            LiteralSegment("deployments"),
            FieldSegment("product"),
            LiteralSegment("terraform"),
            OptionalTail(),
        ),
        operational=True,
    ),
    PathTemplate(
        "cloud-build",
        (
            LiteralSegment("deployments"),
            FieldSegment("product"),
            LiteralSegment("cloud-build"),
            FieldSegment("capability"),
            ChoiceSegment(("cloudbuild.yaml", "cloudbuild.yml")),
        ),
        operational=True,
    ),
    PathTemplate(
        "kubernetes",
        (
            LiteralSegment("deployments"),
            FieldSegment("product"),
            LiteralSegment("kubernetes"),
            FieldSegment("capability"),
            OptionalTail(),
        ),
        operational=True,
    ),
    PathTemplate(
        "cloudflare",
        (
            LiteralSegment("deployments"),
            FieldSegment("product"),
            LiteralSegment("cloudflare"),
            FieldSegment("capability"),
            OptionalTail(),
        ),
        operational=True,
    ),
    PathTemplate(
        "tool",
        (
            LiteralSegment("tools"),
            ChoiceSegment(("ci", "development", "mcp")),
            FieldSegment("capability"),
        ),
    ),
)

PATH_TEMPLATE_BY_KIND = MappingProxyType(
    {template.component_kind: template for template in PATH_TEMPLATES}
)
