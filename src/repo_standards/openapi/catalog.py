from __future__ import annotations

from repo_standards.core.models import RuleDefinition, RuleId
from repo_standards.core.taxonomy import (
    API_CONTRACTS,
    ERROR_CONTRACTS,
    GENERATED_ARTIFACTS,
    HTTP_SEMANTICS,
    REFERENCES,
    taxonomy,
)

from .fixtures import examples_for_rule


_HTTP = "https://www.rfc-editor.org/rfc/rfc9110.html"
_OAS = "https://spec.openapis.org/oas/v3.2.0.html"
_PROBLEM = "https://www.rfc-editor.org/rfc/rfc9457.html"

RULES: tuple[RuleDefinition, ...] = (
    RuleDefinition(
        rule_id=RuleId("api/artifact/provenance"),
        version=1,
        default_severity="error",
        title="Verify artifact provenance",
        description="Derived artifacts identify their source, producer, configuration, and bytes.",
        why="Complete provenance makes generated contracts reproducible and tamper-evident.",
        fix=(
            "Record the exact source, producer, configuration, output, and matching "
            "SHA-256 digests."
        ),
        taxonomy=taxonomy(API_CONTRACTS, GENERATED_ARTIFACTS),
        examples=examples_for_rule(RuleId("api/artifact/provenance")),
        references=(_OAS,),
    ),
    RuleDefinition(
        rule_id=RuleId("api/errors/problem-details"),
        version=1,
        default_severity="warning",
        title="Publish valid Problem Details",
        description="RFC 9457 opt-ins publish a compatible error contract.",
        why=(
            "A stable error envelope lets clients handle failures without endpoint-specific "
            "parsing."
        ),
        fix="Use application/problem+json and align schema member types and status values.",
        taxonomy=taxonomy(API_CONTRACTS, ERROR_CONTRACTS),
        examples=examples_for_rule(RuleId("api/errors/problem-details")),
        references=(_PROBLEM, _OAS),
    ),
    RuleDefinition(
        rule_id=RuleId("api/http/message-semantics"),
        version=1,
        default_severity="error",
        title="Honor HTTP message semantics",
        description="Methods, statuses, request bodies, and response content agree.",
        why="Contradictory contracts generate clients and gateways with impossible behavior.",
        fix="Remove forbidden content or choose a method and status with compatible semantics.",
        taxonomy=taxonomy(API_CONTRACTS, HTTP_SEMANTICS),
        examples=examples_for_rule(RuleId("api/http/message-semantics")),
        references=(_HTTP, _OAS),
    ),
    RuleDefinition(
        rule_id=RuleId("api/references/local-resolution"),
        version=1,
        default_severity="error",
        title="Resolve local references",
        description="Every OpenAPI reference resolves inside the supplied document set.",
        why="Hermetic reference resolution keeps contract analysis deterministic and complete.",
        fix="Use a relative local reference to an object in an explicitly supplied document.",
        taxonomy=taxonomy(API_CONTRACTS, REFERENCES),
        examples=examples_for_rule(RuleId("api/references/local-resolution")),
        references=(_OAS,),
    ),
)


def rules() -> tuple[RuleDefinition, ...]:
    return RULES
