from __future__ import annotations

from dataclasses import replace

from repo_lint.core.models import (
    RuleDefinition,
    RuleId,
    RuleRemediation,
)
from repo_lint.core.taxonomy import (
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
_VALIDATION = "Run repo-standards rest check again against the same tracked contract and semantics."


def _remediation(summary: str, *steps: str) -> RuleRemediation:
    return RuleRemediation(summary, steps, (_VALIDATION,))


RULES: tuple[RuleDefinition, ...] = (
    RuleDefinition(
        rule_id=RuleId("rest/source/nonhermetic-ref"),
        version=1,
        default_severity="error",
        title="Local reference resolution",
        summary="References resolve only from supplied local contract bytes.",
        detects="A $ref is not a string or does not resolve inside the supplied document set.",
        impact=(
            "Remote, escaping, missing, and broken references make analysis "
            "non-reproducible or incomplete."
        ),
        taxonomy=taxonomy(API_CONTRACTS, REFERENCES, "hermeticity", "openapi", "rest"),
        remediation=_remediation(
            "Make the reference resolve inside the bounded contract graph.",
            "Use a relative local $ref.",
            "Supply the exact tracked target document and point to an existing object.",
        ),
        examples=examples_for_rule(RuleId("rest/source/nonhermetic-ref")),
        evidence_required=("parsed $ref keys and the complete supplied document set",),
        non_goals=("validating referenced schemas", "fetching remote resources"),
        false_positive_controls=(
            (
                "Only parsed $ref keys are examined; examples, defaults, and extension data "
                "are ignored."
            ),
            "No reference is fetched, and only explicitly supplied local documents count.",
        ),
        upstream=("OpenAPI resolver and conformance tooling",),
        references=(_OAS,),
    ),
    RuleDefinition(
        rule_id=RuleId("rest/http/forbidden-content"),
        version=1,
        default_severity="error",
        title="Forbidden HTTP message content",
        summary="Operations document content only where HTTP semantics permit it.",
        detects=(
            "A TRACE operation declares a request body, or a HEAD, 1xx, 204, 205, or 304 "
            "response declares non-empty content."
        ),
        impact="The contract promises message content that conforming HTTP behavior forbids.",
        taxonomy=taxonomy(API_CONTRACTS, HTTP_SEMANTICS, "http", "openapi", "rest"),
        remediation=_remediation(
            "Remove content forbidden by the method or response status.",
            "Remove requestBody from TRACE operations.",
            "Remove the response content map while preserving valid headers and links.",
        ),
        examples=examples_for_rule(RuleId("rest/http/forbidden-content")),
        evidence_required=(
            "parsed operation method, response status, requestBody, and non-empty content fields",
        ),
        non_goals=("requiring response completeness", "judging whether optional content is useful"),
        false_positive_controls=(
            "Headers and links are not treated as message content.",
            "Missing or empty response content maps remain clean.",
            (
                "Only TRACE request bodies and the closed HEAD, 1xx, 204, 205, and 304 cases "
                "are checked."
            ),
        ),
        upstream=("HTTP semantics", "OpenAPI conformance tooling"),
        references=(_HTTP, _OAS),
    ),
    RuleDefinition(
        rule_id=RuleId("rest/http/status-method-contradiction"),
        version=1,
        default_severity="error",
        title="Status code incompatible with method",
        summary="Response statuses agree with operation method semantics.",
        detects=(
            "A non-GET operation declares 206, or an operation other than GET or HEAD declares 304."
        ),
        impact=(
            "The contract promises a response status whose semantics cannot apply to that method."
        ),
        taxonomy=taxonomy(API_CONTRACTS, HTTP_SEMANTICS, "http", "openapi", "rest"),
        remediation=_remediation(
            "Use a status compatible with the operation method.",
            "Remove the status or move it to an operation whose method supports it.",
        ),
        examples=examples_for_rule(RuleId("rest/http/status-method-contradiction")),
        evidence_required=("an explicit three-digit response status and parsed HTTP method",),
        non_goals=("recommending success statuses", "inferring behavior from operation names"),
        false_positive_controls=(
            "Only explicit 206 and 304 method relationships are checked.",
            "GET with 206 and GET or HEAD with 304 remain clean.",
            "Response ranges and default responses are not inferred.",
        ),
        upstream=("HTTP semantics",),
        references=(_HTTP,),
    ),
    RuleDefinition(
        rule_id=RuleId("rest/errors/problem-contract"),
        version=1,
        default_severity="warning",
        title="RFC 9457 error contract",
        summary="Opted-in error responses remain compatible with Problem Details.",
        detects=(
            "An operation opted into RFC 9457 documents an error body with the wrong media type, "
            "an unresolved schema, an incompatible member type, or a status constant that "
            "contradicts the response."
        ),
        impact=(
            "Consumers cannot handle opted-in errors through one predictable Problem Details "
            "contract."
        ),
        taxonomy=taxonomy(API_CONTRACTS, ERROR_CONTRACTS, "openapi", "problem-details", "rest"),
        remediation=_remediation(
            "Align the opted-in error representation.",
            "Use application/problem+json with an inline or supplied local object schema.",
            "Correct declared member types and any status constant, or remove the explicit opt-in.",
        ),
        examples=examples_for_rule(RuleId("rest/errors/problem-contract")),
        evidence_required=(
            "an explicit RFC 9457 sidecar opt-in and parsed 4xx, 5xx, 4XX, or 5XX response content",
        ),
        non_goals=(
            "requiring optional Problem Details members",
            "replacing domain-specific errors",
        ),
        false_positive_controls=(
            "Only explicitly opted-in operations and documented error bodies are checked.",
            "Bodyless errors remain valid, and optional Problem Details members are not required.",
            "Only directly resolved local schemas and declared member contradictions are checked.",
        ),
        upstream=("RFC 9457", "OpenAPI conformance tooling"),
        references=(_PROBLEM, _OAS),
        maturity="beta",
    ),
    RuleDefinition(
        rule_id=RuleId("rest/artifact/provenance-incomplete"),
        version=1,
        default_severity="warning",
        title="Incomplete artifact provenance",
        summary="Derived artifacts identify their source, output, configuration, and producer.",
        detects=(
            "A declared derived artifact omits its source, source digest, output digest, producer "
            "name or version, or configuration digest."
        ),
        impact=("The artifact cannot be reproduced or tied to one reviewed source and toolchain."),
        taxonomy=taxonomy(API_CONTRACTS, GENERATED_ARTIFACTS, "openapi", "provenance", "rest"),
        remediation=_remediation(
            "Complete the derivation evidence.",
            "Record one source plus source, configuration, and output digests.",
            "Record the producer name and version.",
        ),
        examples=examples_for_rule(RuleId("rest/artifact/provenance-incomplete")),
        evidence_required=("explicit artifact metadata for a supplied non-source artifact",),
        non_goals=("compiling generated code", "inferring generated artifacts from paths"),
        false_positive_controls=(
            "Only explicit non-source artifact declarations are checked.",
            "Paths do not imply generation, and repository code is never executed.",
            "Missing and contradictory evidence remain distinguishable issue kinds.",
        ),
        upstream=("artifact provenance and OpenAPI bundling workflows",),
        references=(_OAS,),
        maturity="beta",
    ),
    RuleDefinition(
        rule_id=RuleId("rest/artifact/provenance-contradiction"),
        version=1,
        default_severity="error",
        title="Contradictory artifact provenance",
        summary="Declared artifact provenance describes the exact supplied bytes.",
        detects=(
            "Declared artifact or source bytes are absent, or a declared source or output digest "
            "does not match the supplied bytes."
        ),
        impact="The provenance statement does not describe the artifact being reviewed.",
        taxonomy=taxonomy(API_CONTRACTS, GENERATED_ARTIFACTS, "openapi", "provenance", "rest"),
        remediation=_remediation(
            "Make the declaration match the reviewed bytes.",
            "Supply the declared artifact and canonical source bytes.",
            "Recompute and record their exact SHA-256 digests.",
        ),
        examples=examples_for_rule(RuleId("rest/artifact/provenance-contradiction")),
        evidence_required=(
            "explicit artifact metadata and SHA-256 digests of supplied source and artifact bytes",
        ),
        non_goals=("compiling generated code", "inferring generated artifacts from paths"),
        false_positive_controls=(
            "Only explicit non-source artifact declarations are checked.",
            "Digest comparisons use the exact supplied bytes without executing repository code.",
            "Missing and contradictory evidence remain distinguishable issue kinds.",
        ),
        upstream=("artifact provenance and OpenAPI bundling workflows",),
        references=(_OAS,),
    ),
)


def rules() -> tuple[RuleDefinition, ...]:
    by_id = {str(rule.rule_id): rule for rule in RULES}
    groups = (
        (
            "api/references/local-resolution",
            ("rest/source/nonhermetic-ref",),
            "Resolve local references",
            "Every OpenAPI reference resolves inside the supplied document set.",
            "Reports non-string, remote, missing, or otherwise unresolvable references.",
            "Hermetic reference resolution keeps contract analysis deterministic and complete.",
            "error",
        ),
        (
            "api/http/message-semantics",
            ("rest/http/forbidden-content", "rest/http/status-method-contradiction"),
            "Honor HTTP message semantics",
            "Methods, statuses, request bodies, and response content agree with HTTP semantics.",
            "Reports forbidden message content or a response status incompatible with its method.",
            "Contradictory HTTP contracts generate clients and gateways with impossible behavior.",
            "error",
        ),
        (
            "api/errors/problem-details",
            ("rest/errors/problem-contract",),
            "Publish valid Problem Details",
            "Operations opting into RFC 9457 publish a compatible error contract.",
            "Reports incompatible media types, schemas, member types, or response status values.",
            (
                "A stable error envelope lets clients handle failures without "
                "endpoint-specific parsing."
            ),
            "warning",
        ),
        (
            "api/artifact/provenance",
            (
                "rest/artifact/provenance-incomplete",
                "rest/artifact/provenance-contradiction",
            ),
            "Verify artifact provenance",
            "Derived artifacts identify their source, producer, configuration, and exact bytes.",
            "Reports missing provenance fields, absent bytes, or digest contradictions.",
            "Complete provenance makes generated contracts reproducible and tamper-evident.",
            "error",
        ),
    )
    compact_content = {
        "api/artifact/provenance": (
            _remediation(
                "Complete or correct the provenance record.",
                "Identify the exact source, producer, configuration, and output bytes.",
                "Record SHA-256 digests that match the supplied source and artifact.",
            ),
            ("explicit artifact metadata plus the supplied source and artifact bytes",),
            ("compiling generated code", "inferring generated artifacts from paths"),
            (
                "Only explicitly declared derived artifacts are checked.",
                "Digest comparisons use exact supplied bytes without executing repository code.",
            ),
        ),
        "api/http/message-semantics": (
            _remediation(
                "Remove forbidden content or choose a compatible method and status.",
                "Remove a TRACE request body or content forbidden for the response status.",
                "Use 206 only with GET and 304 only with GET or HEAD.",
            ),
            ("parsed methods, statuses, request bodies, and response content",),
            ("requiring response completeness", "recommending success statuses"),
            (
                "Headers and links are not treated as message content.",
                "Missing, empty, range, and default responses are not inferred.",
                "Only the closed TRACE, HEAD, 1xx, 204, 205, 206, and 304 cases are checked.",
            ),
        ),
    }
    merged: list[RuleDefinition] = []
    for target, source_ids, title, summary, detects, impact, severity in groups:
        sources = tuple(by_id[source_id] for source_id in source_ids)
        representative = sources[0]
        compact = compact_content.get(target)
        merged.append(
            replace(
                representative,
                rule_id=RuleId(target),
                default_severity=severity,
                title=title,
                summary=summary,
                detects=detects,
                impact=impact,
                remediation=compact[0] if compact else representative.remediation,
                examples=examples_for_rule(RuleId(target)),
                evidence_required=(
                    compact[1]
                    if compact
                    else tuple(
                        dict.fromkeys(item for rule in sources for item in rule.evidence_required)
                    )
                ),
                non_goals=(
                    compact[2]
                    if compact
                    else tuple(dict.fromkeys(item for rule in sources for item in rule.non_goals))
                ),
                false_positive_controls=(
                    compact[3]
                    if compact
                    else tuple(
                        dict.fromkeys(
                            item for rule in sources for item in rule.false_positive_controls
                        )
                    )
                ),
                upstream=tuple(dict.fromkeys(item for rule in sources for item in rule.upstream)),
                references=tuple(
                    dict.fromkeys(item for rule in sources for item in rule.references)
                ),
            )
        )
    return tuple(sorted(merged, key=lambda item: item.rule_id))
