"""Immutable OpenAPI rule catalog; the single source for rule documentation."""

from __future__ import annotations

from .models import RuleDefinition


_HTTP = "https://www.rfc-editor.org/rfc/rfc9110.html"
_OAS = "https://spec.openapis.org/oas/v3.2.0.html"
_OAUTH_SECURITY = "https://www.rfc-editor.org/rfc/rfc9700.html"
_PROBLEM = "https://www.rfc-editor.org/rfc/rfc9457.html"
_DEPRECATION = "https://www.rfc-editor.org/rfc/rfc9745.html"
_SUNSET = "https://www.rfc-editor.org/rfc/rfc8594.html"


RULES: tuple[RuleDefinition, ...] = (
    RuleDefinition(
        "rest/source/nonhermetic-ref",
        1,
        "error",
        "A parsed $ref crosses the supplied repository boundary or names an unavailable target.",
        "Unbounded or network reference resolution is non-reproducible and can expose "
        "trusted tooling.",
        ("Validating the referenced schema", "Fetching remote resources"),
        "A parsed Reference Object key and its source document.",
        "OpenAPI resolver/conformance tooling",
        (_OAS,),
        '$ref: "https://example.invalid/schema.json"',
        '$ref: "./schemas/widget.json#/$defs/Widget"',
        ("Only parsed $ref keys are examined.", "No reference is fetched."),
    ),
    RuleDefinition(
        "rest/http/forbidden-content",
        1,
        "error",
        "An operation documents content where HTTP semantics prohibit message content.",
        "Clients and intermediaries cannot interoperate reliably with a forbidden message body.",
        ("Requiring response completeness", "Judging whether an optional body is useful"),
        "Parsed method, response status, and non-empty OAS content/requestBody fields.",
        None,
        (_HTTP, _OAS),
        "A 204 response with a content map, or a TRACE requestBody.",
        "A 204 response with headers and no content field.",
        ("Headers and links are not treated as message content.",),
    ),
    RuleDefinition(
        "rest/http/status-method-contradiction",
        1,
        "error",
        "A response status is declared on a method for which its RFC semantics cannot apply.",
        "The generated contract promises a response that conforming HTTP behavior cannot produce.",
        ("Recommending success statuses", "Inferring behavior from operation names"),
        "An explicit response status and parsed HTTP method.",
        None,
        (_HTTP,),
        "POST documents a 304 response.",
        "GET documents a 304 response.",
        ("Only the closed 206 and 304 method relationships are checked.",),
    ),
    RuleDefinition(
        "rest/security/insecure-server",
        1,
        "warning",
        "A literal OpenAPI server URL uses cleartext HTTP.",
        "Credentials and API data can be exposed or modified in transit.",
        ("Inferring deployment TLS behind a proxy", "Evaluating templated or relative URLs"),
        "A parsed, literal Server Object URL.",
        None,
        (_OAS,),
        "url: http://api.example.test",
        "url: https://api.example.test",
        (
            "Relative and templated URLs are not guessed.",
            "This remains advisory until an explicit public/production exposure profile exists.",
        ),
    ),
    RuleDefinition(
        "rest/security/oauth-password-grant",
        1,
        "error",
        "An OAuth 2 security scheme declares the password flow.",
        "The flow directly exposes resource-owner credentials to the client.",
        ("Assessing runtime token security",),
        "The exact components.securitySchemes.*.flows.password key.",
        None,
        (_OAS, _OAUTH_SECURITY),
        "flows: {password: {...}}",
        "flows: {authorizationCode: {...}}",
        ("Scheme names and descriptions are ignored.",),
    ),
    RuleDefinition(
        "rest/security/oauth-implicit-grant",
        1,
        "warning",
        "An OAuth 2 security scheme declares the implicit flow.",
        "The legacy browser flow has weaker token-handling properties than code-based flows.",
        ("Claiming an RFC violation", "Assessing runtime token security"),
        "The exact components.securitySchemes.*.flows.implicit key.",
        None,
        (_OAS, _OAUTH_SECURITY),
        "flows: {implicit: {...}}",
        "flows: {authorizationCode: {...}}",
        ("This remains advisory.", "Scheme names and descriptions are ignored."),
    ),
    RuleDefinition(
        "rest/security/exposure-contradiction",
        1,
        "error",
        "Explicit public/authenticated exposure contradicts effective OpenAPI security "
        "alternatives.",
        "Consumers can be generated with the wrong authentication requirement.",
        ("Inferring exposure", "Proving runtime authorization"),
        "An exact operation_ref sidecar declaration and computed effective security DNF.",
        None,
        (_OAS,),
        "Sidecar says public while every effective alternative requires a scheme.",
        "Sidecar says authenticated and every effective alternative requires at least one scheme.",
        ("Root inheritance, [] and the empty requirement object are modeled explicitly.",),
    ),
    RuleDefinition(
        "rest/errors/problem-contract",
        1,
        "warning",
        "An operation opted into RFC 9457 but a documented error body contradicts that format.",
        "Clients cannot handle errors through the selected common contract.",
        ("Requiring optional problem members", "Replacing domain-specific error formats"),
        "An explicit sidecar opt-in and a parsed 4xx/5xx response content schema.",
        None,
        (_PROBLEM, _OAS),
        "A 422 JSON error body with a string status member.",
        "A 422 application/problem+json body with RFC-compatible optional members.",
        ("Bodyless errors remain valid.", "Only explicitly opted-in operations are checked."),
    ),
    RuleDefinition(
        "rest/lifecycle/sunset-order",
        1,
        "error",
        "An explicit sunset timestamp is not later than its deprecation timestamp.",
        "Consumers receive an impossible or reversed migration window.",
        ("Inferring dates from prose or examples",),
        "Two explicit RFC 3339 sidecar timestamps for one operation.",
        None,
        (_DEPRECATION, _SUNSET),
        "deprecation_at is later than sunset_at.",
        "deprecation_at precedes sunset_at.",
        ("No finding is emitted unless both exact timestamps are declared.",),
    ),
    RuleDefinition(
        "rest/artifact/provenance",
        1,
        "warning",
        "A declared derived artifact lacks pinned provenance or contradicts supplied bytes.",
        "Generated clients and bundles can silently drift from their canonical contract.",
        ("Compiling generated code", "Inferring generated artifacts from paths"),
        "Explicit artifact metadata plus SHA-256 digests of supplied bytes.",
        None,
        (_OAS,),
        "A bundle declares a source digest that differs from the supplied source.",
        "A bundle pins source/output/config digests and producer version.",
        ("Exact digest contradictions are errors; missing evidence remains a warning.",),
    ),
)


def rules() -> tuple[RuleDefinition, ...]:
    """Return the immutable rule catalog in stable ID order."""
    return tuple(sorted(RULES, key=lambda item: item.rule_id))
