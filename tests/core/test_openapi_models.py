from __future__ import annotations

from dataclasses import replace

from repo_lint.core.canonical import semantic_finding_key, semantic_fingerprint, with_fingerprint
from repo_lint.core.models import (
    AdapterRun,
    AnalysisContext,
    AnalysisReport,
    ComponentId,
    Diagnostic,
    EvidenceBundle,
    FixtureId,
    GitObjectId,
    InputProvenance,
    Mode,
    Page,
    PolicyId,
    Query,
    RatchetClassification,
    RatchetComparison,
    RatchetEntry,
    RelatedLocation,
    Remediation,
    RepositoryId,
    Rule,
    RuleCategoryId,
    RuleExamplePair,
    RuleId,
    RuleRemediation,
    RuleTaxonomy,
    RuleTopicId,
    SourceLocation,
)
from repo_lint.core.render import diagnostic_dict, report_dict


def _diagnostic() -> Diagnostic:
    return Diagnostic(
        rule_id=RuleId("openapi/operation-id"),
        rule_version=1,
        severity="error",
        evidence_level="verified",
        component_id=ComponentId("public-api"),
        subject_kind="operation",
        observed="getPet",
        expected="pets.get",
        message="Use a stable operation ID.",
        path="openapi.yaml",
        manifest_anchor="paths./pets/{id}.get",
        remediation=Remediation("Rename it.", ("Set operationId.",), ("Lint again.",)),
        location=SourceLocation("openapi.yaml", line=12, column=5, pointer="/paths/~1pets/get"),
        related_locations=(
            RelatedLocation(SourceLocation("client.ts", line=4), "Generated client use."),
        ),
        observed_value={"operationId": "getPet", "tags": ["pets"]},
        expected_value={"operationId": "pets.get"},
    )


def test_structured_values_have_deterministic_fingerprints_and_stable_keys() -> None:
    diagnostic = _diagnostic()
    reordered = replace(
        diagnostic,
        observed_value={"tags": ["pets"], "operationId": "getPet"},
    )
    changed = replace(
        diagnostic,
        observed_value={"operationId": "fetchPet", "tags": ["pets"]},
    )

    assert semantic_fingerprint(diagnostic) == semantic_fingerprint(reordered)
    assert semantic_fingerprint(diagnostic) != semantic_fingerprint(changed)
    assert semantic_finding_key(diagnostic) == semantic_finding_key(changed)
    enriched = with_fingerprint(diagnostic)
    assert len(enriched.fingerprint) == 64
    assert len(enriched.finding_key) == 64


def test_rich_locations_are_additive_in_the_v1_diagnostic_shape() -> None:
    payload = diagnostic_dict(with_fingerprint(_diagnostic()))

    assert payload["observed"] == {"operationId": "getPet", "tags": ["pets"]}
    assert payload["finding_key"]
    assert payload["location"] == {
        "path": "openapi.yaml",
        "line": 12,
        "column": 5,
        "pointer": "/paths/~1pets/get",
        "manifest_anchor": "paths./pets/{id}.get",
    }
    assert payload["related_locations"][0]["location"]["path"] == "client.ts"  # type: ignore[index]


def test_context_adapter_and_cursor_models_are_framework_neutral() -> None:
    evidence = EvidenceBundle(
        evidence_id="spec:public",
        kind="openapi.document",
        values={"version": "3.1.0"},
        locations=(SourceLocation("openapi.yaml"),),
        content_digest="a" * 64,
    )
    run = AdapterRun("openapi-static", "1", "complete", evidence=(evidence,))
    context = AnalysisContext(
        RepositoryId("example"),
        source_revision="b" * 40,
        tree_digest="c" * 40,
        evidence=(evidence,),
        adapter_runs=(run,),
    )

    assert context.adapter_runs[0].status == "complete"
    assert Query().limit == 100
    assert Page((evidence,), next_cursor="opaque").items == (evidence,)


def test_rule_metadata_is_complete_and_examples_expose_fixture_ids() -> None:
    rule = Rule(
        rule_id=RuleId("example/rule"),
        version=1,
        default_severity="warning",
        title="Example rule",
        summary="The example remains valid.",
        detects="The example is invalid.",
        impact="Invalid examples confuse consumers.",
        taxonomy=RuleTaxonomy(RuleCategoryId("examples"), RuleTopicId("example-rules")),
        remediation=RuleRemediation(
            "Correct the example.",
            ("Change the input.",),
            ("Run the rule again.",),
        ),
        examples=(RuleExamplePair(FixtureId("example-rule"), "text", "invalid", "valid"),),
        evidence_required=("Example input",),
    )

    assert rule.maturity == "stable"
    assert rule.references == ()
    assert rule.fixture_ids == (FixtureId("example-rule"),)


def test_report_serializes_provenance_and_ratchet_when_present() -> None:
    diagnostic = with_fingerprint(_diagnostic())
    provenance = InputProvenance(
        mode="git-tree",
        source_revision="a" * 40,
        tree_digest="b" * 40,
        manifest_path=".repo-lint/repository.toml",
        manifest_object_id=GitObjectId("c" * 40),
        manifest_digest="d" * 64,
    )
    report = AnalysisReport(
        mode=Mode.STRICT,
        repository_id=RepositoryId("example"),
        policy_id=PolicyId("example"),
        policy_version=1,
        scope_digest="e" * 64,
        completion="complete",
        conclusion="findings",
        diagnostics=(diagnostic,),
        input_provenance=provenance,
        ratchet=RatchetComparison(
            (RatchetEntry(diagnostic.fingerprint, RatchetClassification.NEW, diagnostic),)
        ),
    )

    payload = report_dict(report)
    assert payload["input_provenance"]["source_revision"] == "a" * 40  # type: ignore[index]
    assert payload["ratchet_comparison"]["entries"][0]["classification"] == "new"  # type: ignore[index]
