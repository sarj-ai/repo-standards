from __future__ import annotations

from hashlib import sha256
from importlib.metadata import version
import json
from pathlib import Path

from jsonschema import Draft202012Validator, validate
from pydantic import TypeAdapter, ValidationError
import pytest
from typer.testing import CliRunner

from repo_standards.catalog import (
    ApprovedRuleReviewDescriptor,
    Catalog,
    build_catalog,
    catalog_schema,
)
from repo_standards.cli import app
from repo_standards.core.canonical import canonical_json
from repo_standards.core.catalog import core_rules
from repo_standards.core.models import JSONValue
from repo_standards.openapi import rules as openapi_rules
from repo_standards.policy_sarj import SarjPolicy


runner = CliRunner()
_JSON_OBJECT = TypeAdapter(dict[str, JSONValue])


def _catalog_payload() -> dict[str, JSONValue]:
    catalog = build_catalog(app, package_version=version("repo-standards"))
    return _JSON_OBJECT.validate_python(catalog.model_dump(mode="json"), strict=True)


def test_catalog_is_deterministic_and_digest_covers_all_content() -> None:
    first = build_catalog(app, package_version="9.8.7")
    second = build_catalog(app, package_version="9.8.7")

    assert first == second
    assert canonical_json(first.model_dump(mode="json")) == canonical_json(
        second.model_dump(mode="json")
    )
    unsigned = first.model_copy(
        update={"provenance": first.provenance.model_copy(update={"content_digest": ""})}
    )
    expected = sha256(canonical_json(unsigned.model_dump(mode="json")).encode()).hexdigest()
    assert first.provenance.content_digest == expected
    assert len(expected) == 64


def test_catalog_contains_every_rule_policy_binding_command_and_capability() -> None:
    catalog = build_catalog(app, package_version="9.8.7")
    registry = (SarjPolicy(),)
    expected_rule_ids = {str(rule.rule_id) for rule in core_rules()}
    expected_rule_ids.update(str(rule.rule_id) for policy in registry for rule in policy.rules())
    expected_rule_ids.update(rule.rule_id for rule in openapi_rules())
    rule_ids = [rule.rule_id for rule in catalog.rules]

    assert catalog.schema_version == 7
    assert {rule.review.status for rule in catalog.rules} == {"pending"}
    assert rule_ids == sorted(expected_rule_ids)
    assert len(rule_ids) == len(set(rule_ids)) == 10
    assert len({rule.slug for rule in catalog.rules}) == 10
    assert {
        binding.default_activation for policy in catalog.policies for binding in policy.bindings
    } == {"disabled"}


def test_catalog_rule_versions_are_positive() -> None:
    catalog = build_catalog(app, package_version="9.8.7")
    payload = catalog.model_dump(mode="python")
    payload["rules"][0]["rule_version"] = 0
    with pytest.raises(ValidationError, match="greater than 0"):
        Catalog.model_validate(payload)


def test_catalog_policy_binding_review_status_must_match_its_rule() -> None:
    catalog = build_catalog(app, package_version="9.8.7")
    payload = catalog.model_dump(mode="python")
    payload["policies"][0]["bindings"][0]["review_status"] = "approved"

    with pytest.raises(ValidationError, match="policy binding does not match its rule"):
        Catalog.model_validate(payload)


def test_catalog_rule_slugs_are_valid_and_unique() -> None:
    catalog = build_catalog(app, package_version="9.8.7")
    payload = catalog.model_dump(mode="python")
    payload["rules"][1]["slug"] = payload["rules"][0]["slug"]
    with pytest.raises(ValidationError, match="rule slugs must be unique"):
        Catalog.model_validate(payload)

    payload = catalog.model_dump(mode="python")
    payload["rules"][0]["slug"] = "Not a slug"
    with pytest.raises(ValidationError, match="string_pattern_mismatch"):
        Catalog.model_validate(payload)


def test_approved_review_descriptor_requires_immutable_object_id() -> None:
    with pytest.raises(ValidationError, match="string_pattern_mismatch"):
        ApprovedRuleReviewDescriptor(
            reviewed_in="mutable-branch",
        )


def test_catalog_graph_is_complete() -> None:
    catalog = build_catalog(app, package_version="9.8.7")
    registry = (SarjPolicy(),)
    expected_rule_ids = {str(rule.rule_id) for rule in core_rules()}
    expected_rule_ids.update(str(rule.rule_id) for policy in registry for rule in policy.rules())
    expected_rule_ids.update(rule.rule_id for rule in openapi_rules())
    rule_ids = [rule.rule_id for rule in catalog.rules]
    assert rule_ids == sorted(expected_rule_ids)
    assert len(rule_ids) == len(set(rule_ids)) == 10
    assert {policy.policy_id for policy in catalog.policies} == {
        str(policy.policy_id) for policy in registry
    }
    for policy in catalog.policies:
        assert policy.bindings
        assert {binding.rule_id for binding in policy.bindings} <= set(rule_ids)

    command_ids = {command.command_id for command in catalog.commands}
    assert command_ids == {
        "capabilities",
        "catalog",
        "check",
        "explain",
        "inspect",
        "pull-request.size",
        "report",
        "rest.check",
        "rest.discover",
        "rest.doctor",
        "rest.explain",
        "rest.rules",
        "rules",
        "schema",
    }
    assert {capability.capability_id for capability in catalog.capabilities} == {
        "pull-request-size",
        "repository",
        "rest",
    }
    assert next(schema for schema in catalog.schemas if schema.schema_id == "catalog").title == (
        "Repo Standards public catalog"
    )
    for capability in catalog.capabilities:
        assert capability.command_ids
        assert set(capability.command_ids) <= command_ids
        assert capability.input_kinds


def test_catalog_rules_have_complete_clarity_taxonomy_and_examples() -> None:
    catalog = build_catalog(app, package_version="9.8.7")
    category_ids = {category.category_id for category in catalog.categories}
    topic_parents = {
        topic.topic_id: category.category_id
        for category in catalog.categories
        for topic in category.topics
    }
    fixture_ids: list[str] = []

    assert category_ids == {"architecture", "api-contracts", "repository"}
    assert {rule.category_id for rule in catalog.rules} == category_ids
    assert {rule.topic_id for rule in catalog.rules} == set(topic_parents)
    for rule in catalog.rules:
        assert topic_parents[rule.topic_id] == rule.category_id
        assert rule.title
        assert rule.description
        assert rule.why
        assert rule.fix
        assert rule.examples
        for example in rule.examples:
            assert example.language
            assert example.before
            assert example.after
            assert example.before != example.after
            fixture_ids.append(example.id)

    assert len(fixture_ids) == len(set(fixture_ids))


def test_rule_wire_contract_contains_only_compact_fields() -> None:
    rule = build_catalog(app, package_version="9.8.7").rules[0]
    assert set(rule.model_dump()) == {
        "kind",
        "rule_id",
        "slug",
        "rule_version",
        "title",
        "category_id",
        "topic_id",
        "default_severity",
        "description",
        "why",
        "fix",
        "references",
        "examples",
        "source",
        "review",
    }
    assert set(rule.examples[0].model_dump()) == {
        "id",
        "title",
        "language",
        "before",
        "after",
        "expected_severity",
    }


def test_catalog_and_every_embedded_schema_are_valid_json_schemas() -> None:
    catalog = build_catalog(app, package_version=version("repo-standards"))
    payload = _catalog_payload()
    schema = catalog_schema()

    Draft202012Validator.check_schema(schema)
    validate(instance=payload, schema=schema)
    for descriptor in catalog.schemas:
        document = descriptor.document
        assert isinstance(document, dict)
        Draft202012Validator.check_schema(document)


def test_catalog_schema_encodes_approved_review_states() -> None:
    schema = catalog_schema()
    definitions = schema["$defs"]
    assert isinstance(definitions, dict)

    approved = _JSON_OBJECT.validate_python(
        definitions["ApprovedRuleReviewDescriptor"], strict=True
    )
    properties = _JSON_OBJECT.validate_python(approved["properties"], strict=True)
    assert set(properties) == {"status", "reviewed_in"}


def test_catalog_schema_documents_exactly_match_their_cli_selectors() -> None:
    catalog = build_catalog(app, package_version="9.8.7")

    for descriptor in catalog.schemas:
        result = runner.invoke(app, ["schema", descriptor.cli_selector])
        assert result.exit_code == 0
        assert json.loads(result.stdout) == descriptor.document


def test_catalog_schema_descriptor_versions_match_public_contracts() -> None:
    versions = {
        descriptor.schema_id: descriptor.schema_version
        for descriptor in build_catalog(app, package_version="9.8.7").schemas
    }

    assert versions == {
        "catalog": 7,
        "openapi-analysis": 3,
        "report": 3,
    }


def test_catalog_cli_emits_canonical_schema_valid_json() -> None:
    result = runner.invoke(app, ["catalog"])

    assert result.exit_code == 0
    payload = _JSON_OBJECT.validate_json(result.stdout, strict=True)
    assert result.stdout.strip() == canonical_json(payload)
    assert payload == _catalog_payload()
    validate(instance=payload, schema=catalog_schema())


def test_catalog_does_not_observe_environment_or_working_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    baseline = canonical_json(_catalog_payload())
    marker = "catalog-must-not-leak-private-environment-4f8761"
    private_directory = tmp_path / marker
    private_directory.mkdir()
    monkeypatch.chdir(private_directory)
    monkeypatch.setenv("HOME", f"/{marker}/home")
    monkeypatch.setenv("USER", marker)
    monkeypatch.setenv("GITHUB_TOKEN", marker)
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", marker)

    observed = canonical_json(_catalog_payload())

    assert observed == baseline
    assert marker not in observed
    assert str(tmp_path) not in observed
    assert "/Users/" not in observed
    assert "\\Users\\" not in observed


def test_catalog_public_source_pointers_are_relative_and_present() -> None:
    repository = Path(__file__).resolve().parents[1]
    catalog = build_catalog(app, package_version="9.8.7")

    for rule in catalog.rules:
        source = Path(rule.source.path)
        assert not source.is_absolute()
        assert ".." not in source.parts
        assert (repository / source).is_file()
        assert rule.source.symbol
