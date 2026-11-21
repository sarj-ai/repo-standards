from __future__ import annotations

import json

import pytest

from repo_standards.core.models import FixtureId
from repo_standards.policy_sarj import SarjPolicy
from repo_standards.policy_sarj.examples import run_rule_example
from repo_standards.policy_sarj.terraform import MODULE_CLUSTER_RULE_ID, MODULE_LAYOUT_RULE_ID


def _rules(
    paths: list[str], *, manifest: str = 'repository_id = "example"\ncomponents = []\n'
) -> tuple[str, ...]:
    return run_rule_example(
        FixtureId("sarj-terraform-module-cluster"),
        json.dumps({"tracked": paths, "manifest": manifest}),
    )


@pytest.mark.parametrize(
    "names",
    [
        ["query-dns.tf", "query-service.tf", "query-access.tf"],
        ["dns_query.tf", "service_query.tf", "access_query.tf"],
        ["query-dns.tf.json", "query-service.tf", "query-access.tf.json"],
    ],
    ids=("prefix", "suffix", "mixed-json"),
)
def test_meaningful_prefix_and_suffix_clusters_are_advisories(names: list[str]) -> None:
    assert _rules([f"infra/{name}" for name in names]).count(MODULE_CLUSTER_RULE_ID) == 1


@pytest.mark.parametrize(
    "paths",
    [
        ["infra/main.tf", "infra/variables.tf", "infra/outputs.tf"],
        ["infra/a-variables.tf", "infra/b-variables.tf", "infra/c-variables.tf"],
        ["infra/network-module.tf", "infra/service-module.tf", "infra/query-module.tf"],
        ["infra/query-a.tf", "infra/query-b.tf"],
        ["infra/first/query-a.tf", "infra/second/query-b.tf", "infra/third/query-c.tf"],
        ["fixtures/query-a.tf", "fixtures/query-b.tf", "fixtures/query-c.tf"],
        ["generated/query-a.tf", "generated/query-b.tf", "generated/query-c.tf"],
        ["infra/query-a.tfvars", "infra/query-b.tfvars", "infra/query-c.tfvars"],
        ["infra/query-a.tftest.hcl", "infra/query-b.tftest.hcl", "infra/query-c.tftest.hcl"],
    ],
    ids=(
        "canonical",
        "interfaces",
        "generic-module",
        "small",
        "separate",
        "fixtures",
        "generated",
        "tfvars",
        "native-tests",
    ),
)
def test_conventional_names_incomplete_clusters_and_excluded_scopes_pass(paths: list[str]) -> None:
    assert MODULE_CLUSTER_RULE_ID not in _rules(paths)


def test_overlapping_clusters_do_not_repeat_the_same_member_set() -> None:
    paths = ["infra/query-a-reader.tf", "infra/query-b-reader.tf", "infra/query-c-reader.tf"]

    assert _rules(paths).count(MODULE_CLUSTER_RULE_ID) == 1
    assert _rules(list(reversed(paths))) == _rules(paths)


def test_partially_overlapping_clusters_emit_one_review_candidate() -> None:
    paths = [
        "infra/query-a-reader.tf",
        "infra/query-b-service.tf",
        "infra/query-c-access.tf",
        "infra/other-a-reader.tf",
        "infra/extra-a-reader.tf",
    ]

    assert _rules(paths).count(MODULE_CLUSTER_RULE_ID) == 1
    assert _rules(list(reversed(paths))) == _rules(paths)


@pytest.mark.parametrize("kind", ["generated", "vendor"])
def test_declared_generated_and_vendor_components_are_excluded(kind: str) -> None:
    manifest = f"""repository_id = "example"
[[components]]
id = "upstream"
kind = "{kind}"
path = "infra"
owner = "infrastructure"
"""

    assert MODULE_CLUSTER_RULE_ID not in _rules(
        ["infra/query-dns.tf", "infra/query-service.tf", "infra/query-access.tf"], manifest=manifest
    )


@pytest.mark.parametrize("directory", ["variables", "outputs"])
@pytest.mark.parametrize("extension", ["tf", "tf.json"])
def test_declaration_kind_folders_below_a_module_require_ownership_review(
    directory: str, extension: str
) -> None:
    paths = ["infra/main.tf", f"infra/{directory}/declaration.{extension}"]

    assert MODULE_LAYOUT_RULE_ID in _rules(paths)


def test_a_separately_declared_terraform_component_is_a_valid_module_folder() -> None:
    manifest = """repository_id = "example"
[[components]]
id = "input-service"
kind = "terraform-root"
path = "infra/variables"
owner = "infrastructure"
"""

    assert MODULE_LAYOUT_RULE_ID not in _rules(
        ["infra/main.tf", "infra/variables/main.tf"], manifest=manifest
    )


@pytest.mark.parametrize(
    "paths",
    [
        ["infra/main.tf", "infra/variables/prod.tfvars"],
        ["infra/main.tf", "infra/outputs/contract.json"],
        ["infra/service/main.tf", "infra/service/variables.tf", "infra/service/outputs.tf"],
        ["variables/main.tf"],
    ],
    ids=("tfvars", "non-terraform-output", "component-module", "independent-root"),
)
def test_layout_preserves_tfvars_flat_composition_and_independent_roots(paths: list[str]) -> None:
    assert MODULE_LAYOUT_RULE_ID not in _rules(paths)


def test_rule_catalog_retains_warning_lifecycle_and_no_address_autofix() -> None:
    rules = {rule.rule_id: rule for rule in SarjPolicy.rules()}
    for rule_id in (MODULE_CLUSTER_RULE_ID, MODULE_LAYOUT_RULE_ID):
        rule = rules[rule_id]
        assert rule.version == 1
        assert rule.severity == "warning"
        assert "No auto" in rule.fix
