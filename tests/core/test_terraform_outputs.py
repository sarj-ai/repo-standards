from __future__ import annotations

from dataclasses import replace
import json
import shutil
import subprocess
from typing import TYPE_CHECKING

import pytest

from repo_standards.core.errors import ConfigurationError
from repo_standards.core.inspection import (
    git_index_identity,
    load_calibration_snapshot,
    with_terraform_sources,
)
from repo_standards.core.models import FindingsReport, IncompleteReport, PassedReport, RuleId
from repo_standards.policy_sarj import SarjPolicy
from repo_standards.policy_sarj.examples import rule_example_cases, run_rule_example
from repo_standards.repository import RepositoryAnalysisRequest, analyze_repository


if TYPE_CHECKING:
    from pathlib import Path


_RULE = "repository/terraform/unused-module-outputs"
_MANIFEST = f"""repository_id = "output-contracts"
enabled_rules = ["{_RULE}"]
[[components]]
id = "infrastructure"
kind = "terraform-root"
path = "infra"
owner = "@example/platform"
"""


def _git(root: Path, *arguments: str) -> None:
    executable = shutil.which("git")
    assert executable is not None
    subprocess.run(
        [executable, "-C", str(root), *arguments], check=True, capture_output=True, timeout=10
    )


def _repository(tmp_path: Path) -> Path:
    root = tmp_path / "repository"
    (root / ".repo-standards").mkdir(parents=True)
    (root / "infra/child").mkdir(parents=True)
    (root / ".repo-standards/repository.toml").write_text(_MANIFEST)
    (root / "infra/main.tf").write_text(
        'module "child" { source = "./child" }\noutput "public" { value = module.child.used }\n'
    )
    (root / "infra/child/outputs.tf").write_text(
        'output "used" { value = "used" }\noutput "external" { value = "external" }\n'
    )
    _git(root, "init", "--quiet")
    _git(root, "add", ".")
    return root


def test_staged_analysis_rejects_the_previously_missed_unused_export(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    report = analyze_repository(RepositoryAnalysisRequest(root=root, staged=True))
    assert isinstance(report, FindingsReport)
    assert len(report.diagnostics) == 1
    finding = report.diagnostics[0]
    assert finding.rule_id == _RULE
    assert finding.observed == "external"
    assert finding.path == "infra/child/outputs.tf"
    assert finding.location is not None
    assert finding.location.line == 2
    assert finding.severity == "error"
    assert not finding.baselineable


def test_staged_analysis_keeps_an_unread_output_safety_check(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    (root / "infra/child/outputs.tf").write_text(
        """variable "accepted" {
  type = bool
  default = true
}
output "used" { value = "used" }
output "external" {
  value = "never-read"
  precondition {
    condition = var.accepted
    error_message = "The module safety condition must hold."
  }
}
"""
    )
    _git(root, "add", ".")
    assert isinstance(
        analyze_repository(RepositoryAnalysisRequest(root=root, staged=True)), PassedReport
    )


@pytest.mark.parametrize("indexed", [False, True], ids=["unicode", "quoted-instance"])
def test_staged_json_consumers_use_the_native_owner_semantics(
    tmp_path: Path, *, indexed: bool
) -> None:
    root = _repository(tmp_path)
    (root / "infra/main.tf").unlink()
    (root / "infra/child/outputs.tf").write_text(
        'output "café" { value = true }\noutput "external" { value = false }\n'
    )
    call: dict[str, str | dict[str, bool]] = {"source": "./child"}
    if indexed:
        call["for_each"] = {"slot": True}
    value = '${module.child["slot"].café}' if indexed else "${module.child.café}"
    (root / "infra/main.tf.json").write_text(
        json.dumps({"module": {"child": call}, "output": {"public": {"value": value}}})
    )
    _git(root, "add", ".")
    report = analyze_repository(RepositoryAnalysisRequest(root=root, staged=True))
    assert isinstance(report, FindingsReport)
    assert [item.observed for item in report.diagnostics] == ["external"]


def test_head_and_index_keep_their_own_unchanged_consumers(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    _git(
        root,
        "-c",
        "user.name=Repository Lint",
        "-c",
        "user.email=repository-lint@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "fixture",
    )
    (root / "other-root").mkdir()
    (root / "other-root/main.tf").write_text(
        'module "shared" { source = "../infra/child" }\n'
        'output "external" { value = module.shared.external }\n'
    )
    _git(root, "add", ".")
    staged = analyze_repository(RepositoryAnalysisRequest(root=root, staged=True))
    committed = analyze_repository(RepositoryAnalysisRequest(root=root))
    assert isinstance(staged, PassedReport)
    assert isinstance(committed, FindingsReport)
    (root / "other-root/main.tf").write_text("terraform {}\n")
    assert isinstance(
        analyze_repository(RepositoryAnalysisRequest(root=root, staged=True)), PassedReport
    )


@pytest.mark.parametrize(
    ("output", "evidence"),
    [("external", "contract.md"), ("missing", "contract.md"), ("external", "missing.md")],
)
def test_exact_external_contracts_validate_both_output_and_tracked_evidence(
    tmp_path: Path, output: str, evidence: str
) -> None:
    root = _repository(tmp_path)
    (root / "contract.md").write_text(
        "An external metadata reader contract remains uncertain; retain its exact output.\n"
    )
    manifest = root / ".repo-standards/repository.toml"
    manifest.write_text(
        _MANIFEST
        + f"""\n[[terraform.external_outputs]]
module = "infra/child"
output = "{output}"
reason = "Preserve the documented external metadata interface"
evidence = "{evidence}"
"""
    )
    _git(root, "add", ".")
    report = analyze_repository(RepositoryAnalysisRequest(root=root, staged=True))
    if output == "external" and evidence == "contract.md":
        assert isinstance(report, PassedReport)
        snapshot = load_calibration_snapshot(
            root, manifest.read_bytes(), identity=git_index_identity(root)
        )
        assert (
            SarjPolicy.evaluate_repository(snapshot, enabled_rule_ids=frozenset({RuleId(_RULE)}))
            == ()
        )
    else:
        assert isinstance(report, IncompleteReport)


@pytest.mark.parametrize(
    ("output", "expected"),
    [("café", PassedReport), ("*", IncompleteReport)],
    ids=["exact-unicode-contract", "wildcard-is-not-a-consumer"],
)
def test_external_contracts_match_actual_output_names(
    tmp_path: Path, output: str, expected: type[PassedReport | IncompleteReport]
) -> None:
    root = _repository(tmp_path)
    (root / "infra/child/outputs.tf").write_text(
        'output "used" { value = "used" }\noutput "café" { value = "external" }\n'
    )
    (root / "contract.md").write_text("An exact external output contract.\n")
    (root / ".repo-standards/repository.toml").write_text(
        _MANIFEST
        + f"""\n[[terraform.external_outputs]]
module = "infra/child"
output = "{output}"
reason = "Retain the existing externally consumed value"
evidence = "contract.md"
"""
    )
    _git(root, "add", ".")
    assert isinstance(
        analyze_repository(RepositoryAnalysisRequest(root=root, staged=True)), expected
    )


def test_more_than_one_hundred_files_are_analyzed_without_truncation(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    for index in range(120):
        (root / f"infra/child/export-{index}.tf").write_text(
            f'output "unused_{index}" {{ value = "unused" }}\n'
        )
    _git(root, "add", ".")
    report = analyze_repository(RepositoryAnalysisRequest(root=root, staged=True))
    assert isinstance(report, FindingsReport)
    assert len(report.diagnostics) == 121
    assert any(item.path == "infra/child/export-119.tf" for item in report.diagnostics)


def test_malformed_source_cannot_produce_a_successful_policy_result(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    (root / "infra/child/broken.tf").write_text('output "broken" { value = [')
    _git(root, "add", ".")
    assert isinstance(
        analyze_repository(RepositoryAnalysisRequest(root=root, staged=True)), IncompleteReport
    )


def test_explicit_policy_selection_requires_complete_source_evidence(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    manifest = root / ".repo-standards/repository.toml"
    snapshot = load_calibration_snapshot(
        root, manifest.read_bytes(), identity=git_index_identity(root)
    )
    with pytest.raises(ConfigurationError, match="Terraform consumer analysis requires"):
        SarjPolicy.evaluate_repository(
            replace(snapshot, terraform_sources=None),
            enabled_rule_ids=frozenset({RuleId(_RULE)}),
        )


def test_terraform_sources_reject_mutable_worktree_provenance(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    manifest = root / ".repo-standards/repository.toml"
    snapshot = load_calibration_snapshot(
        root, manifest.read_bytes(), identity=git_index_identity(root)
    )
    with pytest.raises(ConfigurationError, match="immutable Git"):
        with_terraform_sources(
            root,
            replace(snapshot, provenance=replace(snapshot.provenance, mode="worktree")),
        )


def test_computed_output_selection_is_preserved_by_the_native_api(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    (root / "infra/main.tf").write_text(
        'module "child" { source = "./child" }\nvariable "selected" {}\n'
        'output "public" { value = module.child[var.selected] }\n'
    )
    _git(root, "add", ".")
    assert isinstance(
        analyze_repository(RepositoryAnalysisRequest(root=root, staged=True)), PassedReport
    )


def test_public_rule_example_exercises_the_real_consumer_analysis() -> None:
    cases = tuple(case for case in rule_example_cases() if case.rule_id == _RULE)
    assert len(cases) == 1
    for case in cases:
        assert _RULE in run_rule_example(case.fixture_id, case.flagged)
        assert _RULE not in run_rule_example(case.fixture_id, case.passes)
