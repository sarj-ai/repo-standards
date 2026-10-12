from __future__ import annotations

import shutil
import subprocess
from typing import TYPE_CHECKING

import pytest

from repo_standards.core.errors import ConfigurationError
from repo_standards.core.inspection import load_repository_snapshot
from repo_standards.policy_sarj import SarjPolicy
from repo_standards.policy_sarj.pull_request_templates import (
    PULL_REQUEST_TEMPLATE_SECTIONS_RULE_ID,
)


if TYPE_CHECKING:
    from pathlib import Path

    from repo_standards.core.models import Diagnostic


_REVIEW_POLICY = """\
repository_id = "example-repository"
components = []

[pull_request.commit_history]
advisory_base_ref = "dev"

[pull_request.review_policy]
zero_review_below_counted_lines = 200
two_reviews_above_counted_lines = 800
migration_roots = []
required_checks = ["ci"]
required_body_sections = ["What & why", "One-way or two-way door", "Test evidence"]
"""
_WITHOUT_REVIEW_POLICY = """\
repository_id = "example-repository"
components = []
"""
_COMPLETE_TEMPLATE = """\
## What & why
<!-- Explain the change. -->

## One-way or two-way door

## Test evidence
"""


def _git(repository: Path, *arguments: str) -> None:
    git_executable = shutil.which("git")
    assert git_executable is not None
    subprocess.run(
        [git_executable, "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        timeout=10,
    )


def _repository(tmp_path: Path, manifest: str, files: dict[str, str]) -> Path:
    repository = tmp_path / "repository"
    for path, content in {".repo-standards/repository.toml": manifest, **files}.items():
        target = repository / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    _git(repository, "init", "--quiet")
    _git(repository, "add", ".")
    _git(
        repository,
        "-c",
        "user.name=Repository Lint",
        "-c",
        "user.email=repository-lint@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "fixture",
    )
    return repository


def _template_diagnostics(repository: Path) -> tuple[Diagnostic, ...]:
    return tuple(
        item
        for item in SarjPolicy.evaluate_repository(load_repository_snapshot(repository))
        if item.rule_id == PULL_REQUEST_TEMPLATE_SECTIONS_RULE_ID
    )


def test_template_with_every_required_heading_passes(tmp_path: Path) -> None:
    repository = _repository(
        tmp_path, _REVIEW_POLICY, {".github/pull_request_template.md": _COMPLETE_TEMPLATE}
    )

    assert _template_diagnostics(repository) == ()


def test_each_missing_heading_is_reported_once(tmp_path: Path) -> None:
    template = "## What & why\n\n<!-- ## Test evidence -->\n"
    repository = _repository(
        tmp_path, _REVIEW_POLICY, {".github/pull_request_template.md": template}
    )

    diagnostics = _template_diagnostics(repository)

    assert [(item.path, item.expected) for item in diagnostics] == [
        (".github/pull_request_template.md", "One-way or two-way door"),
        (".github/pull_request_template.md", "Test evidence"),
    ]
    assert len({item.manifest_anchor for item in diagnostics}) == len(diagnostics)


def test_github_template_names_match_without_case(tmp_path: Path) -> None:
    repository = _repository(
        tmp_path,
        _REVIEW_POLICY,
        {
            "docs/PULL_REQUEST_TEMPLATE.txt": _COMPLETE_TEMPLATE,
            "PULL_REQUEST_TEMPLATE.md": "## What & why\n",
            "apps/web/docs/pull_request_template.md": "",
            ".github/PULL_REQUEST_TEMPLATE/feature.md": "",
        },
    )

    snapshot = load_repository_snapshot(repository)

    assert sorted(template.path for template in snapshot.pull_request_templates) == [
        "PULL_REQUEST_TEMPLATE.md",
        "docs/PULL_REQUEST_TEMPLATE.txt",
    ]
    assert {item.path for item in _template_diagnostics(repository)} == {"PULL_REQUEST_TEMPLATE.md"}


def test_required_sections_without_a_template_are_reported(tmp_path: Path) -> None:
    repository = _repository(tmp_path, _REVIEW_POLICY, {"README.md": "example\n"})

    (diagnostic,) = _template_diagnostics(repository)

    assert diagnostic.subject_kind == "pull-request-template"
    assert diagnostic.path == ".github/pull_request_template.md"


def test_repository_without_review_policy_skips_the_template(tmp_path: Path) -> None:
    repository = _repository(
        tmp_path,
        _WITHOUT_REVIEW_POLICY,
        {".github/pull_request_template.md": "x" * 1_048_577},
    )

    snapshot = load_repository_snapshot(repository)

    assert snapshot.pull_request_templates == ()
    assert _template_diagnostics(repository) == ()


def test_oversized_template_is_a_configuration_error(tmp_path: Path) -> None:
    repository = _repository(
        tmp_path,
        _REVIEW_POLICY,
        {".github/pull_request_template.md": "x" * 1_048_577},
    )

    with pytest.raises(ConfigurationError, match="pull-request template exceeds"):
        load_repository_snapshot(repository)
