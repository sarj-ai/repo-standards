from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, ClassVar

from pydantic import BaseModel, ConfigDict, Field

from repo_standards.core.models import (
    FixtureId,
    GitObjectId,
    InputProvenance,
    MakefileComparison,
    MakefileMetric,
    Manifest,
    RepositoryId,
    RepositoryInspection,
    RepositorySnapshot,
    RuleId,
    TrackedFileEvidence,
)

from .makefiles import MAKEFILE_GROWTH_RULE_ID
from .policy import RULES, SarjPolicy


class _MakefileExampleSource(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", strict=True)

    base: dict[str, Annotated[int, Field(ge=0)]]
    head: dict[str, Annotated[int, Field(ge=0)]]


@dataclass(frozen=True, slots=True)
class RuleExampleResult:
    rule_ids: tuple[RuleId, ...]
    complete: bool
    execution_issue_codes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RuleExampleCase:
    fixture_id: FixtureId
    rule_id: RuleId
    flagged: str
    passes: str


def rule_example_cases() -> tuple[RuleExampleCase, ...]:
    return tuple(
        RuleExampleCase(example.example_id, rule.rule_id, example.before, example.after)
        for rule in RULES
        for example in rule.examples
    )


def run_rule_example(fixture_id: FixtureId, source: str) -> RuleExampleResult:
    case = next((case for case in rule_example_cases() if case.fixture_id == fixture_id), None)
    if case is None:
        message = f"unknown rule example: {fixture_id}"
        raise ValueError(message)
    if case.rule_id == MAKEFILE_GROWTH_RULE_ID:
        return _run_makefile_comparison(source)
    return _run_repository_path(source)


def _run_repository_path(source: str) -> RuleExampleResult:
    return _run_snapshot((source.strip(),))


def _run_makefile_comparison(source: str) -> RuleExampleResult:
    context = _MakefileExampleSource.model_validate_json(source)
    comparison = MakefileComparison(
        base_revision="f" * 40,
        base_tree_digest="e" * 40,
        basis="explicit",
        base_files=tuple(
            MakefileMetric(path=path, object_id="f" * 40, lines=lines)
            for path, lines in sorted(context.base.items())
        ),
        head_files=tuple(
            MakefileMetric(path=path, object_id="a" * 40, lines=lines)
            for path, lines in sorted(context.head.items())
        ),
        as_of=None,
    )
    return _run_snapshot(tuple(sorted(context.head)), comparison=comparison)


def _run_snapshot(
    paths: tuple[str, ...], *, comparison: MakefileComparison | None = None
) -> RuleExampleResult:
    snapshot = RepositorySnapshot(
        manifest=Manifest(repository_id=RepositoryId("example-repository"), components=()),
        baseline=None,
        inspection=RepositoryInspection(
            completion="complete",
            source_revision="b" * 40,
            tree_digest="c" * 40,
            tracked_file_count=len(paths),
            packages=(),
            workflow_paths=(),
            cloudbuild_paths=(),
            dockerfile_paths=(),
            terraform_modules=(),
            issues=(),
            tracked_files=tuple(
                TrackedFileEvidence(path=path, object_id="a" * 40) for path in paths
            ),
        ),
        provenance=InputProvenance(
            mode="git-tree",
            source_revision="b" * 40,
            tree_digest="c" * 40,
            manifest_path=".repo-lint/repository.toml",
            manifest_object_id=GitObjectId("d" * 40),
            manifest_digest="e" * 64,
        ),
        makefile_comparison=comparison,
    )
    diagnostics = SarjPolicy.evaluate_repository(snapshot)
    return RuleExampleResult(
        tuple(sorted((item.rule_id for item in diagnostics), key=str)), complete=True
    )
