from __future__ import annotations

from dataclasses import dataclass

from repo_standards.core.models import (
    FixtureId,
    GitObjectId,
    InputProvenance,
    Manifest,
    RepositoryId,
    RepositoryInspection,
    RepositorySnapshot,
    RuleId,
    TrackedFileEvidence,
)

from .policy import RULES, SarjPolicy


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
    if fixture_id not in {case.fixture_id for case in rule_example_cases()}:
        message = f"unknown rule example: {fixture_id}"
        raise ValueError(message)
    return _run_repository_path(source)


def _run_repository_path(source: str) -> RuleExampleResult:
    path = source.strip()
    snapshot = RepositorySnapshot(
        manifest=Manifest(repository_id=RepositoryId("example-repository"), components=()),
        baseline=None,
        inspection=RepositoryInspection(
            completion="complete",
            source_revision="b" * 40,
            tree_digest="c" * 40,
            tracked_file_count=1,
            packages=(),
            workflow_paths=(),
            cloudbuild_paths=(),
            dockerfile_paths=(),
            terraform_modules=(),
            issues=(),
            tracked_files=(TrackedFileEvidence(path=path, object_id="a" * 40),),
        ),
        provenance=InputProvenance(
            mode="git-tree",
            source_revision="b" * 40,
            tree_digest="c" * 40,
            manifest_path=".repo-lint/repository.toml",
            manifest_object_id=GitObjectId("d" * 40),
            manifest_digest="e" * 64,
        ),
    )
    diagnostics = SarjPolicy.evaluate_repository(snapshot)
    return RuleExampleResult(
        tuple(sorted((item.rule_id for item in diagnostics), key=str)), complete=True
    )
