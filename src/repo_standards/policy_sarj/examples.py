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
    MigrationComparison,
    PullRequestCommitHistoryConfig,
    PullRequestConfig,
    PullRequestReviewPolicyConfig,
    PullRequestTemplate,
    RepositoryId,
    RepositoryInspection,
    RepositorySnapshot,
    RuleId,
    TrackedFileEvidence,
)
from repo_standards.core.parser import parse_manifest_bytes

from .images import UNDECLARED_IMAGES_RULE_ID
from .javascript import UNTYPED_JAVASCRIPT_RULE_ID
from .local_residue import LOCAL_RESIDUE_RULE_ID
from .makefiles import MAKEFILE_GROWTH_RULE_ID
from .migrations import MIGRATION_CONSOLIDATION_RULE_ID, migration_roots
from .policy import RULES, SarjPolicy
from .pull_request_templates import PULL_REQUEST_TEMPLATE_SECTIONS_RULE_ID


class _MakefileExampleSource(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", strict=True)

    base: dict[str, Annotated[int, Field(ge=0)]]
    head: dict[str, Annotated[int, Field(ge=0)]]


class _MigrationExampleSource(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", strict=True)

    base: tuple[str, ...]
    head: tuple[str, ...]


class _PullRequestTemplateExampleSource(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", strict=True)

    required: tuple[str, ...] = Field(min_length=1)
    template: str | None


class _TrackedFilesExampleSource(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", strict=True)

    tracked: tuple[str, ...]
    manifest: str


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
    if case.rule_id == MIGRATION_CONSOLIDATION_RULE_ID:
        context = _MigrationExampleSource.model_validate_json(source)
        manifest = Manifest(repository_id=RepositoryId("example-repository"), components=())
        return _run_snapshot(
            context.head,
            manifest=manifest,
            migration_comparison=MigrationComparison(
                roots=migration_roots(manifest, (*context.base, *context.head)),
                base_files=tuple(TrackedFileEvidence(path, "f" * 40) for path in context.base),
                head_files=tuple(TrackedFileEvidence(path, "a" * 40) for path in context.head),
            ),
        )
    if case.rule_id == PULL_REQUEST_TEMPLATE_SECTIONS_RULE_ID:
        return _run_pull_request_template(source)
    if case.rule_id in {
        UNTYPED_JAVASCRIPT_RULE_ID,
        UNDECLARED_IMAGES_RULE_ID,
        LOCAL_RESIDUE_RULE_ID,
    } and source.lstrip().startswith("{"):
        context = _TrackedFilesExampleSource.model_validate_json(source)
        return _run_snapshot(
            context.tracked, manifest=parse_manifest_bytes(context.manifest.encode())
        )
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


def _run_pull_request_template(source: str) -> RuleExampleResult:
    context = _PullRequestTemplateExampleSource.model_validate_json(source)
    path = ".github/pull_request_template.md"
    manifest = Manifest(
        repository_id=RepositoryId("example-repository"),
        components=(),
        pull_request=PullRequestConfig(
            commit_history=PullRequestCommitHistoryConfig(advisory_base_ref="main"),
            review_policy=PullRequestReviewPolicyConfig(
                zero_review_below_counted_lines=200,
                two_reviews_above_counted_lines=800,
                migration_roots=(),
                required_checks=(),
                required_body_sections=context.required,
            ),
        ),
    )
    templates = () if context.template is None else (PullRequestTemplate(path, context.template),)
    return _run_snapshot(
        tuple(template.path for template in templates),
        manifest=manifest,
        templates=templates,
    )


def _run_snapshot(
    paths: tuple[str, ...],
    *,
    comparison: MakefileComparison | None = None,
    manifest: Manifest | None = None,
    templates: tuple[PullRequestTemplate, ...] = (),
    migration_comparison: MigrationComparison | None = None,
) -> RuleExampleResult:
    snapshot = RepositorySnapshot(
        manifest=manifest
        or Manifest(repository_id=RepositoryId("example-repository"), components=()),
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
        pull_request_templates=templates,
        migration_comparison=migration_comparison,
    )
    diagnostics = SarjPolicy.evaluate_repository(snapshot)
    return RuleExampleResult(
        tuple(sorted((item.rule_id for item in diagnostics), key=str)), complete=True
    )
