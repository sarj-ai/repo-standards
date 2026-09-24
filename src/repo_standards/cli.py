from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, replace
from datetime import date
from enum import StrEnum
from importlib import metadata
import json
import os
from pathlib import Path
import re
from typing import Annotated, ClassVar, Literal, NamedTuple, NewType, NoReturn, TypeGuard

from pydantic import BaseModel, ConfigDict, Field, ValidationError
import typer

from repo_standards.catalog import (
    build_catalog,
    catalog_schema,
    report_schema,
)
from repo_standards.core.canonical import canonical_json
from repo_standards.core.commit_message import CommitMessageResult, check_local_commit_message_file
from repo_standards.core.engine import analyze, check_baseline
from repo_standards.core.errors import ConfigurationError
from repo_standards.core.inspection import (
    GitIdentity,
    git_identity,
    git_index_identity,
    inspect_repository,
    load_repository_snapshot,
    read_tracked_blob_contents,
)
from repo_standards.core.models import (
    AnalysisReport,
    Baseline,
    Diagnostic,
    ExecutionIssue,
    FindingsReport,
    GitObjectId,
    IncompleteReport,
    Mode,
    Policy,
    PolicyId,
    PullRequestConfig,
    PullRequestReviewPolicyConfig,
    RepositoryId,
    RepositoryInspection,
    RepositoryPolicy,
    Rule,
    RuleId,
)
from repo_standards.core.parser import load_manifest
from repo_standards.core.pull_request_body import missing_required_body_sections
from repo_standards.core.pull_request_commits import (
    DEFAULT_MAXIMUM_COMMITS,
    PullRequestCommits,
    TransitionExemption,
    TransitionExemptionId,
    analyze_pull_request_commits,
)
from repo_standards.core.pull_request_documentation import (
    PullRequestDocumentation,
    analyze_pull_request_documentation,
)
from repo_standards.core.pull_request_size import PullRequestSize, analyze_pull_request_size
from repo_standards.core.render import render_text, report_dict
from repo_standards.core.review_policy import (
    CheckConclusion,
    HumanReviewEvidence,
    RequiredCheckEvidence,
    ReviewPolicyConfig,
    ReviewPolicyEvidence,
    ReviewPolicyResult,
    ReviewState,
    evaluate_review_policy,
)
from repo_standards.core.rule_reviews import RuleVersion, activated_rule_ids
from repo_standards.policy_sarj import SarjPolicy
from repo_standards.pull_request._context import NotApplicable
from repo_standards.pull_request._inputs import (
    ResolvedPullRequestInputs,
    resolve_github_pull_request_inputs,
    resolve_local_pull_request_inputs,
)
from repo_standards.rest import (
    InstrumentationDetectionReport,
    TrackedFile as RestTrackedFile,
    detect_instrumentation,
    instrumentation_capabilities,
)


app = typer.Typer(
    name="repo-standards",
    help="Deterministic repository, pull-request, commit, and API contract policy.",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
)
rest_app = typer.Typer(
    name="rest",
    help="Inspect committed OpenAPI contracts without executing application code.",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
)
pull_request_app = typer.Typer(
    name="pull-request",
    help="Analyze pull-request changes without mutating repository or GitHub state.",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
)
app.add_typer(rest_app, name="rest")
app.add_typer(pull_request_app, name="pull-request")

_DISTRIBUTION_NAME = "repo-standards"
_MAX_PAGE_SIZE = 500
_INSPECTION_KINDS = frozenset(
    {"all", "project", "workflow", "cloudbuild", "dockerfile", "terraform", "openapi"}
)
_OPENAPI_BASENAMES = frozenset({"openapi.json", "openapi.yaml", "openapi.yml"})
_MAX_RENDERED_COMMIT_FINDINGS = 3
_MAX_REVIEW_POLICY_EVIDENCE_BYTES = 1_048_576


class _CompletedAnalysis(NamedTuple):
    report: AnalysisReport
    regressions: tuple[Diagnostic, ...]
    baseline_state: Mapping[str, object]
    ratchet_state: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class _TrustedReviewPolicy:
    pull_request: PullRequestConfig
    config: PullRequestReviewPolicyConfig


class _PageOptions(NamedTuple):
    limit: int
    offset: int


class RequestError(ValueError):
    @classmethod
    def fail(cls, message: str) -> NoReturn:
        raise cls(message)


class BaselineError(ConfigurationError):
    """One baseline-specific input failure for explicit ratchet reporting."""


class _TransitionExemptionInput(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True, strict=True)

    id: TransitionExemptionId = Field(min_length=1)
    repository_id: RepositoryId = Field(min_length=1)
    source_ref: str = Field(min_length=1)
    base_ref: str = Field(min_length=1)
    head_prefix: str = Field(min_length=1)
    sha_prefix_length: int = Field(default=12, ge=7, le=40)


class _ReviewPolicyCheckInput(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True, strict=True)

    name: str = Field(min_length=1, max_length=256)
    conclusion: CheckConclusion
    head_sha: str = Field(pattern=r"^[0-9a-f]{40}$")


class _ReviewPolicyReviewInput(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True, strict=True)

    reviewer: str = Field(min_length=1, max_length=256)
    state: ReviewState
    commit_sha: str | None = Field(default=None, pattern=r"^[0-9a-f]{40}$")


BaseRepositoryId = NewType("BaseRepositoryId", int)
HeadRepositoryId = NewType("HeadRepositoryId", int)


class _ReviewPolicyEvidenceInput(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal[1]
    evaluated_head_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    current_head_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    base_ref: str = Field(min_length=1, max_length=1_024)
    head_ref: str = Field(min_length=1, max_length=1_024)
    base_repository_id: BaseRepositoryId = Field(gt=0)
    head_repository_id: HeadRepositoryId = Field(gt=0)
    is_draft: bool
    author_login: str = Field(min_length=1, max_length=256)
    author_is_bot: bool
    required_checks_complete: bool
    required_checks: tuple[_ReviewPolicyCheckInput, ...] = Field(max_length=512)
    reviews_complete: bool
    latest_human_reviews: tuple[_ReviewPolicyReviewInput, ...] = Field(max_length=10_000)
    threads_complete: bool
    threads_resolved: bool
    body: str = Field(max_length=1_048_576)


class OutputFormat(StrEnum):
    """Stable report renderers."""

    JSON = "json"
    PRETTY_JSON = "pretty-json"
    TEXT = "text"


class SchemaDocument(StrEnum):
    REPORT = "report"
    CATALOG = "catalog"


def _version_callback(value: object) -> None:
    if value is True:
        typer.echo(_installed_version())
        raise typer.Exit


@app.callback()
def root_command(
    *,
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version_callback, is_eager=True),
    ] = False,
) -> None:
    """Run deterministic repository analysis."""


def main() -> None:
    app()


def _envelope(
    command: str,
    *,
    completion: str = "complete",
    conclusion: str = "passed",
    provenance: Mapping[str, object] | None = None,
    issues: Sequence[Mapping[str, object]] = (),
) -> dict[str, object]:
    return {
        "schema_version": 2,
        "tool": _tool(),
        "command": command,
        "completion": completion,
        "conclusion": conclusion,
        "provenance": dict(provenance or {"kind": "installed-environment"}),
        "execution_issues": list(issues),
    }


def _tool() -> Mapping[str, object]:
    return {"name": "repo-standards", "version": _installed_version()}


def _installed_version() -> str:
    try:
        return metadata.version(_DISTRIBUTION_NAME)
    except metadata.PackageNotFoundError:
        return "unknown"


@app.command("capabilities")
def capabilities_command() -> None:
    """Describe the stable machine capabilities without inspecting a repository."""
    payload = {
        **_envelope("capabilities"),
        "commands": [
            "capabilities",
            "catalog",
            "check",
            "commit-message",
            "explain",
            "inspect",
            "pull-request commits",
            "pull-request review-policy",
            "pull-request size",
            "report",
            "rest discover",
            "rest doctor",
            "rules",
            "schema",
        ],
        "formats": ["json", "pretty-json", "text"],
        "modes": ["report", "ratchet", "strict"],
        "exit_codes": {"0": "satisfied", "1": "policy-findings", "2": "incomplete"},
        "safety": {
            "network": False,
            "network_default": False,
            "network_mode": "disabled",
            "repository_code_execution": False,
            "mutation": "commit-message --fix-safe only",
            "autofix": "bounded mechanical commit-header normalization only",
            "inspection_input": "exact-git-head-tree",
        },
        "domains": {
            "repository": {"status": "stable"},
            "rest": {
                "status": "preview",
                "input": "committed-openapi-json",
                "application_code_execution": False,
            },
        },
        "schemas": ["catalog", "report"],
        "pagination": {"default_limit": 100, "maximum_limit": _MAX_PAGE_SIZE},
    }
    typer.echo(canonical_json(payload))


@app.command("catalog")
def catalog_command() -> None:
    """Export the deterministic public product, rule, command, and schema catalog."""
    try:
        payload = build_catalog(app, package_version=_installed_version())
    except (ConfigurationError, TypeError, ValueError) as error:
        _emit_command_error(
            "catalog",
            "catalog.invalid",
            str(error),
            remediation="Repair the installed metadata before publishing its public catalog.",
        )
    typer.echo(canonical_json(payload.model_dump(mode="json")))


@app.command("commit-message")
def commit_message_command(
    message_file: Annotated[Path, typer.Argument(help="Git commit-message file to validate.")],
    fix_safe: Annotated[  # ruff: ignore[boolean-default-value-positional-argument] - Typer option
        bool,
        typer.Option(
            "--fix-safe/--no-fix-safe",
            help="Apply only verified mechanical header normalization.",
        ),
    ] = False,
    output_format: Annotated[OutputFormat, typer.Option("--format")] = OutputFormat.TEXT,
) -> None:
    """Enforce `[(i/n) ][TICKET] type(scope)!: description` and safely normalize spacing/case."""
    try:
        result = check_local_commit_message_file(message_file, root=Path.cwd(), fix_safe=fix_safe)
    except (ConfigurationError, OSError) as error:
        _emit_command_error(
            "commit-message",
            "analysis.incomplete",
            str(error),
            phase="analysis",
            remediation="Provide exactly one bounded UTF-8 regular commit-message file.",
        )
    payload = _commit_message_payload(result, fix_safe_enabled=fix_safe)
    if output_format is OutputFormat.TEXT:
        rendered = _render_commit_message(result)
        if rendered:
            typer.echo(rendered, nl=False)
    elif output_format is OutputFormat.PRETTY_JSON:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True) + "\n", nl=False)
    else:
        typer.echo(canonical_json(payload) + "\n", nl=False)
    if not result.satisfied:
        raise typer.Exit(1)


def _commit_message_payload(
    result: CommitMessageResult,
    *,
    fix_safe_enabled: bool,
) -> Mapping[str, object]:
    return {
        **_envelope(
            "commit-message",
            conclusion="passed" if result.satisfied else "findings",
            provenance={"kind": "commit-message-file"},
        ),
        "policy": {
            "id": "managed-conventional-header-v1",
            "enforcement": "strict",
            "safe_fix": True,
            "safe_fix_enabled": fix_safe_enabled,
        },
        "summary": {
            "satisfied": result.satisfied,
            "fix_applied": result.fix_applied,
            "replacement_message": result.replacement_header,
            "replacement_header": result.replacement_header,
        },
        "findings": [asdict(finding) for finding in result.findings],
    }


def _render_commit_message(result: CommitMessageResult) -> str:
    if result.fix_applied:
        return "Commit message: safely normalized; validation passed.\n"
    if result.satisfied:
        return ""
    finding = result.findings[0]
    return f"Commit message: {finding.code}\n{finding.message}\nFix: {finding.remediation}\n"


@pull_request_app.command("size")
def pull_request_size_command(  # ruff: ignore[too-many-arguments,too-many-positional-arguments] - Typer command options stay explicit
    root: Annotated[Path, typer.Argument()] = Path(),
    base: Annotated[str, typer.Option(help="Trusted base revision used for diff and policy.")] = "",
    head: Annotated[str, typer.Option(help="Head revision to compare with the base.")] = "HEAD",
    generated_attribute: Annotated[
        str,
        typer.Option(help="Git attribute that marks repository-specific excluded artifacts."),
    ] = "pr-size-excluded",
    report_path: Annotated[
        Path | None,
        typer.Option(
            "--report-path",
            help="Write the complete canonical JSON report to this path.",
        ),
    ] = None,
    output_format: Annotated[OutputFormat, typer.Option("--format")] = OutputFormat.TEXT,
) -> None:
    """Calculate review-sized churn while excluding tests and declared generated artifacts."""
    if not base:
        _emit_command_error(
            "pull-request size",
            "request.invalid",
            "--base is required",
            phase="request",
            remediation="Pass --base with the trusted revision used for the pull request.",
        )
    try:
        result = analyze_pull_request_size(
            root,
            base=base,
            head=head,
            generated_attribute=generated_attribute,
        )
    except (ConfigurationError, OSError) as error:
        _emit_command_error(
            "pull-request size",
            "analysis.incomplete",
            str(error),
            phase="analysis",
            remediation=(
                "Fetch and verify the base and head revisions, then retry from a Git worktree."
            ),
        )
    top_files = 10
    payload = _pull_request_size_payload(result, top_files=top_files)
    if report_path is not None:
        try:
            report_path.write_text(canonical_json(payload) + "\n", encoding="utf-8")
        except OSError as error:
            _emit_command_error(
                "pull-request size",
                "output.incomplete",
                str(error),
                phase="output",
                remediation="Choose a writable --report-path and retry.",
            )
    if output_format is OutputFormat.TEXT:
        typer.echo(_render_pull_request_size(result, top_files=top_files), nl=False)
    elif output_format is OutputFormat.PRETTY_JSON:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True) + "\n", nl=False)
    else:
        typer.echo(canonical_json(payload) + "\n", nl=False)


def _pull_request_size_payload(result: PullRequestSize, *, top_files: int) -> Mapping[str, object]:
    category_lines = result.category_lines()
    summary = result.summary
    largest = sorted(
        (item for item in result.files if item.category == "production"),
        key=lambda item: (-item.lines, item.path),
    )[:top_files]
    return {
        **_envelope(
            "pull-request size",
            provenance={"kind": "git-revisions", "base": result.base, "head": result.head},
        ),
        "policy": {
            "test_conventions": True,
            "generated_attribute": result.generated_attribute,
            "attribute_source": result.base,
        },
        "summary": {
            "counted_lines": result.counted_lines,
            "excluded_lines": result.excluded_lines,
            "total_lines": result.total_lines,
            "changed_files": summary.changed_files,
            "categories": category_lines,
            "additions": summary.additions,
            "deletions": summary.deletions,
            "counted_files": summary.counted_files,
            "counted_additions": summary.counted_additions,
            "counted_deletions": summary.counted_deletions,
            "excluded_files": summary.excluded_files,
            "excluded_additions": summary.excluded_additions,
            "excluded_deletions": summary.excluded_deletions,
            "binary_files": summary.binary_files,
        },
        "categories": [
            {
                **asdict(category),
                "lines": category.lines,
            }
            for category in result.category_sizes()
        ],
        "directories": [
            {
                "path": directory.path,
                "changed_files": directory.changed_files,
                "additions": directory.additions,
                "deletions": directory.deletions,
                "counted_lines": directory.counted_lines,
                "excluded_lines": directory.excluded_lines,
                "total_lines": directory.total_lines,
                "categories": [
                    {
                        **asdict(category),
                        "lines": category.lines,
                    }
                    for category in directory.categories
                ],
            }
            for directory in result.directory_sizes()
        ],
        "files": [
            {
                **asdict(item),
                "lines": item.lines,
            }
            for item in result.files
        ],
        "largest_counted_files": [
            {
                "path": item.path,
                "lines": item.lines,
                "additions": item.additions,
                "deletions": item.deletions,
            }
            for item in largest
        ],
    }


def _render_pull_request_size(result: PullRequestSize, *, top_files: int) -> str:
    categories = result.category_lines()
    summary = result.summary
    lines = [
        (
            f"Counted review size: {result.counted_lines} lines "
            f"(+{summary.counted_additions}/-{summary.counted_deletions}, "
            f"{summary.counted_files} files)"
        ),
        (
            f"Excluded churn: {result.excluded_lines} lines "
            f"(+{summary.excluded_additions}/-{summary.excluded_deletions}, "
            f"{summary.excluded_files} files)"
        ),
        (
            f"Total churn: {result.total_lines} lines "
            f"(+{summary.additions}/-{summary.deletions}, {summary.changed_files} files)"
        ),
        "Categories: " + ", ".join(f"{name}={value}" for name, value in categories.items()),
    ]
    largest = sorted(
        (item for item in result.files if item.category == "production"),
        key=lambda item: (-item.lines, item.path),
    )[:top_files]
    if largest:
        lines.append("Largest counted files:")
        lines.extend(f"  {item.lines:>6}  {item.path}" for item in largest)
    return "\n".join(lines) + "\n"


@pull_request_app.command("documentation")
def pull_request_documentation_command(
    root: Annotated[Path, typer.Argument()] = Path(),
    base: Annotated[str, typer.Option(help="Trusted base revision used for policy.")] = "",
    head: Annotated[str, typer.Option(help="Head revision to compare with the base.")] = "HEAD",
    output_format: Annotated[OutputFormat, typer.Option("--format")] = OutputFormat.TEXT,
) -> None:
    """Limit newly added Markdown pages using policy from the trusted base tree."""
    if not base:
        _emit_command_error(
            "pull-request documentation",
            "request.invalid",
            "--base is required",
            phase="request",
            remediation="Pass --base with the trusted pull-request base revision.",
        )
    try:
        result = analyze_pull_request_documentation(root, base=base, head=head)
    except (ConfigurationError, OSError) as error:
        _emit_command_error(
            "pull-request documentation",
            "analysis.incomplete",
            str(error),
            phase="analysis",
            remediation="Fetch and verify the base and head revisions, then retry.",
        )
    payload = _pull_request_documentation_payload(result)
    if output_format is OutputFormat.TEXT:
        typer.echo(_render_pull_request_documentation(result), nl=False)
    elif output_format is OutputFormat.PRETTY_JSON:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True) + "\n", nl=False)
    else:
        typer.echo(canonical_json(payload) + "\n", nl=False)
    if not result.satisfied:
        raise typer.Exit(1)


def _pull_request_documentation_payload(
    result: PullRequestDocumentation,
) -> Mapping[str, object]:
    return {
        **_envelope(
            "pull-request documentation",
            provenance={"kind": "git-revisions", "base": result.base, "head": result.head},
        ),
        "policy": {"maximum_added_pages": result.maximum_added_pages, "source": result.base},
        "summary": {
            "satisfied": result.satisfied,
            "added_pages": len(result.added_pages),
            "exempt_pages": len(result.exempt_pages),
        },
        "findings": list(result.added_pages),
        "exemptions": list(result.exempt_pages),
    }


def _render_pull_request_documentation(result: PullRequestDocumentation) -> str:
    lines = [
        f"Added Markdown pages: {len(result.added_pages)}/{result.maximum_added_pages}",
    ]
    lines.extend(f"  {path}" for path in result.added_pages)
    if result.exempt_pages:
        lines.append(f"Explicitly exempt pages: {len(result.exempt_pages)}")
        lines.extend(f"  {path}" for path in result.exempt_pages)
    if not result.satisfied:
        lines.append(
            "Remove or consolidate new pages; durable documentation belongs in the existing graph."
        )
    return "\n".join(lines) + "\n"


def _trusted_review_policy(
    root: Path, manifest: Path | None
) -> _TrustedReviewPolicy:
    manifest_path = manifest or Path(".repo-standards/repository.toml")
    if not manifest_path.is_absolute():
        manifest_path = root / manifest_path
    configured_pull_request = load_manifest(manifest_path).pull_request
    if configured_pull_request is None or configured_pull_request.review_policy is None:
        ConfigurationError.fail("trusted manifest must define pull_request.review_policy")
    return _TrustedReviewPolicy(configured_pull_request, configured_pull_request.review_policy)


@pull_request_app.command("review-policy")
def pull_request_review_policy_command(  # ruff: ignore[too-many-arguments,too-many-positional-arguments] - trusted inputs stay explicit
    root: Annotated[Path, typer.Argument()] = Path(),
    base: Annotated[str, typer.Option(help="Exact trusted base commit SHA.")] = "",
    head: Annotated[str, typer.Option(help="Exact evaluated pull-request head commit SHA.")] = "",
    evidence: Annotated[
        Path | None,
        typer.Option(help="Strict, complete provider evidence JSON."),
    ] = None,
    manifest: Annotated[
        Path | None,
        typer.Option(help="Trusted repository manifest."),
    ] = None,
    generated_attribute: Annotated[
        str,
        typer.Option(help="Git attribute that marks repository-specific excluded artifacts."),
    ] = "pr-size-excluded",
) -> None:
    """Evaluate the configured review tier from exact Git and provider evidence."""
    if not re.fullmatch(r"[0-9a-f]{40}", base) or not re.fullmatch(r"[0-9a-f]{40}", head):
        _emit_command_error(
            "pull-request review-policy",
            "request.invalid",
            "--base and --head must be exact lowercase 40-character commit SHAs",
            phase="request",
            remediation="Pass the immutable base and pull-request head commit object IDs.",
        )
    if evidence is None:
        _emit_command_error(
            "pull-request review-policy",
            "request.invalid",
            "--evidence is required",
            phase="request",
            remediation="Write the complete provider evidence JSON and pass its path.",
        )
    try:  # ruff: ignore[too-many-statements-in-try-clause] - one fail-closed evidence transaction
        resolved_root = root.resolve(strict=True)
        trusted_policy = _trusted_review_policy(resolved_root, manifest)
        configured_pull_request = trusted_policy.pull_request
        configured = trusted_policy.config
        provider = _load_review_policy_evidence(evidence)
        _require_complete_review_policy_evidence(provider)
        if provider.evaluated_head_sha != head:
            ConfigurationError.fail(
                "evidence evaluated_head_sha must equal the exact --head commit SHA"
            )
        configured_check_names = tuple(configured.required_checks)
        observed_check_names = tuple(item.name for item in provider.required_checks)
        if len(observed_check_names) != len(set(observed_check_names)):
            ConfigurationError.fail("required_checks evidence contains duplicate check names")
        if set(observed_check_names) != set(configured_check_names):
            ConfigurationError.fail(
                "required_checks evidence must contain exactly the checks in the trusted manifest"
            )
        transition_exemption = _matching_review_policy_transition(
            provider=provider,
            configured_pull_request=configured_pull_request,
        )
        if transition_exemption is None:
            size = analyze_pull_request_size(
                resolved_root,
                base=base,
                head=head,
                generated_attribute=generated_attribute,
            )
            counted_lines = size.counted_lines
            changed_paths = tuple(item.path for item in size.files)
            missing_sections = missing_required_body_sections(
                provider.body,
                configured.required_body_sections,
            )
        else:
            size = None
            counted_lines = configured.zero_review_below_counted_lines
            changed_paths = ()
            missing_sections = ()
        result = evaluate_review_policy(
            ReviewPolicyEvidence(
                counted_lines=counted_lines,
                changed_paths=changed_paths,
                evaluated_head_sha=GitObjectId(provider.evaluated_head_sha),
                current_head_sha=GitObjectId(provider.current_head_sha),
                required_checks=tuple(
                    RequiredCheckEvidence(item.name, item.conclusion)
                    for item in provider.required_checks
                ),
                latest_human_reviews=tuple(
                    HumanReviewEvidence(
                        reviewer=item.reviewer,
                        state=item.state,
                        commit_sha=(
                            GitObjectId(item.commit_sha) if item.commit_sha is not None else None
                        ),
                    )
                    for item in provider.latest_human_reviews
                ),
                threads_resolved=provider.threads_resolved,
            ),
            ReviewPolicyConfig(
                zero_review_below_lines=configured.zero_review_below_counted_lines,
                one_review_maximum_lines=configured.two_reviews_above_counted_lines,
                migration_roots=configured.migration_roots,
                accepted_check_conclusions=frozenset(
                    CheckConclusion(item) for item in configured.accepted_check_conclusions
                ),
            ),
        )
    except (ConfigurationError, OSError, ValidationError, ValueError) as error:
        _emit_command_error(
            "pull-request review-policy",
            "analysis.incomplete",
            str(error),
            phase="analysis",
            remediation=(
                "Verify the repository manifest, exact revisions, and complete provider evidence."
            ),
        )
    payload = _pull_request_review_policy_payload(
        base=base,
        size=size,
        provider=provider,
        configured=configured,
        result=result,
        missing_sections=missing_sections,
        transition_exemption=transition_exemption,
    )
    typer.echo(canonical_json(payload) + "\n", nl=False)
    if not _review_policy_merge_ready(
        result=result,
        provider=provider,
        missing_sections=missing_sections,
        transition_exemption=transition_exemption,
    ):
        raise typer.Exit(1)


def _load_review_policy_evidence(path: Path) -> _ReviewPolicyEvidenceInput:
    try:
        if path.stat().st_size > _MAX_REVIEW_POLICY_EVIDENCE_BYTES:
            RequestError.fail("review policy evidence exceeds 1048576 bytes")
        return _ReviewPolicyEvidenceInput.model_validate_json(path.read_bytes())
    except OSError:
        RequestError.fail(f"cannot read review policy evidence: {path}")
    except ValidationError:
        RequestError.fail("review policy evidence does not match schema version 1")


def _require_complete_review_policy_evidence(provider: _ReviewPolicyEvidenceInput) -> None:
    incomplete = [
        name
        for name, complete in (
            ("required checks", provider.required_checks_complete),
            ("reviews", provider.reviews_complete),
            ("conversation threads", provider.threads_complete),
        )
        if not complete
    ]
    if incomplete:
        ConfigurationError.fail(f"provider evidence is incomplete for: {', '.join(incomplete)}")


def _matching_review_policy_transition(
    *,
    provider: _ReviewPolicyEvidenceInput,
    configured_pull_request: PullRequestConfig,
) -> str | None:
    review_policy = configured_pull_request.review_policy
    if (
        review_policy is None
        or provider.head_repository_id != provider.base_repository_id
        or provider.current_head_sha != provider.evaluated_head_sha
        or provider.author_login not in review_policy.transition_actors
    ):
        return None
    exemptions = set(review_policy.transition_exemptions)
    for transition in configured_pull_request.commit_history.transitions:
        expected_head_ref = (
            f"{transition.head_prefix}{provider.evaluated_head_sha[: transition.sha_prefix_length]}"
        )
        if (
            transition.transition_id in exemptions
            and provider.base_ref == transition.base_ref
            and provider.head_ref == expected_head_ref
        ):
            return transition.transition_id
    return None


def _review_policy_merge_ready(
    *,
    result: ReviewPolicyResult,
    provider: _ReviewPolicyEvidenceInput,
    missing_sections: tuple[str, ...],
    transition_exemption: str | None,
) -> bool:
    return (
        result.merge_ready
        and not missing_sections
        and not provider.is_draft
        and (not provider.author_is_bot or transition_exemption is not None)
        and provider.head_repository_id == provider.base_repository_id
        and all(check.head_sha == provider.evaluated_head_sha for check in provider.required_checks)
    )


def _pull_request_review_policy_payload(  # ruff: ignore[too-many-arguments] - receipt inputs are distinct evidence domains
    *,
    base: str,
    size: PullRequestSize | None,
    provider: _ReviewPolicyEvidenceInput,
    configured: PullRequestReviewPolicyConfig,
    result: ReviewPolicyResult,
    missing_sections: tuple[str, ...],
    transition_exemption: str | None,
) -> Mapping[str, object]:
    merge_ready = _review_policy_merge_ready(
        result=result,
        provider=provider,
        missing_sections=missing_sections,
        transition_exemption=transition_exemption,
    )
    summary = size.summary if size is not None else None
    reasons = _review_policy_receipt_reasons(
        result=result,
        provider=provider,
        missing_sections=missing_sections,
        transition_exemption=transition_exemption,
    )
    return {
        **_envelope(
            "pull-request review-policy",
            conclusion="passed" if merge_ready else "findings",
            provenance={
                "kind": "git-revisions-and-provider-evidence",
                "base": base,
                "evaluated_head": provider.evaluated_head_sha,
                "current_head": provider.current_head_sha,
            },
        ),
        "policy": {
            "zero_review_below_counted_lines": configured.zero_review_below_counted_lines,
            "two_reviews_above_counted_lines": configured.two_reviews_above_counted_lines,
            "migration_roots": list(configured.migration_roots),
            "required_checks": list(configured.required_checks),
            "accepted_check_conclusions": list(configured.accepted_check_conclusions),
            "required_body_sections": list(configured.required_body_sections),
            "transition_exemptions": list(configured.transition_exemptions),
            "transition_actors": list(configured.transition_actors),
        },
        "summary": {
            "merge_ready": merge_ready,
            "tier": result.required_human_reviews,
            "required_human_reviews": result.required_human_reviews,
            "current_human_approvals": result.current_human_approvals,
            "touches_migration": result.touches_migration,
            "transition_exemption": transition_exemption,
            "missing_body_sections": list(missing_sections),
            "reasons": reasons,
        },
        "counts": {
            "changed_files": summary.changed_files if summary is not None else None,
            "counted_files": summary.counted_files if summary is not None else None,
            "excluded_files": summary.excluded_files if summary is not None else None,
            "binary_files": summary.binary_files if summary is not None else None,
            "required_checks": len(configured.required_checks),
            "human_reviews": len(provider.latest_human_reviews),
        },
        "size": (
            {
                "classification": "measured",
                "counted_lines": summary.counted_lines,
                "excluded_lines": summary.excluded_lines,
                "total_lines": summary.total_lines,
                "additions": summary.additions,
                "deletions": summary.deletions,
                "counted_additions": summary.counted_additions,
                "counted_deletions": summary.counted_deletions,
                "excluded_additions": summary.excluded_additions,
                "excluded_deletions": summary.excluded_deletions,
                "categories": size.category_lines(),
            }
            if size is not None and summary is not None
            else {
                "classification": "transition-exempt",
                "counted_lines": None,
                "excluded_lines": None,
                "total_lines": None,
                "additions": None,
                "deletions": None,
                "counted_additions": None,
                "counted_deletions": None,
                "excluded_additions": None,
                "excluded_deletions": None,
                "categories": {},
            }
        ),
        "files": [
            {
                "path": item.path,
                "category": item.category,
                "additions": item.additions,
                "deletions": item.deletions,
                "lines": item.lines,
            }
            for item in (() if size is None else size.files)
        ],
    }


def _review_policy_receipt_reasons(
    *,
    result: ReviewPolicyResult,
    provider: _ReviewPolicyEvidenceInput,
    missing_sections: tuple[str, ...],
    transition_exemption: str | None,
) -> list[str]:
    reasons = [reason.value for reason in result.reasons]
    if transition_exemption is not None:
        reasons.append("transition_exemption")
    if missing_sections:
        reasons.append("body_sections_incomplete")
    if provider.is_draft:
        reasons.append("draft_pull_request")
    if provider.author_is_bot and transition_exemption is None:
        reasons.append("bot_authored_pull_request")
    if provider.head_repository_id != provider.base_repository_id:
        reasons.append("cross_repository_pull_request")
    if any(check.head_sha != provider.evaluated_head_sha for check in provider.required_checks):
        reasons.append("check_head_mismatch")
    return reasons


@pull_request_app.command("commits")
def pull_request_commits_command(  # ruff: ignore[too-many-arguments,too-many-positional-arguments] - Typer command options stay explicit
    root: Annotated[Path, typer.Argument()] = Path(),
    base: Annotated[str, typer.Option(help="Exact pull-request base revision.")] = "",
    head: Annotated[str, typer.Option(help="Exact pull-request head revision.")] = "HEAD",
    base_ref: Annotated[str | None, typer.Option(help="Pull-request base ref name.")] = None,
    head_ref: Annotated[str | None, typer.Option(help="Pull-request head ref name.")] = None,
    repository_id: Annotated[
        str | None,
        typer.Option(help="Exact PR head owner/name identity used by transition exemptions."),
    ] = None,
    maximum_commits: Annotated[
        int,
        typer.Option("--max-commits", help="Maximum unnumbered non-merge commits."),
    ] = DEFAULT_MAXIMUM_COMMITS,
    transition_exemption: Annotated[
        list[str] | None,
        typer.Option(
            "--transition-exemption",
            help="Trusted JSON transition exemption; repeat for multiple transitions.",
        ),
    ] = None,
    github_event: Annotated[
        Path | None,
        typer.Option(help="GitHub Actions event payload containing exact pull-request evidence."),
    ] = None,
    advisory: Annotated[  # ruff: ignore[boolean-default-value-positional-argument] - Typer renders this as an option
        bool,
        typer.Option(help="Report policy findings without a nonzero policy exit."),
    ] = False,
    quiet: Annotated[  # ruff: ignore[boolean-default-value-positional-argument] - Typer renders this as an option
        bool,
        typer.Option(help="Suppress output only when analysis completes successfully."),
    ] = False,
    output_format: Annotated[OutputFormat, typer.Option("--format")] = OutputFormat.TEXT,
) -> None:
    """Require concise PR history or one complete explicitly numbered series."""
    if github_event is None and not base and not advisory:
        _emit_command_error(
            "pull-request commits",
            "request.invalid",
            "--base is required unless --github-event is used",
            phase="request",
            remediation="Pass exact provider evidence or use advisory local discovery.",
        )
    try:
        exemptions = tuple(
            _parse_transition_exemption(value) for value in (transition_exemption or ())
        )
    except (TypeError, ValueError) as error:
        _emit_command_error(
            "pull-request commits",
            "request.invalid",
            str(error),
            phase="request",
            remediation="Correct the trusted transition exemption configuration.",
        )
    try:
        resolved = _resolve_pull_request_commits_request(
            root=root,
            base=base,
            head=head,
            base_ref=base_ref,
            head_ref=head_ref,
            repository_id=repository_id,
            maximum_commits=maximum_commits,
            exemptions=exemptions,
            github_event=github_event,
            advisory=advisory,
        )
    except (ConfigurationError, OSError) as error:
        if advisory:
            _emit_pull_request_commits_advisory_incomplete(
                error,
                output_format=output_format,
            )
            return
        _emit_command_error(
            "pull-request commits",
            "analysis.incomplete",
            str(error),
            phase="analysis",
            remediation=(
                "Fetch complete base/head history and verify every trusted transition input."
            ),
        )
    if isinstance(resolved, NotApplicable):
        if not quiet:
            _emit_pull_request_commits_not_applicable(
                resolved,
                output_format=output_format,
            )
        return
    result = resolved
    payload = _pull_request_commits_payload(result, advisory=advisory)
    if quiet and not result.has_findings:
        pass
    elif output_format is OutputFormat.TEXT:
        typer.echo(_render_pull_request_commits(result, advisory=advisory), nl=False)
    elif output_format is OutputFormat.PRETTY_JSON:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True) + "\n", nl=False)
    else:
        typer.echo(canonical_json(payload) + "\n", nl=False)
    if not advisory and not result.satisfied:
        raise typer.Exit(1)


def _resolve_pull_request_commits_request(  # ruff: ignore[too-many-arguments] - CLI evidence remains explicit
    *,
    root: Path,
    base: str,
    head: str,
    base_ref: str | None,
    head_ref: str | None,
    repository_id: str | None,
    maximum_commits: int,
    exemptions: tuple[TransitionExemption, ...],
    github_event: Path | None,
    advisory: bool,
) -> PullRequestCommits | NotApplicable:
    if github_event is not None:
        manual_input = any(
            (
                bool(base),
                head != "HEAD",
                base_ref is not None,
                head_ref is not None,
                repository_id is not None,
                maximum_commits != DEFAULT_MAXIMUM_COMMITS,
                bool(exemptions),
                advisory,
            )
        )
        if manual_input:
            ConfigurationError.fail(
                "--github-event cannot be combined with manual evidence, "
                "policy overrides, or --advisory"
            )
        event_name = os.environ.get(  # ruff: ignore[banned-api] - GitHub supplies the trusted event kind
            "GITHUB_EVENT_NAME", ""
        )
        if not event_name:
            ConfigurationError.fail("GITHUB_EVENT_NAME is required with --github-event")
        inputs = resolve_github_pull_request_inputs(
            root,
            github_event,
            event_name=event_name,
        )
        if isinstance(inputs, NotApplicable):
            return inputs
        return _analyze_resolved_pull_request_inputs(root, inputs)
    if base:
        return analyze_pull_request_commits(
            root,
            base=base,
            head=head,
            maximum_commits=maximum_commits,
            repository_id=repository_id,
            base_ref=base_ref,
            head_ref=head_ref,
            transition_exemptions=exemptions,
        )
    if not advisory:
        ConfigurationError.fail(
            "--base is required unless --github-event or --advisory local discovery is used"
        )
    manifest = load_manifest(root / ".repo-standards" / "repository.toml")
    policy = manifest.pull_request
    if policy is None:
        ConfigurationError.fail(
            "local discovery requires pull_request.commit_history configuration"
        )
    history = policy.commit_history
    inputs = resolve_local_pull_request_inputs(
        root,
        default_base_ref=history.advisory_base_ref,
        transition_bases=tuple(
            (
                transition.head_prefix,
                transition.base_ref,
                transition.sha_prefix_length,
            )
            for transition in history.transitions
        ),
    )
    for transition in history.transitions:
        expected_head_ref = (
            f"{transition.head_prefix}{inputs.context.head_sha[: transition.sha_prefix_length]}"
        )
        if (
            inputs.context.base_ref == transition.base_ref
            and inputs.context.head_ref == expected_head_ref
        ):
            return NotApplicable(
                event_name="local",
                reason=(
                    f"candidate transition {transition.transition_id}; "
                    "authoritative CI will verify repository identity and source ancestry"
                ),
            )
    return analyze_pull_request_commits(
        root,
        base=inputs.context.base_sha,
        head=inputs.context.head_sha,
        maximum_commits=history.maximum_commits,
        commit_message_enforcement=(
            manifest.commit_message.enforcement
        ),
    )


def _analyze_resolved_pull_request_inputs(
    root: Path,
    inputs: ResolvedPullRequestInputs,
) -> PullRequestCommits:
    context = inputs.context
    configured = inputs.manifest.pull_request if inputs.manifest is not None else None
    history = configured.commit_history if configured is not None else None
    maximum_commits = history.maximum_commits if history is not None else DEFAULT_MAXIMUM_COMMITS
    repository_id = (
        str(context.head_repository_id) if context.head_repository_id is not None else None
    )
    transition_exemptions = ()
    if history is not None and context.base_repository_id is not None:
        transition_exemptions = tuple(
            TransitionExemption(
                exemption_id=TransitionExemptionId(transition.transition_id),
                repository_id=RepositoryId(str(context.base_repository_id)),
                source_ref=f"origin/{transition.source_ref}",
                base_ref=transition.base_ref,
                head_prefix=transition.head_prefix,
                sha_prefix_length=transition.sha_prefix_length,
            )
            for transition in history.transitions
        )
    return analyze_pull_request_commits(
        root,
        base=context.base_sha,
        head=context.head_sha,
        maximum_commits=maximum_commits,
        repository_id=repository_id,
        base_ref=context.base_ref,
        head_ref=context.head_ref,
        transition_exemptions=transition_exemptions,
        commit_message_enforcement=(
            inputs.manifest.commit_message.enforcement
            if inputs.manifest is not None
            else None
        ),
    )


def _emit_pull_request_commits_not_applicable(
    result: NotApplicable,
    *,
    output_format: OutputFormat,
) -> None:
    is_local_advisory = result.event_name == "local"
    payload = {
        **_envelope(
            "pull-request commits",
            conclusion="inconclusive" if is_local_advisory else "passed",
            provenance=(
                {"kind": "local-advisory"}
                if is_local_advisory
                else {"kind": "github-event", "event_name": result.event_name}
            ),
        ),
        "summary": {"disposition": "not-applicable", "reason": result.reason},
    }
    if output_format is OutputFormat.TEXT:
        typer.echo(f"PR commits: not applicable — {result.reason}.\n", nl=False)
    elif output_format is OutputFormat.PRETTY_JSON:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True) + "\n", nl=False)
    else:
        typer.echo(canonical_json(payload) + "\n", nl=False)


def _parse_transition_exemption(value: str) -> TransitionExemption:
    try:
        document = _TransitionExemptionInput.model_validate_json(value)
    except ValidationError as error:
        message = "transition exemption does not match the required JSON schema"
        raise RequestError(message) from error
    return TransitionExemption(
        exemption_id=document.id,
        repository_id=document.repository_id,
        source_ref=document.source_ref,
        base_ref=document.base_ref,
        head_prefix=document.head_prefix,
        sha_prefix_length=document.sha_prefix_length,
    )


def _emit_pull_request_commits_advisory_incomplete(
    error: Exception,
    *,
    output_format: OutputFormat,
) -> None:
    payload = _envelope(
        "pull-request commits",
        completion="incomplete",
        conclusion="inconclusive",
        issues=[
            _issue_payload(
                "analysis.incomplete",
                "analysis",
                str(error),
                "Authoritative pull-request CI will retry with complete exact revisions.",
            )
        ],
    )
    if output_format is OutputFormat.TEXT:
        typer.echo(
            "PR commit policy: advisory analysis incomplete; continuing.\n"
            f"Reason: {error}\n"
            "Authoritative pull-request CI will evaluate exact revisions."
        )
        return
    rendered = (
        json.dumps(payload, indent=2, sort_keys=True)
        if output_format is OutputFormat.PRETTY_JSON
        else canonical_json(payload)
    )
    typer.echo(rendered)


def _pull_request_commits_payload(
    result: PullRequestCommits,
    *,
    advisory: bool,
) -> Mapping[str, object]:
    summary: dict[str, object] = {
        "commit_count": result.commit_count,
        "satisfied": result.satisfied,
        "disposition": result.disposition,
        "numbering_issue": result.numbering_issue,
        "exemption_id": result.exemption_id,
    }
    payload: dict[str, object] = {
        **_envelope(
            "pull-request commits",
            conclusion="findings" if result.has_findings else "passed",
            provenance={
                "kind": "git-revisions",
                "base": result.base_object_id,
                "head": result.head_object_id,
            },
        ),
        "policy": {
            "enabled": True,
            "maximum_commits": result.maximum_commits,
            "counting": "base-exclusive-non-merge-commits",
            "numbered_series": "complete-(i/n)-subject-prefixes",
            "enforcement": "advisory" if advisory else "strict",
        },
        "summary": summary,
    }
    if result.commit_message_enforcement is not None:
        summary.update(
            {
                "commit_message_enforcement": result.commit_message_enforcement,
                "commit_message_findings": len(result.commit_message_findings),
            }
        )
        payload["summary"] = summary
        payload["commit_message_findings"] = [
            {
                "object_id": finding.object_id,
                "subject": finding.subject,
                **asdict(finding.finding),
            }
            for finding in result.commit_message_findings
        ]
    return payload


def _render_pull_request_commits(result: PullRequestCommits, *, advisory: bool) -> str:
    lines = [
        f"PR commits: {result.commit_count} non-merge commit(s); limit {result.maximum_commits}",
        f"Disposition: {result.disposition}",
        f"Base: {result.base_object_id}",
        f"Head: {result.head_object_id}",
    ]
    if result.numbering_issue is not None:
        lines.append(f"Numbered series: {result.numbering_issue}")
    if result.exemption_id is not None:
        label = "Local transition candidate" if advisory else "Verified transition"
        lines.append(f"{label}: {result.exemption_id}")
    if result.commit_message_findings:
        mode = result.commit_message_enforcement or "disabled"
        lines.append(f"Commit messages: {len(result.commit_message_findings)} finding(s) ({mode})")
        lines.extend(
            f"  {finding.object_id}: {finding.finding.code}"
            for finding in result.commit_message_findings[:_MAX_RENDERED_COMMIT_FINDINGS]
        )
        if len(result.commit_message_findings) > _MAX_RENDERED_COMMIT_FINDINGS:
            remaining = len(result.commit_message_findings) - _MAX_RENDERED_COMMIT_FINDINGS
            lines.append(f"  ... and {remaining} more")
        lines.append(
            "Commit-message fix: rewrite each header as "
            "`[(i/n) ][TICKET] type(scope)!: description` and retry."
        )
    if not result.satisfied:
        lines.append(
            "Remediation: reduce the PR to at most "
            f"{result.maximum_commits} commits (prefer one), or prefix every subject with the "
            "complete canonical `(i/n) ` series."
        )
        if advisory:
            lines.append(
                "Advisory only: authoritative PR CI will evaluate the exact base and head."
            )
    return "\n".join(lines) + "\n"


@app.command("inspect")
def inspect_command(
    root: Annotated[Path, typer.Argument()] = Path(),
    kind: Annotated[
        str,
        typer.Option(
            help="Filter: all, project, workflow, cloudbuild, dockerfile, terraform, openapi."
        ),
    ] = "all",
    path_prefix: Annotated[
        str | None, typer.Option(help="Filter by repository path prefix.")
    ] = None,
    limit: Annotated[str, typer.Option(help="Page size from 1 through 500.")] = "100",
    cursor: Annotated[
        str | None, typer.Option(help="Opaque cursor returned by the prior page.")
    ] = None,
) -> None:
    """Inventory tracked inert repository metadata without requiring a manifest."""
    identity = None
    try:
        resolved = root.resolve(strict=True)
        identity = git_identity(resolved)
        inspection = inspect_repository(resolved, identity=identity)
    except (ConfigurationError, OSError) as error:
        payload = _envelope(
            "inspect",
            completion="incomplete",
            conclusion="inconclusive",
            provenance=_git_provenance(identity),
            issues=[
                _issue_payload(
                    "inspection.incomplete",
                    "inspection",
                    str(error),
                    "Inspect the reported Git object and correct or classify it explicitly.",
                )
            ],
        )
        typer.echo(canonical_json(payload))
        raise typer.Exit(2) from None
    try:
        page_limit, page_offset = _page_options(limit, cursor)
        payload = _inspection_payload(
            inspection,
            kind=kind,
            path_prefix=path_prefix,
            limit=page_limit,
            offset=page_offset,
        )
    except RequestError as error:
        _emit_command_error("inspect", "request.invalid", str(error), phase="request")
    rendered = canonical_json(payload) + "\n"
    typer.echo(rendered, nl=False)
    if inspection.completion != "complete":
        raise typer.Exit(2)


def _inspection_payload(
    inspection: RepositoryInspection,
    *,
    kind: str,
    path_prefix: str | None,
    limit: int,
    offset: int,
) -> Mapping[str, object]:
    if kind not in _INSPECTION_KINDS:
        message = f"--kind must be one of: {', '.join(sorted(_INSPECTION_KINDS))}"
        raise RequestError(message)
    items = _inspection_items(inspection)
    selected = [
        item
        for item in items
        if (kind == "all" or item["kind"] == kind)
        and (path_prefix is None or str(item["path"]).startswith(path_prefix))
    ]
    page = selected[offset : offset + limit]
    next_cursor = str(offset + limit) if offset + limit < len(selected) else None
    return {
        **_envelope(
            "inspect",
            completion=inspection.completion,
            conclusion="passed" if inspection.completion == "complete" else "inconclusive",
            provenance={
                "kind": "git-tree",
                "source_revision": inspection.source_revision,
                "tree_digest": inspection.tree_digest,
            },
            issues=[
                _issue_payload(
                    "metadata.invalid",
                    "inspection",
                    message,
                    "Correct or explicitly exclude the malformed inert metadata file.",
                )
                for message in inspection.issues
            ],
        ),
        "summary": {
            "tracked_files": inspection.tracked_file_count,
            "packages": len(inspection.packages),
            "workflows": len(inspection.workflow_paths),
            "cloudbuild_files": len(inspection.cloudbuild_paths),
            "dockerfiles": len(inspection.dockerfile_paths),
            "terraform_modules": len(inspection.terraform_modules),
            "openapi_candidates": len(_openapi_candidates(inspection)),
        },
        "filters": {"kind": kind, "path_prefix": path_prefix},
        "page": {
            "limit": limit,
            "returned": len(page),
            "total": len(selected),
            "next_cursor": next_cursor,
        },
        "items": page,
    }


def _inspection_items(inspection: RepositoryInspection) -> list[Mapping[str, object]]:
    items: list[Mapping[str, object]] = [
        {
            "kind": "project",
            "ecosystem": item.ecosystem,
            "path": item.path,
            "name": item.name,
            "private": item.private,
            "workspace_root": item.workspace_root,
        }
        for item in inspection.packages
    ]
    for kind, paths in (
        ("workflow", inspection.workflow_paths),
        ("cloudbuild", inspection.cloudbuild_paths),
        ("dockerfile", inspection.dockerfile_paths),
        ("terraform", inspection.terraform_modules),
        ("openapi", _openapi_candidates(inspection)),
    ):
        items.extend({"kind": kind, "path": path} for path in paths)
    return sorted(items, key=lambda item: (str(item["path"]), str(item["kind"])))


def _openapi_candidates(inspection: RepositoryInspection) -> tuple[str, ...]:
    return tuple(
        item.path
        for item in inspection.tracked_files
        if Path(item.path).name.casefold() in _OPENAPI_BASENAMES
    )


def _detect_rest_snapshot(
    root: Path,
    identity: GitIdentity,
    inspection: RepositoryInspection,
) -> InstrumentationDetectionReport:
    paths = tuple(
        item.path for item in inspection.tracked_files if _is_rest_detection_path(item.path)
    )
    selected = read_tracked_blob_contents(root, paths, identity=identity)
    return detect_instrumentation(
        tuple(RestTrackedFile(item.path, item.content) for item in selected)
    )


def _is_rest_detection_path(path: str) -> bool:
    basename = Path(path).name.casefold()
    return (
        basename
        in {
            "api-operation-map.json",
            "cargo.toml",
            "go.mod",
            "package.json",
            "pom.xml",
            "pyproject.toml",
        }
        or basename.startswith(("requirements", "build.gradle"))
        or basename in _OPENAPI_BASENAMES
        or basename in {"swagger.json", "swagger.yaml", "swagger.yml"}
    )


def _git_provenance(identity: GitIdentity | None) -> Mapping[str, object]:
    return {
        "kind": "git-tree",
        "source_revision": identity.source_revision if identity is not None else None,
        "tree_digest": identity.tree_digest if identity is not None else None,
    }


@rest_app.command("discover")
def rest_discover_command(
    root: Annotated[Path, typer.Argument()] = Path(),
) -> None:
    """Discover committed OpenAPI entry candidates without importing application code."""
    identity = None
    try:
        resolved = root.resolve(strict=True)
        identity = git_identity(resolved)
        inspection = inspect_repository(resolved, identity=identity)
    except (ConfigurationError, OSError) as error:
        _emit_rest_error("rest.discover", "rest.discovery-incomplete", str(error), identity)
    detection = _detect_rest_snapshot(resolved, identity, inspection)
    candidates = _openapi_candidates(inspection)
    completion = (
        "incomplete"
        if inspection.completion != "complete" or detection.completion != "complete"
        else "complete"
    )
    payload = {
        **_envelope(
            "rest.discover",
            completion=completion,
            conclusion="passed" if completion == "complete" else "inconclusive",
            provenance=_git_provenance(identity),
            issues=[
                _issue_payload(
                    "metadata.invalid",
                    "inspection",
                    issue,
                    "Correct or explicitly exclude the malformed tracked metadata.",
                )
                for issue in inspection.issues
            ]
            + [
                _issue_payload(
                    issue.code,
                    "rest-detection",
                    issue.message,
                    "Correct or explicitly classify the tracked framework metadata.",
                )
                for issue in detection.issues
            ],
        ),
        "application_code_executed": False,
        "coverage": {
            "status": "partial",
            "reason_codes": ["committed-conventional-specs-only"],
        },
        "candidates": [
            {
                "id": path,
                "kind": "openapi-entry-candidate",
                "path": path,
                "analysis_support": "supported" if path.endswith(".json") else "discovery-only",
            }
            for path in candidates
        ],
        "instrumentation_candidates": [asdict(item) for item in detection.candidates],
        "summary": {
            "contract_candidates": len(candidates),
            "instrumentation_candidates": len(detection.candidates),
            "files_scanned": detection.files_scanned,
            "bytes_scanned": detection.bytes_scanned,
        },
        "next_actions": (
            []
            if len(candidates) == 1
            else ["Select one exact tracked contract for an OpenAPI linter."]
        ),
    }
    typer.echo(canonical_json(payload))
    if completion != "complete":
        raise typer.Exit(2)


@rest_app.command("doctor")
def rest_doctor_command(root: Annotated[Path, typer.Argument()] = Path()) -> None:
    """Return the installed capability handshake and inert repository detection."""
    identity = None
    try:
        resolved = root.resolve(strict=True)
        identity = git_identity(resolved)
        inspection = inspect_repository(resolved, identity=identity)
        detection = _detect_rest_snapshot(resolved, identity, inspection)
    except (ConfigurationError, OSError) as error:
        _emit_rest_error("rest.doctor", "rest.discovery-incomplete", str(error), identity)
    completion = (
        "complete"
        if inspection.completion == "complete" and detection.completion == "complete"
        else "incomplete"
    )
    payload = {
        **_envelope(
            "rest.doctor",
            completion=completion,
            conclusion="passed" if completion == "complete" else "inconclusive",
            provenance=_git_provenance(identity),
            issues=[
                _issue_payload(
                    issue.code,
                    "rest-detection",
                    issue.message,
                    "Correct or explicitly classify the tracked framework metadata.",
                )
                for issue in detection.issues
            ],
        ),
        "application_code_executed": False,
        "capabilities": [asdict(item) for item in instrumentation_capabilities()],
        "detected": [asdict(item) for item in detection.candidates],
        "coverage": {
            "status": "partial",
            "reason_codes": ["manifest-and-committed-artifact-evidence-only"],
        },
    }
    typer.echo(canonical_json(payload))
    if completion != "complete":
        raise typer.Exit(2)


def _emit_rest_error(
    command: str,
    code: str,
    message: str,
    identity: GitIdentity | None,
) -> NoReturn:
    payload = _envelope(
        command,
        completion="incomplete",
        conclusion="inconclusive",
        provenance=_git_provenance(identity),
        issues=[
            _issue_payload(
                code,
                "rest",
                message,
                "Review the tracked contract selection and rerun without executing "
                "application code.",
            )
        ],
    )
    payload["schema_version"] = 3
    typer.echo(canonical_json(payload))
    raise typer.Exit(2)


def _issue_payload(
    code: str,
    phase: str,
    message: str,
    remediation: str,
) -> Mapping[str, object]:
    return {
        "code": code,
        "phase": phase,
        "message": message,
        "retryable": False,
        "remediation": [remediation],
    }


@app.command()
def check(  # ruff: ignore[too-many-arguments,too-many-positional-arguments] - Typer CLI boundary
    root: Annotated[Path, typer.Argument()] = Path(),
    manifest: Annotated[str, typer.Option()] = ".repo-standards/repository.toml",
    baseline: Annotated[str, typer.Option()] = ".repo-standards/baseline.json",
    mode: Annotated[Mode, typer.Option()] = Mode.STRICT,
    output_format: Annotated[OutputFormat, typer.Option("--format")] = OutputFormat.TEXT,
    as_of: Annotated[str | None, typer.Option(help="Deterministic YYYY-MM-DD")] = None,
    staged: Annotated[  # ruff: ignore[boolean-default-value-positional-argument] - Typer option
        bool,
        typer.Option(
            help="Analyze the exact staged Git index; ignore unstaged and untracked bytes."
        ),
    ] = False,
    enable_rule: Annotated[
        list[str] | None,
        typer.Option(
            "--enable-rule",
            help="Activate a current rule ID for this run.",
        ),
    ] = None,
) -> None:
    """Analyze one repository manifest."""
    raise typer.Exit(
        _run_check(
            root=root,
            manifest_path=manifest,
            baseline_path=baseline,
            mode=mode,
            output_format=output_format,
            as_of=as_of,
            staged=staged,
            enabled_rule_ids=tuple(enable_rule or ()),
        )
    )


@app.command("report")
def report_command(
    root: Annotated[Path, typer.Argument()] = Path(),
    manifest: Annotated[str, typer.Option()] = ".repo-standards/repository.toml",
    output_format: Annotated[OutputFormat, typer.Option("--format")] = OutputFormat.TEXT,
    as_of: Annotated[str | None, typer.Option(help="Deterministic YYYY-MM-DD")] = None,
    enable_rule: Annotated[
        list[str] | None,
        typer.Option(
            "--enable-rule",
            help="Activate a current rule ID for this run.",
        ),
    ] = None,
) -> None:
    """Analyze one manifest without blocking on completed policy findings."""
    raise typer.Exit(
        _run_check(
            root=root,
            manifest_path=manifest,
            baseline_path=".repo-standards/baseline.json",
            mode=Mode.REPORT,
            output_format=output_format,
            as_of=as_of,
            staged=False,
            enabled_rule_ids=tuple(enable_rule or ()),
        )
    )


def _run_check(  # ruff: ignore[too-many-arguments] - normalized CLI options
    *,
    root: Path,
    manifest_path: str,
    baseline_path: str,
    mode: Mode,
    output_format: OutputFormat,
    as_of: str | None,
    staged: bool,
    enabled_rule_ids: tuple[str, ...],
) -> int:
    command = "report" if mode is Mode.REPORT else "check"
    baseline_state: Mapping[str, object] = {
        "status": "not-requested" if mode is not Mode.RATCHET else "not-evaluated",
        "path": baseline_path if mode is Mode.RATCHET else None,
    }
    ratchet_state: Mapping[str, object] = {"status": "not-requested"}
    try:
        policy = _policy()
        report, regressions, baseline_state, ratchet_state = _complete_analysis(
            root=root,
            manifest_path=manifest_path,
            baseline_path=baseline_path,
            policy=policy,
            mode=mode,
            as_of=as_of,
            staged=staged,
            enabled_rule_ids=enabled_rule_ids,
        )
    except ConfigurationError as error:
        report = _incomplete(SarjPolicy.policy_id, mode, str(error))
        if mode is Mode.RATCHET:
            baseline_state = {
                "status": "rejected" if isinstance(error, BaselineError) else "not-evaluated",
                "path": baseline_path,
            }
            ratchet_state = {"status": "not-evaluated", "reason": "analysis-incomplete"}
        typer.echo(
            _render(
                report,
                output_format,
                command=command,
                manifest_path=manifest_path,
                baseline=baseline_state,
                ratchet=ratchet_state,
            ),
            nl=False,
        )
        return 2
    typer.echo(
        _render(
            report,
            output_format,
            command=command,
            manifest_path=manifest_path,
            baseline=baseline_state,
            ratchet=ratchet_state,
        ),
        nl=False,
    )
    if report.completion != "complete":
        return 2
    if mode is Mode.REPORT:
        return 0
    if mode is Mode.STRICT:
        return int(
            any(
                item.severity == "error" and item.disposition == "active"
                for item in report.diagnostics
            )
        )
    return int(bool(regressions))


def _complete_analysis(  # ruff: ignore[too-many-arguments] - explicit analysis inputs
    *,
    root: Path,
    manifest_path: str,
    baseline_path: str,
    policy: Policy,
    mode: Mode,
    as_of: str | None,
    staged: bool,
    enabled_rule_ids: tuple[str, ...],
) -> _CompletedAnalysis:
    try:
        resolved_root = root.resolve(strict=True)
    except OSError:
        ConfigurationError.fail(f"repository root is unavailable: {root}")
    try:
        snapshot = load_repository_snapshot(
            resolved_root,
            manifest_path=manifest_path,
            baseline_path=baseline_path if mode is Mode.RATCHET else None,
            identity=git_index_identity(resolved_root) if staged else None,
        )
    except ConfigurationError as error:
        if mode is Mode.RATCHET and "baseline" in str(error):
            raise BaselineError(str(error)) from error
        raise
    repository_diagnostics = (
        policy.evaluate_repository(snapshot) if isinstance(policy, RepositoryPolicy) else ()
    )
    if snapshot.manifest.enabled_rules and enabled_rule_ids:
        ConfigurationError.fail("manifest enabled_rules cannot be combined with --enable-rule")
    report = analyze(
        snapshot.manifest,
        policy,
        mode=mode,
        as_of=_parse_date(as_of),
        additional_diagnostics=repository_diagnostics,
        enabled_rules=activated_rule_ids(
            snapshot.manifest.enabled_rules or enabled_rule_ids,
            current_rules=frozenset(
                RuleVersion(rule.rule_id, rule.version) for rule in policy.rules()
            ),
        ),
    )
    report = replace(report, input_provenance=snapshot.provenance)
    if mode is not Mode.RATCHET:
        return _CompletedAnalysis(
            report,
            (),
            {"status": "not-requested", "path": None},
            {"status": "not-requested"},
        )
    if snapshot.baseline is None:
        message = "baseline is absent from the selected Git tree"
        raise BaselineError(message)
    return _complete_ratchet_analysis(report, snapshot.baseline, baseline_path)


def _complete_ratchet_analysis(
    report: AnalysisReport, baseline: Baseline, baseline_path: str
) -> _CompletedAnalysis:
    try:
        regressions = check_baseline(report, baseline)
    except ConfigurationError as error:
        raise BaselineError(str(error)) from error
    stale_rule = RuleId("core/baseline/stale-entry")
    stale = tuple(item for item in regressions if item.rule_id == stale_rule)
    new_count = len(regressions) - len(stale)
    active_count = sum(
        item.severity == "error" and item.disposition == "active" for item in report.diagnostics
    )
    ratchet_summary = {
        **report.summary,
        "ratchet_regressions": len(regressions),
        "ratchet_new": new_count,
        "ratchet_stale": len(stale),
        "ratchet_known": max(active_count - new_count, 0),
    }
    if stale:
        report = FindingsReport(
            mode=report.mode,
            repository_id=report.repository_id,
            policy_id=report.policy_id,
            policy_version=report.policy_version,
            scope_digest=report.scope_digest,
            diagnostics=tuple(
                sorted(report.diagnostics + stale, key=lambda item: item.fingerprint)
            ),
            summary=ratchet_summary,
            input_provenance=report.input_provenance,
            ratchet=report.ratchet,
        )
    else:
        report = replace(report, summary=ratchet_summary)
    baseline_state: Mapping[str, object] = {
        "status": "verified",
        "path": baseline_path,
        "fingerprints": len(baseline.fingerprints),
        "scope_digest": baseline.scope_digest,
    }
    ratchet_state: Mapping[str, object] = {
        "status": "regressions" if regressions else "clean",
        "known": max(active_count - new_count, 0),
        "new": new_count,
        "stale": len(stale),
        "regressions": len(regressions),
    }
    return _CompletedAnalysis(report, regressions, baseline_state, ratchet_state)


def _parse_date(value: str | None) -> date | None:
    if value is None:
        return None
    try:
        parsed = date.fromisoformat(value)
    except ValueError:
        ConfigurationError.fail("--as-of must use YYYY-MM-DD")
    if parsed.isoformat() != value:
        ConfigurationError.fail("--as-of must use YYYY-MM-DD")
    return parsed


def _policy() -> Policy:
    return SarjPolicy()


def _incomplete(policy_id: PolicyId, mode: Mode, issue: str) -> AnalysisReport:
    return IncompleteReport(
        mode=mode,
        repository_id=RepositoryId("unknown"),
        policy_id=policy_id,
        policy_version=0,
        scope_digest="0" * 64,
        execution_issues=(
            ExecutionIssue(
                code="analysis.configuration",
                phase="configuration",
                message=issue,
                retryable=False,
                remediation=(
                    "Correct the declared input or select an installed compatible policy.",
                    "Run the same command again and require completion=complete.",
                ),
            ),
        ),
        summary={"diagnostics": 0, "errors": 0, "warnings": 0},
    )


def _render(  # ruff: ignore[too-many-arguments] - stable report envelope inputs
    report: AnalysisReport,
    output_format: OutputFormat,
    *,
    command: str,
    manifest_path: str,
    baseline: Mapping[str, object],
    ratchet: Mapping[str, object],
) -> str:
    if output_format is OutputFormat.TEXT:
        return render_text(report)
    payload = _report_payload(
        report,
        command=command,
        manifest_path=manifest_path,
        baseline=baseline,
        ratchet=ratchet,
    )
    if output_format is OutputFormat.PRETTY_JSON:
        return json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    return canonical_json(payload) + "\n"


def _report_payload(
    report: AnalysisReport,
    *,
    command: str,
    manifest_path: str,
    baseline: Mapping[str, object],
    ratchet: Mapping[str, object],
) -> Mapping[str, object]:
    payload = dict(report_dict(report))
    raw_issues = payload.pop("execution_issues")
    issues = _mapping_list(raw_issues)
    provenance: dict[str, object] = {
        "kind": "repository-manifest",
        "manifest_path": manifest_path,
        "source_revision": None,
        "tree_digest": None,
    }
    if report.input_provenance is not None:
        provenance["kind"] = report.input_provenance.mode
        provenance["source_revision"] = report.input_provenance.source_revision
        provenance["tree_digest"] = report.input_provenance.tree_digest
    return {
        **_envelope(
            command,
            completion=report.completion,
            conclusion=report.conclusion,
            provenance=provenance,
            issues=issues,
        ),
        **payload,
        "baseline": dict(baseline),
        "ratchet": dict(ratchet),
    }


@app.command("explain")
def explain_rule(
    rule_id: Annotated[str, typer.Argument()],
) -> None:
    """Explain one immutable rule."""
    try:
        selected_policy = _policy()
        rules = {str(item.rule_id): item for item in _all_rules(selected_policy)}
    except ConfigurationError as error:
        _emit_command_error("explain", "policy.unavailable", str(error))
    rule = rules.get(rule_id)
    if rule is None:
        _emit_command_error(
            "explain",
            "rule.unknown",
            f"rule is not installed: {rule_id}",
            remediation="Use `repo-standards rules` to discover installed rule IDs.",
        )
    payload = {
        **_envelope(
            "explain",
            provenance={
                "kind": "installed-policy",
                "policy": {
                    "id": str(selected_policy.policy_id),
                    "version": selected_policy.policy_version,
                },
            },
        ),
        "rule": asdict(rule),
    }
    typer.echo(json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True))


@app.command("rules")
def list_rules(
    rule_prefix: Annotated[str | None, typer.Option(help="Filter rule IDs by prefix.")] = None,
    severity: Annotated[str | None, typer.Option(help="Filter by warning or error.")] = None,
    limit: Annotated[str, typer.Option(help="Page size from 1 through 500.")] = "100",
    cursor: Annotated[
        str | None, typer.Option(help="Opaque cursor returned by the prior page.")
    ] = None,
) -> None:
    """List installed policy rules as bounded deterministic JSON."""
    try:
        page_limit, offset = _page_options(limit, cursor)
        _validate_severity(severity)
        selected_policy = _policy()
        rules = [
            item
            for item in sorted(_all_rules(selected_policy), key=lambda item: item.rule_id)
            if (rule_prefix is None or str(item.rule_id).startswith(rule_prefix))
            and (severity is None or item.severity == severity)
        ]
    except ConfigurationError as error:
        _emit_command_error("rules", "policy.unavailable", str(error))
    except RequestError as error:
        _emit_command_error("rules", "request.invalid", str(error), phase="request")
    page = rules[offset : offset + page_limit]
    next_cursor = str(offset + page_limit) if offset + page_limit < len(rules) else None
    payload = {
        **_envelope(
            "rules",
            provenance={
                "kind": "installed-policy",
                "policy": {
                    "id": str(selected_policy.policy_id),
                    "version": selected_policy.policy_version,
                },
            },
        ),
        "filters": {"rule_prefix": rule_prefix, "severity": severity},
        "page": {
            "limit": page_limit,
            "returned": len(page),
            "total": len(rules),
            "next_cursor": next_cursor,
        },
        "rules": [asdict(item) for item in page],
    }
    typer.echo(canonical_json(payload))


def _emit_command_error(
    command: str,
    code: str,
    message: str,
    *,
    phase: str = "configuration",
    remediation: str = "Select an installed compatible policy and retry the same command.",
) -> NoReturn:
    payload = _envelope(
        command,
        completion="incomplete",
        conclusion="inconclusive",
        issues=[_issue_payload(code, phase, message, remediation)],
    )
    typer.echo(canonical_json(payload))
    raise typer.Exit(2)


@app.command("schema")
def print_schema(
    document: Annotated[str, typer.Argument()] = SchemaDocument.REPORT,
) -> None:
    """Print repository report or catalog JSON Schema."""
    try:
        selected = SchemaDocument(document)
    except ValueError:
        _emit_command_error(
            "schema",
            "schema.unknown",
            f"unknown schema document: {document}",
            phase="request",
            remediation="Request `report` or `catalog`.",
        )
    match selected:
        case SchemaDocument.CATALOG:
            payload = catalog_schema()
        case SchemaDocument.REPORT:
            payload = _report_schema()
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))


def _report_schema() -> Mapping[str, object]:
    return report_schema()


def _mapping_list(value: object) -> list[Mapping[str, object]]:
    if not _is_object_list(value):
        return []
    result: list[Mapping[str, object]] = []
    for candidate in value:
        if not _is_object_mapping(candidate):
            continue
        result.append({key: item for key, item in candidate.items() if isinstance(key, str)})
    return result


def _is_object_list(value: object) -> TypeGuard[list[object]]:
    return isinstance(value, list)


def _is_object_mapping(value: object) -> TypeGuard[Mapping[object, object]]:
    return isinstance(value, Mapping)


def _page_options(limit: str, cursor: str | None) -> _PageOptions:
    try:
        parsed_limit = int(limit)
        offset = 0 if cursor is None else int(cursor)
    except ValueError as error:
        message = "--limit and --cursor must be base-10 integers"
        raise RequestError(message) from error
    if not 1 <= parsed_limit <= _MAX_PAGE_SIZE:
        message = f"--limit must be between 1 and {_MAX_PAGE_SIZE}"
        raise RequestError(message)
    if offset < 0 or (cursor is not None and str(offset) != cursor):
        message = "--cursor must be a canonical non-negative integer"
        raise RequestError(message)
    return _PageOptions(parsed_limit, offset)


def _validate_severity(severity: str | None) -> None:
    if severity not in {None, "warning", "error"}:
        message = "--severity must be warning or error"
        raise RequestError(message)


def _all_rules(policy: Policy) -> tuple[Rule, ...]:
    return policy.rules()
