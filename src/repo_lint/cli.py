from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict, replace
from datetime import date, timedelta
from enum import StrEnum
from importlib import metadata
import json
import os
from pathlib import Path
import re
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import] - fixed local Git metadata query
from typing import TYPE_CHECKING, Annotated, NamedTuple, NoReturn, TypeGuard
from urllib.error import URLError
from urllib.parse import SplitResult, urlsplit

import typer

from repo_lint.catalog import (
    build_catalog,
    catalog_schema,
    openapi_report_schema,
    report_schema,
)
from repo_lint.core.canonical import canonical_json
from repo_lint.core.catalog import core_rules
from repo_lint.core.engine import analyze, check_baseline
from repo_lint.core.errors import ConfigurationError
from repo_lint.core.inspection import (
    GitIdentity,
    git_identity,
    inspect_repository,
    load_repository_snapshot,
    read_tracked_blob_contents,
)
from repo_lint.core.migration import migration_diagnostics
from repo_lint.core.models import (
    AnalysisReport,
    DeliveryConfig,
    Diagnostic,
    ExecutionIssue,
    Mode,
    Policy,
    PolicyId,
    RepositoryId,
    RepositoryInspection,
    RepositorySnapshot,
    Rule,
    RuleId,
)
from repo_lint.core.pull_request_size import PullRequestSize, analyze_pull_request_size
from repo_lint.core.registry import POLICY_API_VERSION, PolicyRegistry
from repo_lint.core.render import diagnostic_dict, render_text, report_dict
from repo_lint.core.rule_reviews import activated_rule_versions
from repo_lint.github import GitHubAnalysisReport, GitHubClient, GitHubResponse
from repo_lint.github import WorkflowDocument as GitHubWorkflowDocument
from repo_lint.github import analyze as analyze_github
from repo_lint.openapi import AnalysisReport as OpenApiAnalysisReport
from repo_lint.openapi import AnalysisRequest as OpenApiAnalysisRequest
from repo_lint.openapi import DocumentInput as OpenApiDocumentInput
from repo_lint.openapi import analyze as analyze_openapi
from repo_lint.openapi import local_reference_paths
from repo_lint.openapi import rules as openapi_rules
from repo_lint.rest import (
    InstrumentationDetectionReport,
    detect_instrumentation,
    instrumentation_capabilities,
)
from repo_lint.rest import TrackedFile as RestTrackedFile


if TYPE_CHECKING:
    from urllib.request import Request


app = typer.Typer(
    name="repo-standards",
    help="Deterministic, read-only repository architecture and API contract linter.",
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
_MAX_OPENAPI_DOCUMENTS = 100
_MAX_OPENAPI_TOTAL_BYTES = 20 * 1024 * 1024
_MAX_GIT_ORIGIN_BYTES = 4_096
_GITHUB_SLUG = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}[A-Za-z0-9])?/"
    r"[A-Za-z0-9_.-]{1,100}"
)
_GITHUB_SCP_ORIGIN = re.compile(r"git@github\.com:(?P<path>[^?#]+)")
_GITHUB_HTTP_ERROR = re.compile(r"\(HTTP (?P<status>[1-5][0-9]{2})\)")


class _GitHubCommandAnalysis(NamedTuple):
    report: GitHubAnalysisReport
    identity: GitIdentity
    canonical_repository: str | None


class _CompletedAnalysis(NamedTuple):
    report: AnalysisReport
    regressions: tuple[Diagnostic, ...]
    baseline_state: Mapping[str, object]
    ratchet_state: Mapping[str, object]


class _GitHubAnalysis(NamedTuple):
    diagnostics: tuple[Diagnostic, ...]
    issues: tuple[ExecutionIssue, ...]


class _PageOptions(NamedTuple):
    limit: int
    offset: int


class RequestError(ValueError):
    """One invalid CLI request that must be returned as structured JSON."""


class BaselineError(ConfigurationError):
    """One baseline-specific input failure for explicit ratchet reporting."""


class OutputFormat(StrEnum):
    """Stable report renderers."""

    JSON = "json"
    PRETTY_JSON = "pretty-json"
    TEXT = "text"


class RestEnforcement(StrEnum):
    """Blocking behavior for committed REST contracts."""

    REPORT = "report"
    STRICT = "strict"


class SchemaDocument(StrEnum):
    REPORT = "report"
    OPENAPI_ANALYSIS = "openapi-analysis"
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
    try:
        registry = PolicyRegistry.from_installed()
    except ConfigurationError as error:
        _emit_command_error("capabilities", "policy.unavailable", str(error))
    payload = {
        **_envelope("capabilities"),
        "commands": [
            "capabilities",
            "check",
            "explain",
            "github",
            "inspect",
            "pull-request size",
            "report",
            "rest check",
            "rest discover",
            "rest doctor",
            "rest explain",
            "rest rules",
            "rules",
            "schema",
        ],
        "formats": ["json", "pretty-json", "text"],
        "modes": ["report", "ratchet", "strict"],
        "exit_codes": {"0": "satisfied", "1": "policy-findings", "2": "incomplete"},
        "policy_api_version": POLICY_API_VERSION,
        "policies": [
            {"id": policy.policy_id, "version": policy.policy_version}
            for policy in registry.policies
        ],
        "safety": {
            "network": True,
            "network_default": False,
            "network_mode": "opt-in-read-only-github-api",
            "repository_code_execution": False,
            "mutation": False,
            "autofix": False,
            "inspection_input": "exact-git-head-tree",
        },
        "domains": {
            "github": {
                "status": "beta",
                "input": "committed-workflow-yaml",
                "manifest_required": False,
                "live_evidence": "explicit-read-only",
            },
            "repository": {"status": "stable"},
            "rest": {
                "status": "preview",
                "input": "committed-openapi-json",
                "application_code_execution": False,
            },
        },
        "schemas": {"catalog": 7, "openapi-analysis": 2, "report": 2},
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


@pull_request_app.command("size")
def pull_request_size_command(
    root: Annotated[Path, typer.Argument()] = Path(),
    base: Annotated[str, typer.Option(help="Trusted base revision used for diff and policy.")] = "",
    head: Annotated[str, typer.Option(help="Head revision to compare with the base.")] = "HEAD",
    generated_attribute: Annotated[
        str,
        typer.Option(help="Git attribute that marks repository-specific excluded artifacts."),
    ] = "pr-size-excluded",
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
    if output_format is OutputFormat.TEXT:
        typer.echo(_render_pull_request_size(result, top_files=top_files), nl=False)
    elif output_format is OutputFormat.PRETTY_JSON:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True) + "\n", nl=False)
    else:
        typer.echo(canonical_json(payload) + "\n", nl=False)


def _pull_request_size_payload(result: PullRequestSize, *, top_files: int) -> Mapping[str, object]:
    category_lines = result.category_lines()
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
            "changed_files": len(result.files),
            "categories": category_lines,
        },
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
    lines = [
        f"Counted review size: {result.counted_lines} lines",
        f"Excluded churn: {result.excluded_lines} lines",
        f"Total churn: {result.total_lines} lines",
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


@app.command("github")
def github_command(
    root: Annotated[Path, typer.Argument()] = Path(),
    output_format: Annotated[OutputFormat, typer.Option("--format")] = OutputFormat.TEXT,
    github_repository: Annotated[
        str | None,
        typer.Option(
            help="GitHub owner/name for explicit read-only branch and repository evidence."
        ),
    ] = None,
    enable_rule: Annotated[
        list[str] | None,
        typer.Option(
            "--enable-rule",
            help="Activate one approved rule-id@version selector for this run.",
        ),
    ] = None,
) -> None:
    """Audit committed GitHub workflows, with or without a repository manifest."""
    try:
        enabled = activated_rule_versions(tuple(enable_rule or ()))
        report, identity, canonical_repository = _github_command_analysis(
            root=root,
            github_repository=github_repository,
        )
    except (ConfigurationError, OSError, ValueError) as error:
        payload: Mapping[str, object] = {
            **_envelope(
                "github",
                completion="incomplete",
                conclusion="inconclusive",
                issues=[
                    _issue_payload(
                        "github.analysis-incomplete",
                        "github",
                        str(error),
                        "Correct the selected Git tree or GitHub audit input and rerun.",
                    )
                ],
            ),
            "summary": {"diagnostics": 0, "errors": 0, "warnings": 0},
            "diagnostics": list[Mapping[str, object]](),
        }
        typer.echo(_render_github_payload(payload, output_format), nl=False)
        raise typer.Exit(2) from None
    diagnostics = tuple(
        item
        for item in report.diagnostics
        if any(
            str(rule.rule_id) == item.rule_id and rule.version == item.rule_version
            for rule in enabled
        )
    )
    conclusion = (
        "inconclusive"
        if report.completion != "complete"
        else "findings"
        if diagnostics
        else "passed"
    )
    payload = {
        **_envelope(
            "github",
            completion=report.completion,
            conclusion=conclusion,
            provenance={
                "kind": "git-tree",
                "source_revision": identity.source_revision,
                "tree_digest": identity.tree_digest,
                "github_repository_requested": github_repository,
                "github_repository_canonical": canonical_repository,
            },
            issues=[
                {
                    "code": item.code,
                    "phase": item.phase,
                    "message": item.message,
                    "retryable": item.retryable,
                    "remediation": list(item.remediation),
                }
                for item in report.execution_issues
            ],
        ),
        "summary": {
            "diagnostics": len(diagnostics),
            "errors": sum(item.severity == "error" for item in diagnostics),
            "warnings": sum(item.severity == "warning" for item in diagnostics),
        },
        "diagnostics": [diagnostic_dict(item) for item in diagnostics],
    }
    typer.echo(_render_github_payload(payload, output_format), nl=False)
    if report.completion != "complete":
        raise typer.Exit(2)
    if any(item.severity == "error" for item in diagnostics):
        raise typer.Exit(1)


def _github_command_analysis(
    *,
    root: Path,
    github_repository: str | None,
) -> _GitHubCommandAnalysis:
    resolved = root.resolve(strict=True)
    identity = git_identity(resolved)
    inspection = inspect_repository(resolved, identity=identity)
    delivery = _tracked_delivery_config(resolved, identity, inspection)
    workflows = _workflow_documents(resolved, identity, inspection)
    evidence = None
    canonical_repository = None
    if github_repository is not None:
        repository = resolve_github_repository(
            resolved,
            cli_repository=github_repository,
            manifest_repository=delivery.repository if delivery else None,
        )
        if repository is None:
            ConfigurationError.fail("GitHub repository could not be resolved")
        token = os.environ.get(  # ruff: ignore[banned-api] - approved credential source
            "SARJ_REPO_LINT_GITHUB_TOKEN"
        )
        evidence = _authenticated_github_client(token).collect(repository)
        canonical_repository = evidence.repository
    report = analyze_github(
        delivery,
        evidence,
        workflows,
        repository_files=tuple(item.path for item in inspection.tracked_files),
        selected_revision=identity.source_revision if evidence is not None else None,
    )
    return _GitHubCommandAnalysis(report, identity, canonical_repository)


def _authenticated_github_client(token: str | None) -> GitHubClient:
    if token is not None:
        return GitHubClient(token)
    if shutil.which("gh") is not None:
        return GitHubClient(None, transport=gh_api_transport)
    return GitHubClient(None)


def gh_api_transport(request: Request, timeout: timedelta) -> GitHubResponse:
    executable = shutil.which("gh")
    if executable is None:
        message = "GitHub CLI is unavailable"
        raise OSError(message)
    try:
        result = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] - fixed read-only GitHub API query
            [
                executable,
                "api",
                request.full_url,
                "--method",
                "GET",
                "--header",
                "Accept: application/vnd.github+json",
                "--header",
                "X-GitHub-Api-Version: 2022-11-28",
            ],
            check=False,
            capture_output=True,
            timeout=timeout.total_seconds(),
        )
    except subprocess.TimeoutExpired as error:
        message = "GitHub CLI API request timed out"
        raise TimeoutError(message) from error
    if result.returncode == 0:
        return GitHubResponse(200, result.stdout)
    message = result.stderr.decode("utf-8", errors="replace")
    match = _GITHUB_HTTP_ERROR.search(message)
    if match is None:
        failure = (
            "GitHub CLI could not complete the authenticated API request for "
            f"{urlsplit(request.full_url).path}"
        )
        raise URLError(failure)
    return GitHubResponse(int(match.group("status")), result.stdout or b"{}")


def _tracked_delivery_config(
    root: Path,
    identity: GitIdentity,
    inspection: RepositoryInspection,
) -> DeliveryConfig | None:
    manifest_path = ".repo-lint/repository.toml"
    if not any(item.path == manifest_path for item in inspection.tracked_files):
        return None
    return load_repository_snapshot(root, identity=identity).manifest.delivery


def _workflow_documents(
    root: Path,
    identity: GitIdentity,
    inspection: RepositoryInspection,
) -> tuple[GitHubWorkflowDocument, ...]:
    blobs = read_tracked_blob_contents(root, inspection.workflow_paths, identity=identity)
    return tuple(GitHubWorkflowDocument(path=item.path, content=item.content) for item in blobs)


def _render_github_payload(payload: Mapping[str, object], output_format: OutputFormat) -> str:
    if output_format is OutputFormat.JSON:
        return canonical_json(payload) + "\n"
    if output_format is OutputFormat.PRETTY_JSON:
        return json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    lines: list[str] = []
    for item in _mapping_list(payload.get("diagnostics")):
        location_value = item.get("location")
        location = _string_key_mapping(location_value)
        path = location.get("path", item.get("path", ".github/workflows"))
        line = location.get("line")
        coordinate = f"{path}{':' + str(line) if line is not None else ''}"
        lines.append(
            f"{coordinate}: {item.get('severity', 'warning')} "
            f"{item.get('rule_id', 'github/unknown')}: "
            f"{item.get('message', 'GitHub policy finding')}"
        )
    lines.extend(
        f"repo-standards: analysis incomplete: {item.get('code')}: {item.get('message')}"
        for item in _mapping_list(payload.get("execution_issues"))
    )
    lines.append(f"repo-standards github: {payload.get('conclusion', 'inconclusive')}")
    return "\n".join(lines) + "\n"


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
            "projects": len(inspection.projects),
            "workflows": len(inspection.workflow_paths),
            "cloudbuild_files": len(inspection.cloudbuild_paths),
            "dockerfiles": len(inspection.dockerfile_paths),
            "terraform_roots": len(inspection.terraform_roots),
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
        for item in inspection.projects
    ]
    for kind, paths in (
        ("workflow", inspection.workflow_paths),
        ("cloudbuild", inspection.cloudbuild_paths),
        ("dockerfile", inspection.dockerfile_paths),
        ("terraform", inspection.terraform_roots),
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
            else ["Select one exact tracked contract with `repo-standards rest check --spec PATH`."]
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


@rest_app.command("check")
def rest_check_command(
    root: Annotated[Path, typer.Argument()] = Path(),
    spec: Annotated[
        str | None,
        typer.Option(help="Exact tracked OpenAPI entry path; inferred only when unambiguous."),
    ] = None,
    semantics: Annotated[
        str | None,
        typer.Option(help="Optional exact tracked contract-semantics JSON path."),
    ] = None,
    enforcement: Annotated[
        RestEnforcement,
        typer.Option(help="report or strict; incomplete evidence always exits 2."),
    ] = RestEnforcement.STRICT,
    enable_rule: Annotated[
        list[str] | None,
        typer.Option(
            "--enable-rule",
            help="Activate one approved rule-id@version selector for this run.",
        ),
    ] = None,
) -> None:
    """Check one committed OpenAPI contract from the exact selected Git tree."""
    identity: GitIdentity | None = None
    try:
        enabled = activated_rule_versions(tuple(enable_rule or ()))
        resolved = root.resolve(strict=True)
        identity = git_identity(resolved)
    except (ConfigurationError, OSError, RequestError) as error:
        _emit_rest_error("rest.check", "rest.analysis-incomplete", str(error), identity)
    try:
        report = _analyze_rest_snapshot(resolved, identity, spec, semantics)
    except (ConfigurationError, OSError, RequestError) as error:
        _emit_rest_error("rest.check", "rest.analysis-incomplete", str(error), identity)
    diagnostics = tuple(
        item
        for item in report.diagnostics
        if any(
            str(rule.rule_id) == item.rule_id and rule.version == item.rule_version
            for rule in enabled
        )
    )
    conclusion = (
        "inconclusive"
        if report.completion != "complete"
        else "findings"
        if diagnostics
        else "passed"
    )
    payload = {
        **_envelope(
            "rest.check",
            completion=report.completion,
            conclusion=conclusion,
            provenance=_git_provenance(identity),
            issues=[asdict(item) for item in report.execution_issues],
        ),
        "application_code_executed": False,
        "entrypoint": report.entrypoint,
        "openapi_version": report.openapi_version,
        "diagnostics": [asdict(item) for item in diagnostics],
        "summary": {
            "diagnostics": len(diagnostics),
            "errors": sum(item.severity == "error" for item in diagnostics),
            "warnings": sum(item.severity == "warning" for item in diagnostics),
        },
    }
    typer.echo(canonical_json(payload))
    if report.completion != "complete":
        raise typer.Exit(2)
    if enforcement is RestEnforcement.STRICT and any(
        item.severity == "error" for item in diagnostics
    ):
        raise typer.Exit(1)


@rest_app.command("rules")
def rest_rules_command() -> None:
    """List the immutable REST/OpenAPI RuleProblem catalog."""
    installed = openapi_rules()
    payload = {
        **_envelope(
            "rest.rules",
            provenance={"kind": "installed-package", "package": "repo-standards"},
        ),
        "rules": [asdict(item) for item in installed],
        "summary": {"rules": len(installed)},
    }
    typer.echo(canonical_json(payload))


@rest_app.command("explain")
def rest_explain_command(rule_id: Annotated[str, typer.Argument()]) -> None:
    """Explain one immutable REST/OpenAPI rule without scanning a repository."""
    installed = {item.rule_id: item for item in openapi_rules()}
    rule = installed.get(RuleId(rule_id))
    if rule is None:
        _emit_rest_error("rest.explain", "rule.unknown", f"unknown REST rule: {rule_id}", None)
    payload = {
        **_envelope(
            "rest.explain",
            provenance={"kind": "installed-package", "package": "repo-standards"},
        ),
        "rule": asdict(rule),
    }
    typer.echo(canonical_json(payload))


def _analyze_rest_snapshot(
    root: Path,
    identity: GitIdentity,
    spec: str | None,
    semantics: str | None,
) -> OpenApiAnalysisReport:
    inspection = inspect_repository(root, identity=identity)
    entrypoint = _select_openapi_entry(inspection, spec)
    documents = _read_openapi_closure(root, identity, inspection, entrypoint)
    semantics_bytes = None
    if semantics is not None:
        semantics_bytes = read_tracked_blob_contents(root, (semantics,), identity=identity)[
            0
        ].content
    request = OpenApiAnalysisRequest(
        entrypoint=entrypoint,
        documents=documents,
        semantics=semantics_bytes,
    )
    return analyze_openapi(request)


def _select_openapi_entry(inspection: RepositoryInspection, selected: str | None) -> str:
    candidates = _openapi_candidates(inspection)
    if selected is not None:
        tracked = {item.path for item in inspection.tracked_files}
        if selected not in tracked:
            message = "--spec must name an exact tracked regular file"
            raise RequestError(message)
        return selected
    if len(candidates) != 1:
        raise RequestError(
            "OpenAPI discovery is ambiguous; select one exact candidate with --spec"
            if candidates
            else "no conventional committed OpenAPI document was discovered"
        )
    candidate = candidates[0]
    if not candidate.endswith(".json"):
        message = "the only discovered OpenAPI document uses YAML, which is discovery-only in v2"
        raise RequestError(message)
    return candidate


def _read_openapi_closure(
    root: Path,
    identity: GitIdentity,
    inspection: RepositoryInspection,
    entrypoint: str,
) -> tuple[OpenApiDocumentInput, ...]:
    tracked = {item.path for item in inspection.tracked_files}
    queued = [entrypoint]
    selected: dict[str, bytes] = {}
    total_bytes = 0
    while queued:
        path = queued.pop(0)
        if path in selected:
            continue
        if len(selected) >= _MAX_OPENAPI_DOCUMENTS:
            message = "OpenAPI reference closure exceeds the 100-document limit"
            raise RequestError(message)
        content = read_tracked_blob_contents(root, (path,), identity=identity)[0].content
        total_bytes += len(content)
        if total_bytes > _MAX_OPENAPI_TOTAL_BYTES:
            message = "OpenAPI reference closure exceeds the 20 MiB aggregate limit"
            raise RequestError(message)
        selected[path] = content
        queued.extend(
            target
            for target in local_reference_paths(path, content)
            if target in tracked and target not in selected
        )
    return tuple(OpenApiDocumentInput(path, selected[path]) for path in sorted(selected))


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
    if command == "rest.check":
        payload.update(
            {
                "application_code_executed": False,
                "entrypoint": "",
                "openapi_version": None,
                "diagnostics": [],
                "summary": {"diagnostics": 0, "errors": 0, "warnings": 0},
            }
        )
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
def check(  # ruff: ignore[too-many-arguments,too-many-positional-arguments] - CLI boundary
    root: Annotated[Path, typer.Argument()] = Path(),
    manifest: Annotated[str, typer.Option()] = ".repo-lint/repository.toml",
    baseline: Annotated[str, typer.Option()] = ".repo-lint/baseline.json",
    policy: Annotated[str, typer.Option()] = "sarj",
    mode: Annotated[Mode, typer.Option()] = Mode.STRICT,
    output_format: Annotated[OutputFormat, typer.Option("--format")] = OutputFormat.TEXT,
    as_of: Annotated[str | None, typer.Option(help="Deterministic YYYY-MM-DD")] = None,
    github_repository: Annotated[
        str | None,
        typer.Option(help="GitHub owner/name override for optional read-only delivery evidence."),
    ] = None,
    require_github_evidence: Annotated[  # ruff: ignore[boolean-default-value-positional-argument] - Typer option
        bool,
        typer.Option(help="Exit 2 unless configured GitHub evidence is complete."),
    ] = False,
    enable_rule: Annotated[
        list[str] | None,
        typer.Option(
            "--enable-rule",
            help="Activate one approved rule-id@version selector for this run.",
        ),
    ] = None,
) -> None:
    """Analyze one repository manifest."""
    raise typer.Exit(
        _run_check(
            root=root,
            manifest_path=manifest,
            baseline_path=baseline,
            policy_name=policy,
            mode=mode,
            output_format=output_format,
            as_of=as_of,
            github_repository=github_repository,
            require_github_evidence=require_github_evidence,
            enabled_rule_ids=tuple(enable_rule or ()),
        )
    )


@app.command("report")
def report_command(  # ruff: ignore[too-many-arguments,too-many-positional-arguments] - CLI boundary
    root: Annotated[Path, typer.Argument()] = Path(),
    manifest: Annotated[str, typer.Option()] = ".repo-lint/repository.toml",
    policy: Annotated[str, typer.Option()] = "sarj",
    output_format: Annotated[OutputFormat, typer.Option("--format")] = OutputFormat.TEXT,
    as_of: Annotated[str | None, typer.Option(help="Deterministic YYYY-MM-DD")] = None,
    github_repository: Annotated[
        str | None,
        typer.Option(help="GitHub owner/name override for optional read-only delivery evidence."),
    ] = None,
    require_github_evidence: Annotated[  # ruff: ignore[boolean-default-value-positional-argument] - Typer option
        bool,
        typer.Option(help="Exit 2 unless configured GitHub evidence is complete."),
    ] = False,
    enable_rule: Annotated[
        list[str] | None,
        typer.Option(
            "--enable-rule",
            help="Activate one approved rule-id@version selector for this run.",
        ),
    ] = None,
) -> None:
    """Analyze one manifest without blocking on completed policy findings."""
    raise typer.Exit(
        _run_check(
            root=root,
            manifest_path=manifest,
            baseline_path=".repo-lint/baseline.json",
            policy_name=policy,
            mode=Mode.REPORT,
            output_format=output_format,
            as_of=as_of,
            github_repository=github_repository,
            require_github_evidence=require_github_evidence,
            enabled_rule_ids=tuple(enable_rule or ()),
        )
    )


def _run_check(  # ruff: ignore[too-many-arguments] - normalized CLI options
    *,
    root: Path,
    manifest_path: str,
    baseline_path: str,
    policy_name: str,
    mode: Mode,
    output_format: OutputFormat,
    as_of: str | None,
    github_repository: str | None,
    require_github_evidence: bool,
    enabled_rule_ids: tuple[str, ...],
) -> int:
    command = "report" if mode is Mode.REPORT else "check"
    baseline_state: Mapping[str, object] = {
        "status": "not-requested" if mode is not Mode.RATCHET else "not-evaluated",
        "path": baseline_path if mode is Mode.RATCHET else None,
    }
    ratchet_state: Mapping[str, object] = {"status": "not-requested"}
    try:
        policy = _policy(policy_name)
        report, regressions, baseline_state, ratchet_state = _complete_analysis(
            root=root,
            manifest_path=manifest_path,
            baseline_path=baseline_path,
            policy=policy,
            mode=mode,
            as_of=as_of,
            github_repository=github_repository,
            require_github_evidence=require_github_evidence,
            enabled_rule_ids=enabled_rule_ids,
        )
    except ConfigurationError as error:
        report = _incomplete(PolicyId(policy_name), mode, str(error))
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
                root=root,
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
            root=root,
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
    github_repository: str | None,
    require_github_evidence: bool,
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
        )
    except ConfigurationError as error:
        if mode is Mode.RATCHET and "baseline" in str(error):
            raise BaselineError(str(error)) from error
        raise
    github_diagnostics, github_issues = _github_analysis(
        root=resolved_root,
        snapshot=snapshot,
        github_repository=github_repository,
        require_github_evidence=require_github_evidence,
    )
    report = analyze(
        snapshot.manifest,
        policy,
        mode=mode,
        as_of=_parse_date(as_of),
        additional_diagnostics=migration_diagnostics(snapshot) + github_diagnostics,
        enabled_rules=activated_rule_versions(enabled_rule_ids),
    )
    report = replace(
        report,
        input_provenance=snapshot.provenance,
        completion="incomplete" if github_issues else "complete",
        conclusion="inconclusive" if github_issues else report.conclusion,
        execution_issues=github_issues,
    )
    if mode is not Mode.RATCHET:
        return _CompletedAnalysis(
            report,
            (),
            {"status": "not-requested", "path": None},
            {"status": "not-requested"},
        )
    try:
        baseline = snapshot.baseline
        if baseline is None:
            message = "baseline is absent from the selected Git tree"
            raise BaselineError(message)
        regressions = check_baseline(report, baseline)
    except ConfigurationError as error:
        raise BaselineError(str(error)) from error
    stale_rule = RuleId("core/baseline/stale-entry")
    stale = tuple(item for item in regressions if item.rule_id == stale_rule)
    new_count = len(regressions) - len(stale)
    active_count = sum(
        item.severity == "error" and item.disposition == "active" for item in report.diagnostics
    )
    report = replace(
        report,
        diagnostics=tuple(sorted(report.diagnostics + stale, key=lambda item: item.fingerprint)),
        summary={
            **report.summary,
            "ratchet_regressions": len(regressions),
            "ratchet_new": new_count,
            "ratchet_stale": len(stale),
            "ratchet_known": max(active_count - new_count, 0),
        },
    )
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


def _github_analysis(
    *,
    root: Path,
    snapshot: RepositorySnapshot,
    github_repository: str | None,
    require_github_evidence: bool,
) -> _GitHubAnalysis:
    # Kept local to this CLI boundary: the core engine remains network-free.
    manifest = snapshot.manifest
    inspection = snapshot.inspection
    provenance = snapshot.provenance
    workflow_blobs = read_tracked_blob_contents(
        root,
        inspection.workflow_paths,
        identity=GitIdentity(provenance.source_revision, provenance.tree_digest),
    )
    workflows = tuple(
        GitHubWorkflowDocument(path=item.path, content=item.content) for item in workflow_blobs
    )
    collection_requested = github_repository is not None or require_github_evidence
    evidence = None
    if collection_requested:
        repository = resolve_github_repository(
            root,
            cli_repository=github_repository,
            manifest_repository=(manifest.delivery.repository if manifest.delivery else None),
        )
        if repository is not None:
            token = os.environ.get(  # ruff: ignore[banned-api] - approved credential source
                "SARJ_REPO_LINT_GITHUB_TOKEN"
            )
            evidence = _authenticated_github_client(token).collect(repository)
    effective_config = manifest.delivery
    if require_github_evidence and evidence is None and effective_config is None:
        effective_config = DeliveryConfig()
    github_report = analyze_github(
        effective_config,
        evidence,
        workflows,
        repository_files=tuple(item.path for item in inspection.tracked_files),
        selected_revision=provenance.source_revision if evidence is not None else None,
    )
    return _GitHubAnalysis(github_report.diagnostics, github_report.execution_issues)


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


def resolve_github_repository(
    root: Path,
    *,
    cli_repository: str | None,
    manifest_repository: str | None,
) -> str | None:
    if (
        cli_repository is not None
        and manifest_repository is not None
        and cli_repository.casefold() != manifest_repository.casefold()
    ):
        ConfigurationError.fail(
            "--github-repository must match delivery.repository when both are provided"
        )
    actions_repository = (
        os.environ.get(  # ruff: ignore[banned-api] - GitHub Actions repository context
            "GITHUB_REPOSITORY"
        )
        if os.environ.get(  # ruff: ignore[banned-api] - GitHub Actions trust signal
            "GITHUB_ACTIONS"
        )
        == "true"
        else None
    )
    candidate = (
        cli_repository
        or manifest_repository
        or actions_repository
        or _github_repository_from_origin(root)
    )
    if candidate is None:
        return None
    if not _GITHUB_SLUG.fullmatch(candidate) or candidate.endswith(("/.", "/..")):
        ConfigurationError.fail("GitHub repository must use a safe owner/name value")
    return candidate


def _github_repository_from_origin(  # ruff: ignore[too-many-return-statements] - reject unsafe forms explicitly
    root: Path,
) -> str | None:
    executable = shutil.which("git")
    if executable is None:
        return None
    environment = {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
    }
    try:
        result = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] - fixed Git metadata query
            [executable, "-C", str(root), "config", "--local", "--get", "remote.origin.url"],
            check=False,
            capture_output=True,
            env=environment,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0 or len(result.stdout) > _MAX_GIT_ORIGIN_BYTES:
        return None
    try:
        origin = result.stdout.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError:
        return None
    if (match := _GITHUB_SCP_ORIGIN.fullmatch(origin)) is not None:
        return _slug_from_origin_path(match.group("path"))
    parsed = urlsplit(origin)
    if _unsafe_github_origin(parsed):
        return None
    return _slug_from_origin_path(parsed.path)


def _unsafe_github_origin(parsed: SplitResult) -> bool:
    return (
        parsed.scheme not in {"https", "ssh"}
        or parsed.hostname != "github.com"
        or parsed.port is not None
        or bool(parsed.query)
        or bool(parsed.fragment)
        or parsed.password is not None
        or (parsed.scheme == "https" and parsed.username is not None)
        or (parsed.scheme == "ssh" and parsed.username != "git")
    )


def _slug_from_origin_path(path: str) -> str | None:
    candidate = path.removeprefix("/").removesuffix(".git")
    return candidate if _GITHUB_SLUG.fullmatch(candidate) else None


def _policy(name: str) -> Policy:
    return PolicyRegistry.from_installed().resolve(name)


def _incomplete(policy_id: PolicyId, mode: Mode, issue: str) -> AnalysisReport:
    return AnalysisReport(
        mode=mode,
        repository_id=RepositoryId("unknown"),
        policy_id=policy_id,
        policy_version=0,
        scope_digest="0" * 64,
        completion="incomplete",
        conclusion="inconclusive",
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
    root: Path,
    manifest_path: str,
    baseline: Mapping[str, object],
    ratchet: Mapping[str, object],
) -> str:
    if output_format is OutputFormat.TEXT:
        return render_text(report)
    payload = _report_payload(
        report,
        command=command,
        root=root,
        manifest_path=manifest_path,
        baseline=baseline,
        ratchet=ratchet,
    )
    if output_format is OutputFormat.PRETTY_JSON:
        return json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    return canonical_json(payload) + "\n"


def _report_payload(  # ruff: ignore[too-many-arguments] - stable report envelope inputs
    report: AnalysisReport,
    *,
    command: str,
    root: Path,
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
    try:
        identity = git_identity(root.resolve(strict=True))
    except (ConfigurationError, OSError):
        pass
    else:
        provenance["source_revision"] = identity.source_revision
        provenance["tree_digest"] = identity.tree_digest
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
    policy: Annotated[str, typer.Option()] = "sarj",
) -> None:
    """Explain one immutable rule."""
    try:
        selected_policy = _policy(policy)
        rules = {str(item.rule_id): item for item in _all_rules(selected_policy)}
    except ConfigurationError as error:
        _emit_command_error("explain", "policy.unavailable", str(error))
    rule = rules.get(rule_id)
    if rule is None:
        _emit_command_error(
            "explain",
            "rule.unknown",
            f"rule is not installed for policy {policy}: {rule_id}",
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
                "policy_api_version": POLICY_API_VERSION,
            },
        ),
        "rule": asdict(rule),
    }
    typer.echo(json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True))


@app.command("list-rules", hidden=True)
@app.command("rules")
def list_rules(
    policy: Annotated[str, typer.Option()] = "sarj",
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
        selected_policy = _policy(policy)
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
                "policy_api_version": POLICY_API_VERSION,
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
    """Print report, OpenAPI analysis, or catalog JSON Schema."""
    try:
        selected = SchemaDocument(document)
    except ValueError:
        _emit_command_error(
            "schema",
            "schema.unknown",
            f"unknown schema document: {document}",
            phase="request",
            remediation="Request `report`, `openapi-analysis`, or `catalog`.",
        )
    match selected:
        case SchemaDocument.CATALOG:
            payload = catalog_schema()
        case SchemaDocument.OPENAPI_ANALYSIS:
            payload = _openapi_report_schema()
        case SchemaDocument.REPORT:
            payload = _report_schema()
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))


def _openapi_report_schema() -> Mapping[str, object]:
    return openapi_report_schema()


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


def _string_key_mapping(value: object) -> Mapping[str, object]:
    if not _is_object_mapping(value):
        return {}
    return {key: item for key, item in value.items() if isinstance(key, str)}


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
    return core_rules() + policy.rules()
