"""Read-only command-line interface for repository structural analysis."""

from __future__ import annotations

from dataclasses import asdict, replace
from datetime import date
from enum import StrEnum
import json
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, NoReturn

from repo_lint_core.canonical import canonical_json
from repo_lint_core.engine import analyze, check_baseline
from repo_lint_core.errors import ConfigurationError
from repo_lint_core.inspection import RepositoryInspection, git_identity, inspect_repository
from repo_lint_core.models import (
    AnalysisReport,
    Diagnostic,
    ExecutionIssue,
    Mode,
    Policy,
    PolicyId,
    RepositoryId,
    Rule,
    RuleId,
)
from repo_lint_core.parser import load_baseline, load_manifest
from repo_lint_core.registry import POLICY_API_VERSION, PolicyRegistry
from repo_lint_core.render import output_schema, render_json, render_rules, render_text
import typer


if TYPE_CHECKING:
    from collections.abc import Mapping

app = typer.Typer(
    name="repo-lint",
    help="Deterministic, read-only repository architecture linter.",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
)


class OutputFormat(StrEnum):
    """Stable report renderers."""

    JSON = "json"
    PRETTY_JSON = "pretty-json"
    TEXT = "text"


def main() -> None:
    """Run the command-line application."""
    app()


@app.command("capabilities")
def capabilities_command() -> None:
    """Describe the stable machine capabilities without inspecting a repository."""
    registry = PolicyRegistry.from_installed()
    payload = {
        "schema_version": 1,
        "tool": {"name": "repo-lint", "version": "0.1.0"},
        "commands": ["capabilities", "check", "explain", "inspect", "report", "rules", "schema"],
        "formats": ["json", "pretty-json", "text"],
        "modes": ["report", "ratchet", "strict"],
        "exit_codes": {"0": "satisfied", "1": "policy-findings", "2": "incomplete"},
        "policy_api_version": POLICY_API_VERSION,
        "policies": [
            {"id": policy.policy_id, "version": policy.policy_version}
            for policy in registry.policies
        ],
        "safety": {
            "network": False,
            "repository_code_execution": False,
            "mutation": False,
            "autofix": False,
            "inspection_input": "exact-git-head-tree",
        },
        "schemas": {"report": 1},
    }
    typer.echo(canonical_json(payload))


@app.command("inspect")
def inspect_command(
    root: Annotated[Path, typer.Argument()] = Path(),
) -> None:
    """Inventory tracked inert repository metadata without requiring a manifest."""
    identity = None
    try:
        resolved = root.resolve(strict=True)
        identity = git_identity(resolved)
        inspection = inspect_repository(resolved, identity=identity)
    except (ConfigurationError, OSError) as error:
        typer.echo(
            json.dumps(
                {
                    "schema_version": 1,
                    "command": "inspect",
                    "completion": "incomplete",
                    "conclusion": "inconclusive",
                    "input": {
                        "source_revision": identity.source_revision if identity else None,
                        "tree_digest": identity.tree_digest if identity else None,
                        "mode": "git-tree",
                    },
                    "issues": [_issue_payload("inspection.incomplete", str(error))],
                },
                ensure_ascii=True,
                sort_keys=True,
            )
        )
        raise typer.Exit(2) from None
    payload = _inspection_payload(inspection)
    rendered = canonical_json(payload) + "\n"
    typer.echo(rendered, nl=False)
    if inspection.completion != "complete":
        raise typer.Exit(2)


def _inspection_payload(inspection: RepositoryInspection) -> Mapping[str, object]:
    return {
        "schema_version": 1,
        "command": "inspect",
        "completion": inspection.completion,
        "conclusion": "passed" if inspection.completion == "complete" else "inconclusive",
        "input": {
            "source_revision": inspection.source_revision,
            "tree_digest": inspection.tree_digest,
            "mode": "git-tree",
        },
        "summary": {
            "tracked_files": inspection.tracked_file_count,
            "projects": len(inspection.projects),
            "workflows": len(inspection.workflow_paths),
            "cloudbuild_files": len(inspection.cloudbuild_paths),
            "dockerfiles": len(inspection.dockerfile_paths),
            "terraform_roots": len(inspection.terraform_roots),
        },
        "projects": [
            {
                "ecosystem": item.ecosystem,
                "path": item.path,
                "name": item.name,
                "private": item.private,
                "workspace_root": item.workspace_root,
            }
            for item in inspection.projects
        ],
        "workflow_paths": list(inspection.workflow_paths),
        "cloudbuild_paths": list(inspection.cloudbuild_paths),
        "dockerfile_paths": list(inspection.dockerfile_paths),
        "terraform_roots": list(inspection.terraform_roots),
        "issues": [_issue_payload("metadata.invalid", message) for message in inspection.issues],
    }


def _issue_payload(code: str, message: str) -> Mapping[str, object]:
    return {
        "code": code,
        "phase": "inspection",
        "message": message,
        "retryable": False,
        "remediation": ["Inspect the reported Git object and correct or classify it explicitly."],
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
        )
    )


@app.command("report")
def report_command(
    root: Annotated[Path, typer.Argument()] = Path(),
    manifest: Annotated[str, typer.Option()] = ".repo-lint/repository.toml",
    policy: Annotated[str, typer.Option()] = "sarj",
    output_format: Annotated[OutputFormat, typer.Option("--format")] = OutputFormat.TEXT,
    as_of: Annotated[str | None, typer.Option(help="Deterministic YYYY-MM-DD")] = None,
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
) -> int:
    try:
        policy = _policy(policy_name)
        report, regressions = _complete_analysis(
            root=root,
            manifest_path=manifest_path,
            baseline_path=baseline_path,
            policy=policy,
            mode=mode,
            as_of=as_of,
        )
    except ConfigurationError as error:
        report = _incomplete(PolicyId(policy_name), mode, str(error))
        typer.echo(_render(report, output_format), nl=False)
        return 2
    typer.echo(_render(report, output_format), nl=False)
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
) -> tuple[AnalysisReport, tuple[Diagnostic, ...]]:
    resolved_root = _repository_root(root)
    manifest = load_manifest(_contained(resolved_root, manifest_path))
    report = analyze(manifest, policy, mode=mode, as_of=_parse_date(as_of))
    if mode is not Mode.RATCHET:
        return report, ()
    baseline = load_baseline(_contained(resolved_root, baseline_path))
    regressions = check_baseline(report, baseline)
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
    return report, regressions


def _repository_root(root: Path) -> Path:
    try:
        resolved = root.resolve(strict=True)
    except OSError:
        ConfigurationError.fail(f"repository root is unavailable: {root}")
    if not resolved.is_dir():
        ConfigurationError.fail("repository root must be a directory")
    return resolved


def _contained(root: Path, relative: str) -> Path:
    candidate = root / relative
    current = root
    for part in Path(relative).parts:
        current /= part
        if current.is_symlink():
            ConfigurationError.fail(f"input path contains a symlink: {relative}")
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError):
        ConfigurationError.fail(f"input path is missing or escapes repository root: {relative}")
    return resolved


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


def _render(report: AnalysisReport, output_format: OutputFormat) -> str:
    if output_format is OutputFormat.TEXT:
        return render_text(report)
    return render_json(report, pretty=output_format is OutputFormat.PRETTY_JSON)


@app.command("explain")
def explain_rule(
    rule_id: Annotated[str, typer.Argument()],
    policy: Annotated[str, typer.Option()] = "sarj",
) -> None:
    """Explain one immutable rule."""
    try:
        rules = {str(item.rule_id): item for item in _all_rules(_policy(policy))}
    except ConfigurationError as error:
        _emit_command_error("explain", str(error))
    rule = rules.get(rule_id)
    if rule is None:
        typer.echo(f"unknown rule: {rule_id}", err=True)
        raise typer.Exit(2)
    typer.echo(json.dumps(asdict(rule), ensure_ascii=True, indent=2, sort_keys=True))


@app.command("list-rules", hidden=True)
@app.command("rules")
def list_rules(
    policy: Annotated[str, typer.Option()] = "sarj",
) -> None:
    """List installed policy rules as JSON."""
    try:
        rendered = render_rules(_all_rules(_policy(policy)))
    except ConfigurationError as error:
        _emit_command_error("rules", str(error))
    typer.echo(rendered, nl=False)


def _emit_command_error(command: str, message: str) -> NoReturn:
    typer.echo(
        canonical_json(
            {
                "schema_version": 1,
                "command": command,
                "completion": "incomplete",
                "conclusion": "inconclusive",
                "issues": [_issue_payload("policy.unavailable", message)],
            }
        )
    )
    raise typer.Exit(2)


@app.command("schema")
def print_schema(
    document: Annotated[str, typer.Argument()] = "report",
) -> None:
    """Print the report JSON Schema."""
    if document != "report":
        typer.echo(f"unknown schema document: {document}; available: report", err=True)
        raise typer.Exit(2)
    typer.echo(json.dumps(output_schema(), indent=2, sort_keys=True))


def _all_rules(policy: Policy) -> tuple[Rule, ...]:
    core_rules = (
        Rule(
            rule_id=RuleId("core/layout/non-overlapping-root"),
            version=1,
            severity="error",
            summary="Component ownership roots are disjoint.",
            rationale="Overlapping roots make ownership and affected analysis ambiguous.",
            bad_example="component B is nested beneath component A",
            good_example="components A and B have disjoint roots",
        ),
        Rule(
            rule_id=RuleId("core/exception/expired"),
            version=1,
            severity="error",
            summary="Policy exceptions are narrow and unexpired.",
            rationale="Expired exceptions cannot silently become permanent policy holes.",
            bad_example="expires_on is before the analysis date",
            good_example="fix the finding or renew it through review",
        ),
        Rule(
            rule_id=RuleId("core/baseline/stale-entry"),
            version=1,
            severity="error",
            summary="Resolved debt is removed from the exact baseline.",
            rationale="Shrink-only baselines must lock in improvements.",
            bad_example="baseline contains a fingerprint no longer emitted",
            good_example="delete the resolved fingerprint in the same change",
        ),
    )
    return core_rules + policy.rules()
