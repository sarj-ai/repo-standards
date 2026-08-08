"""Read-only command-line interface for repository structural analysis."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, replace
from datetime import date
from pathlib import Path
from typing import NoReturn

from repo_lint_core.engine import analyze, check_baseline
from repo_lint_core.errors import ConfigurationError
from repo_lint_core.models import AnalysisReport, Mode, Rule
from repo_lint_core.parser import load_baseline, load_manifest
from repo_lint_core.render import output_schema, render_json, render_rules, render_text
from repo_lint_policy_sarj import SarjPolicy

POLICIES = {"sarj": SarjPolicy}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="repo-lint",
        description="Deterministic, read-only repository architecture linter.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)
    check = subcommands.add_parser("check", help="analyze one repository manifest")
    check.add_argument("root", nargs="?", default=".")
    check.add_argument("--manifest", default=".repo-lint/repository.toml")
    check.add_argument("--baseline", default=".repo-lint/baseline.json")
    check.add_argument("--policy", required=True, choices=sorted(POLICIES))
    check.add_argument("--mode", choices=("report", "ratchet", "strict"), default="report")
    check.add_argument("--format", choices=("json", "pretty-json", "text"), default="text")
    check.add_argument("--output")
    check.add_argument("--as-of", help="deterministic YYYY-MM-DD used for exception expiry")

    explain = subcommands.add_parser("explain", help="explain one immutable rule")
    explain.add_argument("rule_id")
    explain.add_argument("--policy", required=True, choices=sorted(POLICIES))

    rules = subcommands.add_parser("list-rules", help="list installed policy rules as JSON")
    rules.add_argument("--policy", required=True, choices=sorted(POLICIES))

    subcommands.add_parser("schema", help="print the report JSON Schema")
    return parser


def _contained(root: Path, relative: str) -> Path:
    candidate = root / relative
    current = root
    for part in Path(relative).parts:
        current /= part
        if current.is_symlink():
            raise ConfigurationError(f"input path contains a symlink: {relative}")
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as error:
        raise ConfigurationError(
            f"input path is missing or escapes repository root: {relative}"
        ) from error
    return resolved


def _policy(name: str) -> SarjPolicy:
    return POLICIES[name]()


def _incomplete(policy_id: str, mode: Mode, issue: str) -> AnalysisReport:
    return AnalysisReport(
        mode=mode,
        repository_id="unknown",
        policy_id=policy_id,
        policy_version=0,
        scope_digest="0" * 64,
        completion="incomplete",
        conclusion="inconclusive",
        execution_issues=(issue,),
        summary={"diagnostics": 0, "errors": 0, "warnings": 0},
    )


def _write(value: str, output: str | None) -> None:
    if output is None:
        sys.stdout.write(value)
        return
    destination = Path(output)
    destination.write_text(value, encoding="utf-8")


def _render(report: AnalysisReport, output_format: str) -> str:
    if output_format == "text":
        return render_text(report)
    return render_json(report, pretty=output_format == "pretty-json")


def _parse_date(value: str | None) -> date | None:
    if value is None:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError as error:
        raise ConfigurationError("--as-of must use YYYY-MM-DD") from error


def _run_check(arguments: argparse.Namespace) -> int:
    mode: Mode = arguments.mode
    policy = _policy(arguments.policy)
    output_format: str = arguments.format
    try:
        root = Path(arguments.root).resolve(strict=True)
        if not root.is_dir():
            raise ConfigurationError("repository root must be a directory")
        manifest = load_manifest(_contained(root, arguments.manifest))
        report = analyze(manifest, policy, mode=mode, as_of=_parse_date(arguments.as_of))
        regressions = ()
        if mode == "ratchet":
            baseline = load_baseline(_contained(root, arguments.baseline))
            regressions = check_baseline(report, baseline)
            stale = tuple(
                item for item in regressions if item.rule_id == "core/baseline/stale-entry"
            )
            if stale:
                report = replace(
                    report,
                    diagnostics=tuple(
                        sorted(report.diagnostics + stale, key=lambda item: item.fingerprint)
                    ),
                    summary={**report.summary, "ratchet_regressions": len(regressions)},
                )
        _write(_render(report, output_format), arguments.output)
    except ConfigurationError as error:
        report = _incomplete(arguments.policy, mode, str(error))
        _write(_render(report, output_format), arguments.output)
        return 2
    if mode == "report":
        return 0
    if mode == "strict":
        return int(
            any(
                item.severity == "error" and item.disposition == "active"
                for item in report.diagnostics
            )
        )
    return int(bool(regressions))


def _all_rules(policy: SarjPolicy) -> tuple[Rule, ...]:
    core_rules = (
        Rule(
            rule_id="core/layout/non-overlapping-root",
            version=1,
            severity="error",
            summary="Component ownership roots are disjoint.",
            rationale="Overlapping roots make ownership and affected analysis ambiguous.",
            bad_example="component B is nested beneath component A",
            good_example="components A and B have disjoint roots",
        ),
        Rule(
            rule_id="core/exception/expired",
            version=1,
            severity="error",
            summary="Policy exceptions are narrow and unexpired.",
            rationale="Expired exceptions cannot silently become permanent policy holes.",
            bad_example="expires_on is before the analysis date",
            good_example="fix the finding or renew it through review",
        ),
        Rule(
            rule_id="core/baseline/stale-entry",
            version=1,
            severity="error",
            summary="Resolved debt is removed from the exact baseline.",
            rationale="Shrink-only baselines must lock in improvements.",
            bad_example="baseline contains a fingerprint no longer emitted",
            good_example="delete the resolved fingerprint in the same change",
        ),
    )
    return core_rules + policy.rules()


def _run_explain(arguments: argparse.Namespace) -> int:
    rules = {item.rule_id: item for item in _all_rules(_policy(arguments.policy))}
    rule = rules.get(arguments.rule_id)
    if rule is None:
        sys.stderr.write(f"unknown rule: {arguments.rule_id}\n")
        return 2
    sys.stdout.write(json.dumps(asdict(rule), ensure_ascii=True, indent=2, sort_keys=True) + "\n")
    return 0


def main(argv: list[str] | None = None) -> NoReturn:
    """Run the command-line interface."""
    arguments = _parser().parse_args(argv)
    if arguments.command == "check":
        code = _run_check(arguments)
    elif arguments.command == "explain":
        code = _run_explain(arguments)
    elif arguments.command == "list-rules":
        sys.stdout.write(render_rules(_all_rules(_policy(arguments.policy))))
        code = 0
    else:
        sys.stdout.write(json.dumps(output_schema(), indent=2, sort_keys=True) + "\n")
        code = 0
    raise SystemExit(code)
