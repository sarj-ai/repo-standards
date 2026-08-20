from __future__ import annotations

from datetime import timedelta
import importlib
from importlib.metadata import version
import json
from pathlib import Path
import re
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import] - fixed local Git fixture only
from urllib.error import URLError
from urllib.request import Request

from jsonschema import ValidationError as JSONSchemaValidationError
from jsonschema import validate
import pytest
from typer.testing import CliRunner

from repo_lint.cli import (
    app,
    gh_api_transport,
    resolve_github_repository,
)
from repo_lint.core import ConfigurationError
from repo_lint.github import RepositoryEvidence


runner = CliRunner()


def test_version_matches_installed_distribution() -> None:
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.stdout.strip() == version("repo-standards")


def test_gh_transport_preserves_api_contract_without_forwarding_authorization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[str] = []

    def fake_run(arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        del kwargs
        observed.extend(arguments)
        return subprocess.CompletedProcess(arguments, 0, stdout=b"{}", stderr=b"")

    def fake_which(name: str) -> str:
        return f"/usr/bin/{name}"

    monkeypatch.setattr(shutil, "which", fake_which)
    monkeypatch.setattr(subprocess, "run", fake_run)
    request = Request(
        "https://api.github.com/repos/acme/widgets",
        headers={"Authorization": "Bearer never-forward-this"},
    )

    status, body = gh_api_transport(request, timedelta(seconds=2))

    assert (status, body) == (200, b"{}")
    assert "Accept: application/vnd.github+json" in observed
    assert "X-GitHub-Api-Version: 2022-11-28" in observed
    assert not any("never-forward-this" in value for value in observed)


def test_gh_transport_normalizes_timeout_and_operational_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_which(name: str) -> str:
        return f"/usr/bin/{name}"

    monkeypatch.setattr(shutil, "which", fake_which)

    def timeout(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        del args, kwargs
        command = "gh"
        raise subprocess.TimeoutExpired(command, 2)

    monkeypatch.setattr(subprocess, "run", timeout)
    request = Request("https://api.github.com/repos/acme/widgets")
    with pytest.raises(TimeoutError, match="timed out"):
        gh_api_transport(request, timedelta(seconds=2))

    def failure(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        del args, kwargs
        return subprocess.CompletedProcess([], 1, stdout=b"", stderr=b"not authenticated: secret")

    monkeypatch.setattr(subprocess, "run", failure)
    with pytest.raises(URLError, match="could not complete") as captured:
        gh_api_transport(request, timedelta(seconds=2))
    assert "secret" not in str(captured.value)


def _git(repository: Path, *arguments: str) -> str:
    executable = shutil.which("git")
    assert executable is not None
    completed = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] - fixed local Git fixture only
        [executable, "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        timeout=10,
    )
    return completed.stdout.decode().strip()


def _commit_fixture(repository: Path) -> None:
    _git(repository, "init", "--quiet")
    _commit_changes(repository)


def _commit_changes(repository: Path) -> None:
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


def test_pull_request_size_command_returns_stable_json(tmp_path: Path) -> None:
    _git(tmp_path, "init", "--quiet")
    (tmp_path / ".gitattributes").write_text("generated/** pr-size-excluded\n", encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("value = 1\n", encoding="utf-8")
    _commit_changes(tmp_path)
    base = _git(tmp_path, "rev-parse", "HEAD")
    (tmp_path / "src" / "app.py").write_text("value = 2\nextra = 3\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_app.py").write_text("assert True\n" * 20, encoding="utf-8")
    _commit_changes(tmp_path)

    result = runner.invoke(
        app,
        [
            "pull-request",
            "size",
            str(tmp_path),
            "--base",
            base,
            "--head",
            "HEAD",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    payload = _json_object(result.stdout)
    assert payload["command"] == "pull-request size"
    assert _object(payload["summary"])["counted_lines"] == 3
    assert _object(payload["summary"])["excluded_lines"] == 20


def test_pull_request_size_errors_have_command_specific_remediation(tmp_path: Path) -> None:
    missing = runner.invoke(app, ["pull-request", "size", str(tmp_path), "--format", "json"])
    missing_issue = _object_list(_json_object(missing.stdout)["execution_issues"])[0]
    assert "trusted revision" in str(missing_issue["remediation"])

    _git(tmp_path, "init", "--quiet")
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    _commit_changes(tmp_path)
    invalid = runner.invoke(
        app,
        ["pull-request", "size", str(tmp_path), "--base", "missing", "--format", "json"],
    )
    invalid_issue = _object_list(_json_object(invalid.stdout)["execution_issues"])[0]
    assert "Fetch and verify" in str(invalid_issue["remediation"])


def _manifest(root: Path, text: str) -> None:
    policy_directory = root / ".repo-lint"
    policy_directory.mkdir()
    (policy_directory / "repository.toml").write_text(text, encoding="utf-8")
    _commit_fixture(root)


def _json_object(value: str) -> dict[str, object]:
    parsed: object = json.loads(value)  # pyright: ignore[reportAny]
    assert isinstance(parsed, dict)
    return {
        key: item
        for key, item in parsed.items()  # pyright: ignore[reportUnknownVariableType]
        if isinstance(key, str)
    }


def _object(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    return {
        key: item
        for key, item in value.items()  # pyright: ignore[reportUnknownVariableType]
        if isinstance(key, str)
    }


def _object_list(value: object) -> list[dict[str, object]]:
    assert isinstance(value, list)
    return [
        _object(item)  # pyright: ignore[reportUnknownArgumentType]
        for item in value  # pyright: ignore[reportUnknownVariableType]
    ]


GOOD_MANIFEST = """
schema_version = 2
repository_id = "example-repository"
policy = "sarj"
policy_version = 5

[[components]]
id = "alpha.agent"
kind = "application"
product = "alpha"
path = "applications/alpha/agent"
owner = "@example/alpha"
"""


def test_report_json_is_one_deterministic_value(tmp_path: Path) -> None:
    _manifest(tmp_path, GOOD_MANIFEST)
    first = runner.invoke(app, ["report", str(tmp_path), "--policy", "sarj", "--format", "json"])
    second = runner.invoke(app, ["report", str(tmp_path), "--policy", "sarj", "--format", "json"])
    assert first.exit_code == second.exit_code == 0
    assert first.stdout == second.stdout
    report = _json_object(first.stdout)
    assert report["conclusion"] == "passed"
    assert report["command"] == "report"
    assert _object(report["baseline"])["status"] == "not-requested"
    assert _object(report["ratchet"])["status"] == "not-requested"
    assert _object(report["tool"])["version"] != "0.1.0-dev"

    (tmp_path / ".repo-lint" / "repository.toml").write_text(
        GOOD_MANIFEST.replace("applications/alpha/agent", "python/agent"),
        encoding="utf-8",
    )
    dirty = runner.invoke(app, ["report", str(tmp_path), "--policy", "sarj", "--format", "json"])
    assert dirty.exit_code == 0
    assert dirty.stdout == first.stdout


def test_pending_report_findings_are_disabled(tmp_path: Path) -> None:
    _manifest(tmp_path, GOOD_MANIFEST.replace("applications/alpha/agent", "python/agent"))
    result = runner.invoke(app, ["report", str(tmp_path), "--policy", "sarj", "--format", "json"])
    report = _json_object(result.stdout)
    assert result.exit_code == 0
    assert report["conclusion"] == "passed"
    assert _object_list(report["diagnostics"]) == []


def test_unapproved_rule_cannot_be_explicitly_activated(tmp_path: Path) -> None:
    _manifest(tmp_path, GOOD_MANIFEST)
    result = runner.invoke(
        app,
        [
            "report",
            str(tmp_path),
            "--enable-rule",
            "architecture/dependencies/policy@1",
            "--format",
            "json",
        ],
    )

    report = _json_object(result.stdout)
    assert result.exit_code == 2
    assert report["conclusion"] == "inconclusive"
    assert "not approved for activation" in str(report)


def test_enable_rule_help_requires_an_exact_version() -> None:
    result = runner.invoke(app, ["check", "--help"], terminal_width=160)
    help_text = " ".join(re.sub(r"\x1b\[[0-9;]*m", "", result.stdout).split())

    assert result.exit_code == 0
    assert "--enable-rule" in help_text
    assert "rule-id@version" in help_text
    assert "selector" in help_text


def test_text_diagnostics_do_not_invent_source_coordinates(tmp_path: Path) -> None:
    _manifest(tmp_path, GOOD_MANIFEST.replace("applications/alpha/agent", "python/agent"))
    result = runner.invoke(app, ["report", str(tmp_path), "--policy", "sarj", "--format", "text"])
    assert result.exit_code == 0
    assert ":1:1:" not in result.stdout
    assert result.stdout == "repo-standards: passed; 0 errors, 0 warnings\n"


def test_pending_strict_errors_do_not_block(tmp_path: Path) -> None:
    _manifest(tmp_path, GOOD_MANIFEST.replace("applications/alpha/agent", "python/agent"))
    result = runner.invoke(
        app, ["check", str(tmp_path), "--policy", "sarj", "--mode", "strict", "--format", "json"]
    )
    assert result.exit_code == 0


def test_strict_operational_layout_guidance_is_nonblocking(tmp_path: Path) -> None:
    operational_manifest = GOOD_MANIFEST.replace(
        '''id = "alpha.agent"
kind = "application"
product = "alpha"
path = "applications/alpha/agent"''',
        '''id = "alpha.terraform"
kind = "terraform-root"
product = "alpha"
path = "iac/alpha"''',
    )
    _manifest(tmp_path, operational_manifest)
    result = runner.invoke(
        app, ["check", str(tmp_path), "--policy", "sarj", "--mode", "strict", "--format", "json"]
    )
    report = _json_object(result.stdout)
    assert result.exit_code == 0
    assert _object_list(report["diagnostics"]) == []


def test_malformed_manifest_is_incomplete(tmp_path: Path) -> None:
    _manifest(tmp_path, "schema_version = 2\nunknown = true\n")
    result = runner.invoke(app, ["report", str(tmp_path), "--policy", "sarj", "--format", "json"])
    report = _json_object(result.stdout)
    assert result.exit_code == 2
    assert report["completion"] == "incomplete"
    assert report["conclusion"] == "inconclusive"


def test_schema_is_machine_discoverable() -> None:
    result = runner.invoke(app, ["schema"])
    assert result.exit_code == 0
    schema = _json_object(result.stdout)
    properties = _object(schema["properties"])
    schema_version = _object(properties["schema_version"])
    assert schema_version["const"] == 2


def test_report_validates_against_published_schema(tmp_path: Path) -> None:
    _manifest(tmp_path, GOOD_MANIFEST)
    checked = runner.invoke(app, ["report", str(tmp_path), "--policy", "sarj", "--format", "json"])
    assert checked.exit_code == 0
    report = _json_object(checked.stdout)
    schema_result = runner.invoke(app, ["schema"])
    assert schema_result.exit_code == 0
    schema = _json_object(schema_result.stdout)
    validate(instance=report, schema=schema)


def test_report_schema_rejects_incoherent_outcome_state(tmp_path: Path) -> None:
    _manifest(tmp_path, GOOD_MANIFEST)
    checked = runner.invoke(app, ["report", str(tmp_path), "--policy", "sarj", "--format", "json"])
    assert checked.exit_code == 0
    report = _json_object(checked.stdout)
    report["completion"] = "complete"
    report["conclusion"] = "inconclusive"
    report["diagnostics"] = []
    report["execution_issues"] = []
    schema_result = runner.invoke(app, ["schema"])
    assert schema_result.exit_code == 0
    with pytest.raises(JSONSchemaValidationError):
        validate(instance=report, schema=_json_object(schema_result.stdout))


def test_incomplete_report_and_anchor_locations_validate_against_schema(tmp_path: Path) -> None:
    _manifest(tmp_path, "schema_version = 2\nunknown = true\n")
    incomplete = runner.invoke(
        app, ["report", str(tmp_path), "--policy", "sarj", "--format", "json"]
    )
    schema_result = runner.invoke(app, ["schema"])
    validate(instance=_json_object(incomplete.stdout), schema=_json_object(schema_result.stdout))

    policy_directory = tmp_path / ".repo-lint"
    (policy_directory / "repository.toml").write_text(
        GOOD_MANIFEST.replace("applications/alpha/agent", "python/agent"),
        encoding="utf-8",
    )
    _commit_changes(tmp_path)
    findings = runner.invoke(app, ["report", str(tmp_path), "--policy", "sarj", "--format", "json"])
    assert _object_list(_json_object(findings.stdout)["diagnostics"]) == []


def test_neutral_core_contains_no_sarj_policy_vocabulary() -> None:
    core = Path(__file__).parents[1] / "src" / "repo_lint" / "core"
    source = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(core.glob("*.py"))
    ).casefold()
    assert "sarj" not in source
    assert "foundation-service" not in source
    assert "product-library" not in source


def test_manifest_symlink_is_rejected(tmp_path: Path) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside.toml"
    outside.write_text(GOOD_MANIFEST, encoding="utf-8")
    policy_directory = tmp_path / ".repo-lint"
    policy_directory.mkdir()
    Path(policy_directory / "repository.toml").symlink_to(outside)
    _commit_fixture(tmp_path)
    result = runner.invoke(app, ["report", str(tmp_path), "--policy", "sarj", "--format", "json"])
    report = _json_object(result.stdout)
    assert result.exit_code == 2
    issues = _object_list(report["execution_issues"])
    assert issues[0]["code"] == "analysis.configuration"
    assert "symlink" in str(issues[0]["message"])


def test_repository_code_is_not_executed(tmp_path: Path) -> None:
    _manifest(tmp_path, GOOD_MANIFEST)
    marker = tmp_path / "must-not-exist"
    (tmp_path / "package.json").write_text(
        json.dumps({"scripts": {"postinstall": f"touch {marker}"}}), encoding="utf-8"
    )
    result = runner.invoke(app, ["report", str(tmp_path), "--policy", "sarj", "--format", "json"])
    assert result.exit_code == 0
    assert not marker.exists()


def test_inspect_bootstraps_without_a_repository_manifest() -> None:
    repository = Path(__file__).parents[1]
    result = runner.invoke(app, ["inspect", str(repository)])
    assert result.exit_code == 0
    inspection = _json_object(result.stdout)
    assert inspection["command"] == "inspect"
    assert inspection["completion"] == "complete"
    summary = _object(inspection["summary"])
    assert isinstance(summary["tracked_files"], int)
    assert summary["tracked_files"] > 0
    assert _object(inspection["page"])["limit"] == 100


def test_inspect_supports_bounded_filtered_pages() -> None:
    repository = Path(__file__).parents[1]
    result = runner.invoke(
        app,
        ["inspect", str(repository), "--kind", "project", "--limit", "1"],
    )
    assert result.exit_code == 0
    payload = _json_object(result.stdout)
    page = _object(payload["page"])
    returned = page["returned"]
    assert isinstance(returned, int)
    assert returned <= 1
    assert all(item["kind"] == "project" for item in _object_list(payload["items"]))


def test_github_audit_bootstraps_without_a_repository_manifest(tmp_path: Path) -> None:
    workflow = tmp_path / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "on: pull_request\npermissions: {}\njobs:\n  test:\n"
        "    timeout-minutes: 5\n    steps:\n      - uses: actions/checkout@v4\n",
        encoding="utf-8",
    )
    _commit_fixture(tmp_path)

    result = runner.invoke(app, ["github", str(tmp_path), "--format", "json"])
    report = _json_object(result.stdout)

    assert result.exit_code == 0
    assert report["command"] == "github"
    assert report["completion"] == "complete"
    assert _object_list(report["diagnostics"]) == []

    workflow.write_text(
        workflow.read_text(encoding="utf-8").replace(
            "actions/checkout@v4",
            "actions/checkout@0123456789abcdef0123456789abcdef01234567",
        ),
        encoding="utf-8",
    )
    dirty = runner.invoke(app, ["github", str(tmp_path), "--format", "json"])
    assert dirty.stdout == result.stdout


def test_invalid_page_is_a_structured_failure() -> None:
    result = runner.invoke(app, ["rules", "--limit", "501"])
    payload = _json_object(result.stdout)
    assert result.exit_code == 2
    assert payload["completion"] == "incomplete"
    issue = _object_list(payload["execution_issues"])[0]
    assert issue["code"] == "request.invalid"


def test_capabilities_are_machine_discoverable() -> None:
    result = runner.invoke(app, ["capabilities"])
    assert result.exit_code == 0
    capabilities = _json_object(result.stdout)
    assert capabilities["schema_version"] == 2
    safety = _object(capabilities["safety"])
    assert safety["repository_code_execution"] is False
    assert safety["mutation"] is False
    assert safety["network"] is True
    assert safety["network_default"] is False
    assert safety["network_mode"] == "opt-in-read-only-github-api"
    assert _object(capabilities["tool"])["version"]
    assert capabilities["execution_issues"] == []


def test_removed_github_rules_do_not_require_repository_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    _manifest(tmp_path, GOOD_MANIFEST)
    result = runner.invoke(
        app,
        [
            "report",
            str(tmp_path),
            "--format",
            "json",
            "--require-github-evidence",
        ],
    )
    report = _json_object(result.stdout)
    assert result.exit_code == 0
    assert report["completion"] == "complete"
    assert report["conclusion"] == "passed"
    assert report["execution_issues"] == []


def test_github_repository_override_uses_token_from_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed: dict[str, str | None] = {}

    class FakeGitHubClient:
        def __init__(self, token: str | None) -> None:
            observed["token"] = token

        def collect(  # ruff: ignore[no-self-use] - test double matches client instance API
            self, repository: str
        ) -> RepositoryEvidence:
            observed["repository"] = repository
            return RepositoryEvidence(
                repository=repository,
                default_branch="main",
                branches=(),
                rulesets=(),
                allow_auto_merge=False,
                actions_default_workflow_permissions="read",
                actions_can_approve_pull_requests=False,
            )

    cli_module = importlib.import_module("repo_lint.cli")
    monkeypatch.setattr(cli_module, "GitHubClient", FakeGitHubClient)
    monkeypatch.setenv("SARJ_REPO_LINT_GITHUB_TOKEN", "test-token")
    monkeypatch.setenv("GITHUB_REPOSITORY", "ignored/environment")
    _manifest(tmp_path, GOOD_MANIFEST)
    result = runner.invoke(
        app,
        [
            "report",
            str(tmp_path),
            "--format",
            "json",
            "--github-repository",
            "selected/repository",
        ],
    )
    assert result.exit_code == 0
    assert observed == {"token": "test-token", "repository": "selected/repository"}


def test_github_repository_resolution_priority_and_safe_origin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _manifest(tmp_path, GOOD_MANIFEST)
    _git(tmp_path, "remote", "add", "origin", "git@github.com:origin/repository.git")
    monkeypatch.setenv("GITHUB_REPOSITORY", "environment/repository")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    with pytest.raises(ConfigurationError, match="must match"):
        resolve_github_repository(
            tmp_path,
            cli_repository="override/repository",
            manifest_repository="manifest/repository",
        )
    assert (
        resolve_github_repository(
            tmp_path,
            cli_repository=None,
            manifest_repository="manifest/repository",
        )
        == "manifest/repository"
    )
    assert (
        resolve_github_repository(tmp_path, cli_repository=None, manifest_repository=None)
        == "environment/repository"
    )
    monkeypatch.delenv("GITHUB_REPOSITORY")
    monkeypatch.delenv("GITHUB_ACTIONS")
    assert (
        resolve_github_repository(tmp_path, cli_repository=None, manifest_repository=None)
        == "origin/repository"
    )

    _git(tmp_path, "remote", "set-url", "origin", "https://token@github.com/unsafe/repo.git")
    assert (
        resolve_github_repository(tmp_path, cli_repository=None, manifest_repository=None) is None
    )
    with pytest.raises(ConfigurationError, match="safe owner/name"):
        resolve_github_repository(
            tmp_path,
            cli_repository="https://github.com/unsafe/repo",
            manifest_repository=None,
        )


def test_workflow_analysis_reads_exact_committed_tree(tmp_path: Path) -> None:
    policy_directory = tmp_path / ".repo-lint"
    policy_directory.mkdir()
    (policy_directory / "repository.toml").write_text(GOOD_MANIFEST, encoding="utf-8")
    workflow = tmp_path / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "name: CI\non: [pull_request]\njobs:\n  test:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - uses: actions/checkout@v4\n",
        encoding="utf-8",
    )
    _commit_fixture(tmp_path)
    workflow.write_text(
        "name: CI\non: [pull_request]\npermissions: read-all\njobs:\n  test:\n"
        "    timeout-minutes: 10\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567\n",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["report", str(tmp_path), "--format", "json"])
    diagnostics = _object_list(_json_object(result.stdout)["diagnostics"])
    assert result.exit_code == 0
    assert diagnostics == []


def test_rules_are_filterable_and_paginated() -> None:
    result = runner.invoke(
        app,
        ["rules", "--rule-prefix", "architecture/", "--severity", "error", "--limit", "2"],
    )
    assert result.exit_code == 0
    payload = _json_object(result.stdout)
    rules = _object_list(payload["rules"])
    assert len(rules) == 2
    assert all(str(item["rule_id"]).startswith("architecture/") for item in rules)
    assert all(item["default_severity"] == "error" for item in rules)
    assert _object(payload["page"])["next_cursor"] == "2"


def test_ratchet_report_has_explicit_verified_baseline_status(tmp_path: Path) -> None:
    _manifest(tmp_path, GOOD_MANIFEST)
    initial = runner.invoke(app, ["report", str(tmp_path), "--format", "json"])
    report = _json_object(initial.stdout)
    policy = _object(report["policy"])
    baseline: dict[str, object] = {
        "schema_version": 2,
        "repository_id": report["repository_id"],
        "policy": policy["id"],
        "policy_version": policy["version"],
        "scope_digest": report["scope_digest"],
        "fingerprints": list[str](),
    }
    (tmp_path / ".repo-lint" / "baseline.json").write_text(json.dumps(baseline), encoding="utf-8")
    _commit_changes(tmp_path)
    checked = runner.invoke(
        app,
        ["check", str(tmp_path), "--mode", "ratchet", "--format", "json"],
    )
    payload = _json_object(checked.stdout)
    assert checked.exit_code == 0
    assert _object(payload["baseline"])["status"] == "verified"
    assert _object(payload["ratchet"])["status"] == "clean"

    (tmp_path / ".repo-lint" / "baseline.json").write_text("not-json", encoding="utf-8")
    dirty = runner.invoke(
        app,
        ["check", str(tmp_path), "--mode", "ratchet", "--format", "json"],
    )
    assert dirty.exit_code == 0
    assert _object(_json_object(dirty.stdout)["ratchet"])["status"] == "clean"


def test_ratchet_rejects_missing_baseline_explicitly(tmp_path: Path) -> None:
    _manifest(tmp_path, GOOD_MANIFEST)
    checked = runner.invoke(
        app,
        ["check", str(tmp_path), "--mode", "ratchet", "--format", "json"],
    )
    payload = _json_object(checked.stdout)
    assert checked.exit_code == 2
    assert _object(payload["baseline"])["status"] == "rejected"
    assert _object(payload["ratchet"])["status"] == "not-evaluated"


def test_unknown_policy_is_structured_incomplete(tmp_path: Path) -> None:
    _manifest(tmp_path, GOOD_MANIFEST)
    result = runner.invoke(
        app,
        ["report", str(tmp_path), "--policy", "missing", "--format", "json"],
    )
    assert result.exit_code == 2
    report = _json_object(result.stdout)
    assert report["completion"] == "incomplete"
    assert report["conclusion"] == "inconclusive"


@pytest.mark.parametrize(
    "arguments",
    [
        pytest.param(("rules",), id="rules"),
        pytest.param(("explain", "example/rule"), id="explain"),
    ],
)
def test_unknown_policy_is_structured_for_rule_commands(arguments: tuple[str, ...]) -> None:
    result = runner.invoke(app, [*arguments, "--policy", "missing"])
    assert result.exit_code == 2
    payload = _json_object(result.stdout)
    assert payload["completion"] == "incomplete"
    assert _object_list(payload["execution_issues"])


def test_unknown_rule_and_schema_are_structured() -> None:
    for arguments, code in (
        (("explain", "not/a-rule"), "rule.unknown"),
        (("schema", "missing"), "schema.unknown"),
    ):
        result = runner.invoke(app, list(arguments))
        payload = _json_object(result.stdout)
        assert result.exit_code == 2
        assert _object_list(payload["execution_issues"])[0]["code"] == code


def test_public_corpus_is_six_immutable_not_downloaded_sources() -> None:
    manifest_path = Path(__file__).parents[1] / "corpus" / "public-oss-v2.json"
    corpus = _json_object(manifest_path.read_text(encoding="utf-8"))
    sources = _object_list(corpus["sources"])
    assert len(sources) == 6
    assert len({item["profile"] for item in sources}) == 6
    assert all(len(str(item["commit"])) == 40 for item in sources)
    assert all(len(str(item["tree"])) == 40 for item in sources)
    assert all(_object(item["snapshot"])["status"] == "not-downloaded" for item in sources)


def test_rest_check_is_zero_config_and_reads_only_committed_bytes(tmp_path: Path) -> None:
    spec = tmp_path / "openapi.json"
    spec.write_text(
        json.dumps(
            {
                "openapi": "3.1.2",
                "info": {"title": "Example", "version": "1"},
                "paths": {"/items": {"get": {"responses": {"204": {}}}}},
            }
        ),
        encoding="utf-8",
    )
    _commit_fixture(tmp_path)
    first = runner.invoke(app, ["rest", "check", str(tmp_path)])
    assert first.exit_code == 0
    payload = _json_object(first.stdout)
    assert payload["application_code_executed"] is False
    assert payload["completion"] == "complete"
    assert _object(payload["summary"])["errors"] == 0

    spec.write_text(
        json.dumps(
            {
                "openapi": "3.1.2",
                "info": {"title": "Dirty", "version": "1"},
                "paths": {
                    "/items": {
                        "get": {
                            "responses": {
                                "204": {
                                    "content": {"application/json": {"schema": {"type": "object"}}}
                                }
                            }
                        }
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    repeated = runner.invoke(app, ["rest", "check", str(tmp_path)])
    assert repeated.exit_code == 0
    assert repeated.stdout == first.stdout

    schema_result = runner.invoke(app, ["schema", "openapi-analysis"])
    assert schema_result.exit_code == 0
    validate(instance=payload, schema=_json_object(schema_result.stdout))


def test_pending_rest_rule_does_not_block(tmp_path: Path) -> None:
    (tmp_path / "openapi.json").write_text(
        json.dumps(
            {
                "openapi": "3.1.2",
                "info": {"title": "Example", "version": "1"},
                "paths": {
                    "/items": {
                        "get": {
                            "responses": {
                                "204": {
                                    "content": {"application/json": {"schema": {"type": "object"}}}
                                }
                            }
                        }
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    _commit_fixture(tmp_path)
    strict = runner.invoke(app, ["rest", "check", str(tmp_path)])
    report = runner.invoke(app, ["rest", "check", str(tmp_path), "--enforcement", "report"])
    assert strict.exit_code == 0
    assert report.exit_code == 0
    assert _object_list(_json_object(strict.stdout)["diagnostics"]) == []


def test_rest_check_reads_only_exact_local_reference_closure(tmp_path: Path) -> None:
    api = tmp_path / "api"
    api.mkdir()
    (api / "openapi.json").write_text(
        json.dumps(
            {
                "openapi": "3.1.2",
                "info": {"title": "Example", "version": "1"},
                "paths": {
                    "/items": {
                        "get": {
                            "responses": {
                                "200": {
                                    "description": "ok",
                                    "content": {
                                        "application/json": {
                                            "schema": {"$ref": "../schemas.json#/$defs/Item"}
                                        }
                                    },
                                }
                            }
                        }
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "schemas.json").write_text(
        json.dumps({"$defs": {"Item": {"type": "object"}}}), encoding="utf-8"
    )
    (api / "unrelated.json").write_text("not-json", encoding="utf-8")
    _commit_fixture(tmp_path)
    checked = runner.invoke(app, ["rest", "check", str(tmp_path)])
    assert checked.exit_code == 0
    assert _json_object(checked.stdout)["completion"] == "complete"


def test_rest_discover_requires_explicit_selection_when_ambiguous(tmp_path: Path) -> None:
    for directory in (tmp_path / "a", tmp_path / "b"):
        directory.mkdir()
        (directory / "openapi.json").write_text(
            '{"openapi":"3.1.2","info":{"title":"x","version":"1"},"paths":{}}',
            encoding="utf-8",
        )
    _commit_fixture(tmp_path)
    discovered = runner.invoke(app, ["rest", "discover", str(tmp_path)])
    checked = runner.invoke(app, ["rest", "check", str(tmp_path)])
    assert discovered.exit_code == 0
    assert len(_object_list(_json_object(discovered.stdout)["candidates"])) == 2
    assert checked.exit_code == 2
    incomplete = _json_object(checked.stdout)
    assert incomplete["completion"] == "incomplete"
    schema = _json_object(runner.invoke(app, ["schema", "openapi-analysis"]).stdout)
    validate(instance=incomplete, schema=schema)


def test_rest_catalog_and_capability_handshake_are_offline() -> None:
    rules_result = runner.invoke(app, ["rest", "rules"])
    explanation = runner.invoke(app, ["rest", "explain", "api/http/message-semantics"])
    assert rules_result.exit_code == explanation.exit_code == 0
    assert len(_object_list(_json_object(rules_result.stdout)["rules"])) == 4
    assert _object(_json_object(explanation.stdout)["rule"])["detects"]
