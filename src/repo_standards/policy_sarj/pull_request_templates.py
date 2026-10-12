from __future__ import annotations

from typing import TYPE_CHECKING

from repo_standards.core.models import ComponentId, Diagnostic, Remediation, RuleId
from repo_standards.core.pull_request_body import missing_template_sections


if TYPE_CHECKING:
    from repo_standards.core.models import RepositorySnapshot, RuleDefinition


PULL_REQUEST_TEMPLATE_SECTIONS_RULE_ID = RuleId(
    "repository/documentation/pull-request-template-sections"
)
_DEFAULT_TEMPLATE_PATH = ".github/pull_request_template.md"
_VALIDATION = ("Run repo-standards again. It should report no findings.",)


def pull_request_template_diagnostics(
    snapshot: RepositorySnapshot, *, rule: RuleDefinition
) -> tuple[Diagnostic, ...]:
    pull_request = snapshot.manifest.pull_request
    if pull_request is None or pull_request.review_policy is None:
        return ()
    required = pull_request.review_policy.required_body_sections
    if not snapshot.pull_request_templates:
        return (_absent_template_diagnostic(required, rule=rule),)
    return tuple(
        _missing_section_diagnostic(template.path, section, rule=rule)
        for template in snapshot.pull_request_templates
        for section in missing_template_sections(template.content, required)
    )


def _absent_template_diagnostic(required: tuple[str, ...], *, rule: RuleDefinition) -> Diagnostic:
    return Diagnostic(
        rule_id=rule.rule_id,
        rule_version=rule.version,
        severity=rule.severity,
        evidence_level="verified",
        component_id=ComponentId("repository"),
        subject_kind="pull-request-template",
        observed="no pull-request template",
        expected=_DEFAULT_TEMPLATE_PATH,
        message="there is no PR template",
        path=_DEFAULT_TEMPLATE_PATH,
        manifest_anchor="pull_request.review_policy.required_body_sections",
        remediation=Remediation(
            summary="Add a PR template.",
            steps=(
                f"Create {_DEFAULT_TEMPLATE_PATH}.",
                "Add these headings to it: " + ", ".join(required) + ".",
            ),
            validation=_VALIDATION,
        ),
    )


def _missing_section_diagnostic(path: str, section: str, *, rule: RuleDefinition) -> Diagnostic:
    return Diagnostic(
        rule_id=rule.rule_id,
        rule_version=rule.version,
        severity=rule.severity,
        evidence_level="verified",
        component_id=ComponentId("repository"),
        subject_kind="pull-request-template-section",
        observed="heading absent",
        expected=section,
        message=f"the PR template has no '{section}' heading",
        path=path,
        manifest_anchor=f"tracked_files.{path}.sections.{section}",
        remediation=Remediation(
            summary="Add the missing heading to the PR template.",
            steps=(
                f"Add '## {section}' to {path}.",
                "Do not put it inside a comment or a code block.",
                "If the section is no longer needed, remove it from required_body_sections.",
            ),
            validation=_VALIDATION,
        ),
    )
