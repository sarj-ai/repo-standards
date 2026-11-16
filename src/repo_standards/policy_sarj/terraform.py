from __future__ import annotations

from typing import TYPE_CHECKING

from sarj_iac_lint.module_outputs import unused_module_outputs

from repo_standards.core.canonical import ComponentIndex
from repo_standards.core.errors import ConfigurationError
from repo_standards.core.models import ComponentId, Diagnostic, Remediation, RuleId, SourceLocation


if TYPE_CHECKING:
    from repo_standards.core.models import RepositorySnapshot, RuleDefinition


UNUSED_MODULE_OUTPUTS_RULE_ID = RuleId("repository/terraform/unused-module-outputs")


def terraform_output_diagnostics(
    snapshot: RepositorySnapshot, *, rule: RuleDefinition
) -> tuple[Diagnostic, ...]:
    tracked = frozenset(item.path for item in snapshot.inspection.tracked_files)
    expected = {path for path in tracked if path.endswith((".tf", ".tf.json"))}
    if snapshot.terraform_sources is None:
        if expected or snapshot.manifest.terraform_output_contracts:
            ConfigurationError.fail(
                "Terraform consumer analysis requires complete selected Git source evidence"
            )
        return ()
    sources = {source.path: source.content for source in snapshot.terraform_sources}
    if set(sources) != expected or len(sources) != len(snapshot.terraform_sources):
        ConfigurationError.fail(
            "Terraform consumer analysis requires the complete selected Git tree"
        )
    contracts = snapshot.manifest.terraform_output_contracts
    for contract in contracts:
        if contract.evidence not in tracked:
            ConfigurationError.fail(f"external output evidence is not tracked: {contract.evidence}")
    try:
        unused = unused_module_outputs(
            sources, external_outputs=tuple((item.module, item.output) for item in contracts)
        )
    except (TypeError, ValueError, RecursionError) as error:
        message = f"Terraform consumer analysis is incomplete: {error}"
        raise ConfigurationError(message) from error
    components = ComponentIndex(snapshot.manifest.components)
    diagnostics: list[Diagnostic] = []
    for output in unused:
        component = components.nearest(output.path)
        diagnostics.append(
            Diagnostic(
                rule_id=rule.rule_id,
                rule_version=rule.version,
                severity=rule.severity,
                evidence_level="verified",
                component_id=component.component_id if component else ComponentId("repository"),
                subject_kind="terraform-module-output",
                observed=output.name,
                expected="a reachable value consumer or an exact documented external contract",
                message=(
                    f"Module output {output.name!r} has no reachable consumer "
                    "in the selected Git tree."
                ),
                path=output.path,
                manifest_anchor=f"terraform.outputs.{output.path}.{output.name}",
                location=SourceLocation(output.path, line=output.line),
                baselineable=False,
                remediation=Remediation(
                    summary="Remove the unused export after reviewing its external contract.",
                    steps=(
                        "Review root re-exports, remote state, scripts, CI and external users.",
                        (
                            "Preserve uncertain contracts with an exact terraform.external_outputs "
                            "record and tracked evidence."
                        ),
                        "Remove the unused export; keep its resource and justified dependencies.",
                        "Do not add visualization references or fabricated consumers.",
                    ),
                    validation=(
                        "Rerun the normal repository check on the same HEAD or staged index.",
                    ),
                ),
            )
        )
    return tuple(diagnostics)
