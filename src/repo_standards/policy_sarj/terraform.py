from __future__ import annotations

from collections import defaultdict
from pathlib import PurePosixPath
import re
from typing import TYPE_CHECKING

from repo_standards.core.canonical import ComponentIndex
from repo_standards.core.models import ComponentId, Diagnostic, Remediation, RuleId, SourceLocation


if TYPE_CHECKING:
    from repo_standards.core.models import RepositorySnapshot, RuleDefinition


MODULE_CLUSTER_RULE_ID = RuleId("repository/terraform/module-cluster")
MODULE_LAYOUT_RULE_ID = RuleId("repository/terraform/module-layout")
_MIN_CLUSTER_FILES = 3
_MIN_NAME_PARTS = 2
_MIN_TOKEN_LENGTH = 3
_CONVENTIONAL = frozenset(
    {
        "main",
        "variables",
        "outputs",
        "versions",
        "providers",
        "provider",
        "backend",
        "locals",
        "data",
        "resources",
        "moved",
        "imports",
        "override",
        "terraform",
        "module",
        "modules",
        "config",
        "configuration",
        "test",
        "tests",
        "example",
        "examples",
    }
)
_EXCLUDED = frozenset(
    {
        ".terraform",
        "vendor",
        "generated",
        "fixtures",
        "fixture",
        "testdata",
        "examples",
        "node_modules",
    }
)


def _modules(snapshot: RepositorySnapshot) -> dict[str, list[str]]:
    modules: dict[str, list[str]] = defaultdict(list)
    components = ComponentIndex(snapshot.manifest.components)
    for item in snapshot.inspection.tracked_files:
        path = PurePosixPath(item.path)
        component = components.nearest(item.path)
        if component is not None and component.kind in {"generated", "vendor"}:
            continue
        if path.name.endswith((".tf", ".tf.json")) and not any(
            part.casefold() in _EXCLUDED for part in path.parts[:-1]
        ):
            modules[path.parent.as_posix()].append(path.as_posix())
    return modules


def module_cluster_diagnostics(
    snapshot: RepositorySnapshot, *, rule: RuleDefinition
) -> tuple[Diagnostic, ...]:
    diagnostics: list[Diagnostic] = []
    for _directory, paths in sorted(_modules(snapshot).items()):
        covered: set[str] = set()
        for (direction, token), members in sorted(
            _clusters(paths).items(), key=lambda item: (-len(item[1]), item[0])
        ):
            if len(members) < _MIN_CLUSTER_FILES or members & covered:
                continue
            covered.update(members)
            names = ", ".join(PurePosixPath(path).name for path in sorted(members))
            diagnostics.append(
                _finding(
                    snapshot,
                    rule=rule,
                    path=min(members),
                    message=(
                        f"Terraform files share {direction} {token!r}: "
                        f"{names}. "
                        "Names suggest a module review; extraction still needs semantic evidence."
                    ),
                    remediation=Remediation(
                        validation=("Rerun both standards engines on the same selected Git tree.",),
                        summary="Review cohesion and coupling before extraction.",
                        steps=(
                            (
                                "Keep useful flat composition; extract only a cohesive capability "
                                "or meaningful duplication, with a small typed interface."
                            ),
                            (
                                "Use Code Standards semantic findings to assess dependencies; "
                                "filename similarity cannot establish resource cohesion."
                            ),
                            (
                                "For any resource/module address change, review state-preserving "
                                "migration, callers, provider mappings and fixture plans before "
                                "changing infrastructure."
                            ),
                        ),
                    ),
                )
            )
    return tuple(diagnostics)


def _clusters(paths: list[str]) -> dict[tuple[str, str], set[str]]:
    clusters: dict[tuple[str, str], set[str]] = defaultdict(set)
    for path in paths:
        stem = PurePosixPath(path).name.removesuffix(".json").removesuffix(".tf")
        parts = re.split(r"[-_]", stem)
        if len(parts) < _MIN_NAME_PARTS or stem in _CONVENTIONAL:
            continue
        for direction, token in (("prefix", parts[0]), ("suffix", parts[-1])):
            if token.casefold() not in _CONVENTIONAL and len(token) >= _MIN_TOKEN_LENGTH:
                clusters[direction, token].add(path)
    return clusters


def module_layout_diagnostics(
    snapshot: RepositorySnapshot, *, rule: RuleDefinition
) -> tuple[Diagnostic, ...]:
    modules = _modules(snapshot)
    declared = {
        component.path
        for component in snapshot.manifest.components
        if component.kind == "terraform-root"
    }
    return tuple(
        _finding(
            snapshot,
            rule=rule,
            path=min(paths),
            message=(
                f"Declaration-kind folder {directory!r} sits below a Terraform module. "
                "Terraform does not recursively load it into the parent; "
                "use a component module with its own variables.tf and outputs.tf, or retain "
                "a separately declared Terraform component."
            ),
            remediation=Remediation(
                validation=("Rerun both standards engines on the same selected Git tree.",),
                summary="Review module ownership and loading before reorganizing declarations.",
                steps=(
                    (
                        "Keep each declaration in its owning module; Code Standards checks "
                        "the block's canonical filename."
                    ),
                    (
                        "A separately invoked or externally consumed module must "
                        "be retained and declared as a Terraform component in the existing "
                        "repository manifest."
                    ),
                    (
                        "Do not create empty files or move tfvars. Preserve -var-file wiring, "
                        "automatic loading, relative paths, provider mappings, backends and "
                        "deployment entrypoints."
                    ),
                ),
            ),
        )
        for directory, paths in sorted(modules.items())
        if PurePosixPath(directory).name in {"variables", "outputs"}
        and PurePosixPath(directory).parent.as_posix() in modules
        and directory not in declared
    )


def _finding(
    snapshot: RepositorySnapshot,
    *,
    rule: RuleDefinition,
    path: str,
    message: str,
    remediation: Remediation,
) -> Diagnostic:
    component = ComponentIndex(snapshot.manifest.components).nearest(path)
    return Diagnostic(
        rule_id=rule.rule_id,
        rule_version=rule.version,
        severity=rule.severity,
        evidence_level="verified",
        component_id=component.component_id if component else ComponentId("repository"),
        subject_kind="tracked-terraform-topology",
        observed=path,
        expected=remediation.summary,
        message=message,
        path=path,
        manifest_anchor=f"tracked_files.{path}",
        location=SourceLocation(path, line=1),
        remediation=remediation,
    )
