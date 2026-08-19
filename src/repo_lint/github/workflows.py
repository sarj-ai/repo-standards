# PyYAML intentionally has no complete type surface; all returned values are recursively
# bounded and type-checked below before they enter the public evidence model.
# pyright: reportAny=false, reportUnknownArgumentType=false, reportUnknownMemberType=false, reportUnknownVariableType=false

from __future__ import annotations

from pathlib import PurePosixPath
import re
from typing import TYPE_CHECKING, NamedTuple, NoReturn

import yaml
from yaml.tokens import AliasToken, AnchorToken

from .models import (
    ActionReference,
    WorkflowDocument,
    WorkflowInspection,
    WorkflowJobInspection,
    WorkflowStepInspection,
)


if TYPE_CHECKING:
    from yaml.nodes import MappingNode


_MAX_WORKFLOW_BYTES = 1024 * 1024
_MAX_NODES = 20_000
_MAX_DEPTH = 50
_WORKFLOW_PATH_PARTS = 3
_FULL_SHA = re.compile(r"[0-9a-fA-F]{40}")
_OCI_DIGEST = re.compile(r"sha256:[0-9a-fA-F]{64}")
_SECRET = re.compile(r"\$\{\{\s*secrets\.([A-Za-z_][A-Za-z0-9_]*)\s*}}")


class WorkflowTriggers(NamedTuple):
    names: frozenset[str]
    push_branches: tuple[str, ...]
    push_uses_branches_ignore: bool


class UsesLocation(NamedTuple):
    line: int
    next_start: int


class WorkflowInputError(ValueError):
    @classmethod
    def fail(cls, message: str) -> NoReturn:
        raise cls(message)


class _WorkflowLoader(yaml.SafeLoader):
    """A duplicate-key-rejecting YAML 1.2-ish safe loader."""


# PyYAML defaults to YAML 1.1 and otherwise turns GitHub's `on` key into True.
_WorkflowLoader.yaml_implicit_resolvers = {
    key: [entry for entry in entries if entry[0] != "tag:yaml.org,2002:bool"]
    for key, entries in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
_WorkflowLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|false)$", re.IGNORECASE),
    list("tTfF"),
)


def _construct_unique_mapping(
    loader: _WorkflowLoader, node: MappingNode, *, deep: bool = False
) -> dict[object, object]:
    output: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in output
        except TypeError:
            WorkflowInputError.fail("workflow mapping contains an unhashable key")
        if duplicate:
            WorkflowInputError.fail(f"workflow mapping contains duplicate key {key!r}")
        output[key] = loader.construct_object(value_node, deep=deep)
    return output


_WorkflowLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def inspect_workflow(  # ruff: ignore[too-many-locals] - one bounded parse pass assembles facts
    document: WorkflowDocument,
) -> WorkflowInspection:
    _validate_path(document.path)
    if len(document.content) > _MAX_WORKFLOW_BYTES:
        WorkflowInputError.fail("workflow exceeds the 1 MiB inspection limit")
    try:
        decoded = document.content.decode("utf-8")
        valid_utf8 = True
    except UnicodeDecodeError:
        # Replacement decoding lets us report any safely recoverable structural facts too.
        decoded = document.content.decode("utf-8", errors="replace")
        valid_utf8 = False
    root = _load_workflow(decoded)
    triggers = _parse_triggers(root.get("on"))
    jobs = _parse_jobs(root.get("jobs"))
    references = _action_references(jobs, decoded)
    scripts = "\n".join(
        _strip_shell_comments(step.run)
        for job in jobs
        for step in job.steps
        if step.run is not None
    )
    evidence_values = "\n".join(
        value
        for job in jobs
        for step in job.steps
        for _, value in (*job.environment, *step.environment, *step.inputs)
    )
    lowered = scripts.lower()
    concurrency = root.get("concurrency")
    has_concurrency = isinstance(concurrency, (str, dict))
    cancel = _cancel_in_progress(concurrency)
    root_declares_permissions = "permissions" in root
    root_permissions_safe = _permissions_are_explicit_and_bounded(root.get("permissions"))
    has_permissions = (
        (root_declares_permissions and root_permissions_safe)
        or all(job.has_permissions for job in jobs)
    ) and all(job.permissions_safe for job in jobs)
    has_timeout = bool(jobs) and all(job.has_timeout for job in jobs)
    return WorkflowInspection(
        path=document.path,
        valid_utf8=valid_utf8,
        action_references=references,
        has_permissions=has_permissions,
        has_timeout=has_timeout,
        has_concurrency=has_concurrency,
        cancels_in_progress=cancel,
        has_pull_request_trigger="pull_request" in triggers.names,
        has_merge_group_trigger="merge_group" in triggers.names,
        has_push_trigger="push" in triggers.names,
        has_schedule_trigger="schedule" in triggers.names,
        has_workflow_dispatch_trigger="workflow_dispatch" in triggers.names,
        creates_pull_request=_creates_pull_request(jobs),
        enables_auto_merge=re.search(r"\bgh\s+pr\s+merge\b[^\n]*\s--auto\b", lowered) is not None
        or "enablepullrequestautomerge" in lowered.replace("_", ""),
        uses_non_default_token=_uses_non_default_token(evidence_values),
        pins_source_sha=_has_any(
            lowered,
            "github.event.after",
            "github.event.workflow_run.head_sha",
            "github.sha",
            "source_sha",
        ),
        guards_stale_head=_has_any(lowered, "ls-remote", "head.sha", "head_sha", "headrefoid"),
        refuses_conflicts=(
            _has_any(lowered, "merge-tree", "merge --no-commit", '"conflicting"')
            and _has_any(lowered, "exit 1", "exit 2")
        ),
        text=decoded,
        push_branches=triggers.push_branches,
        push_uses_branches_ignore=triggers.push_uses_branches_ignore,
        jobs=jobs,
    )


def inspect_workflows(documents: tuple[WorkflowDocument, ...]) -> tuple[WorkflowInspection, ...]:
    paths = [document.path for document in documents]
    if len(paths) != len(set(paths)):
        WorkflowInputError.fail("workflow paths must be unique")
    return tuple(inspect_workflow(document) for document in sorted(documents, key=lambda d: d.path))


def _load_workflow(text: str) -> dict[str, object]:
    try:
        value = _load_yaml(text)
    except WorkflowInputError:
        raise
    except yaml.YAMLError as error:
        WorkflowInputError.fail(f"workflow is invalid YAML: {error}")
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        WorkflowInputError.fail("workflow root must be a mapping with string keys")
    _validate_safe_tree(value, depth=0, count=[0])
    return value


def _load_yaml(text: str) -> object:
    tokens = yaml.scan(text, Loader=_WorkflowLoader)
    for token in tokens:
        if isinstance(token, (AliasToken, AnchorToken)):
            WorkflowInputError.fail("workflow YAML anchors and aliases are not supported")
    loader = _WorkflowLoader(text)
    try:
        return loader.get_single_data()
    finally:
        loader.dispose()


def _validate_safe_tree(value: object, *, depth: int, count: list[int]) -> None:
    count[0] += 1
    if count[0] > _MAX_NODES or depth > _MAX_DEPTH:
        WorkflowInputError.fail("workflow structure exceeds inspection complexity limits")
    if value is None or isinstance(value, (str, bool, int, float)):
        return
    if isinstance(value, list):
        for item in value:
            _validate_safe_tree(item, depth=depth + 1, count=count)
        return
    if isinstance(value, dict) and all(isinstance(key, str) for key in value):
        for item in value.values():
            _validate_safe_tree(item, depth=depth + 1, count=count)
        return
    WorkflowInputError.fail("workflow contains an unsupported YAML value")


def _parse_triggers(value: object) -> WorkflowTriggers:
    if isinstance(value, str):
        return WorkflowTriggers(
            names=frozenset((value,)),
            push_branches=(),
            push_uses_branches_ignore=False,
        )
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return WorkflowTriggers(
            names=frozenset(value),
            push_branches=(),
            push_uses_branches_ignore=False,
        )
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        WorkflowInputError.fail("workflow 'on' must be a string, string list, or mapping")
    push = value.get("push")
    branches: tuple[str, ...] = ()
    if isinstance(push, dict) and "branches" in push:
        raw = push["branches"]
        match raw:
            case str():
                branches = (raw,)
            case list() if all(isinstance(item, str) for item in raw):
                branches = tuple(raw)
            case _:
                WorkflowInputError.fail("workflow push.branches must be a string or string list")
    elif push is not None and not isinstance(push, dict):
        WorkflowInputError.fail("workflow push trigger configuration must be a mapping or null")
    return WorkflowTriggers(
        names=frozenset(value),
        push_branches=branches,
        push_uses_branches_ignore=isinstance(push, dict) and "branches-ignore" in push,
    )


def _parse_jobs(value: object) -> tuple[WorkflowJobInspection, ...]:
    if not isinstance(value, dict) or not value:
        WorkflowInputError.fail("workflow jobs must be a non-empty mapping")
    jobs: list[WorkflowJobInspection] = []
    for job_id, raw_job in sorted(value.items()):
        if not isinstance(job_id, str) or not isinstance(raw_job, dict):
            WorkflowInputError.fail("workflow jobs must map string identifiers to mappings")
        condition = raw_job.get("if")
        if condition is not None and not isinstance(condition, (str, bool)):
            WorkflowInputError.fail(f"workflow job {job_id!r} has an invalid if condition")
        raw_steps = raw_job.get("steps", [])
        if not isinstance(raw_steps, list):
            WorkflowInputError.fail(f"workflow job {job_id!r} steps must be a list")
        reusable_uses = raw_job.get("uses")
        if reusable_uses is not None and not isinstance(reusable_uses, str):
            WorkflowInputError.fail(f"workflow job {job_id!r} reusable uses must be a string")
        steps = tuple(_parse_step(job_id, step) for step in raw_steps)
        if not steps and "uses" not in raw_job:
            WorkflowInputError.fail(f"workflow job {job_id!r} must contain steps or reusable uses")
        jobs.append(
            WorkflowJobInspection(
                job_id=job_id,
                condition=(str(condition).lower() if isinstance(condition, bool) else condition),
                environment=_string_map(raw_job.get("env"), f"job {job_id!r} env"),
                has_permissions="permissions" in raw_job,
                has_timeout="timeout-minutes" in raw_job or "uses" in raw_job,
                steps=steps,
                reusable_uses=reusable_uses,
                permissions_safe=(
                    "permissions" not in raw_job
                    or _permissions_are_explicit_and_bounded(raw_job.get("permissions"))
                ),
                continues_on_error=raw_job.get("continue-on-error") is True,
            )
        )
    return tuple(jobs)


def _permissions_are_explicit_and_bounded(value: object) -> bool:
    if value == "read-all":
        return True
    if value == {}:
        return True
    if value == "write-all" or not isinstance(value, dict):
        return False
    return all(
        isinstance(scope, str) and isinstance(access, str) and access in {"none", "read", "write"}
        for scope, access in value.items()
    )


def _parse_step(job_id: str, value: object) -> WorkflowStepInspection:
    if not isinstance(value, dict):
        WorkflowInputError.fail(f"workflow job {job_id!r} contains a non-mapping step")
    uses = value.get("uses")
    run = value.get("run")
    if uses is not None and not isinstance(uses, str):
        WorkflowInputError.fail(f"workflow job {job_id!r} step uses must be a string")
    if run is not None and not isinstance(run, str):
        WorkflowInputError.fail(f"workflow job {job_id!r} step run must be a string")
    if uses is None and run is None:
        WorkflowInputError.fail(f"workflow job {job_id!r} step must contain uses or run")
    return WorkflowStepInspection(
        uses=uses,
        run=run,
        environment=_string_map(value.get("env"), f"job {job_id!r} step env"),
        inputs=_string_map(value.get("with"), f"job {job_id!r} step with"),
        continues_on_error=value.get("continue-on-error") is True,
    )


def _string_map(value: object, context: str) -> tuple[tuple[str, str], ...]:
    if value is None:
        return ()
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        WorkflowInputError.fail(f"workflow {context} must be a mapping with string keys")
    output: list[tuple[str, str]] = []
    for key, item in sorted(value.items()):
        if item is None or isinstance(item, (dict, list)):
            WorkflowInputError.fail(f"workflow {context} values must be scalar")
        rendered = str(item).lower() if isinstance(item, bool) else str(item)
        output.append((key, rendered))
    return tuple(output)


def _action_references(
    jobs: tuple[WorkflowJobInspection, ...], text: str
) -> tuple[ActionReference, ...]:
    output: list[ActionReference] = []
    starts_by_value: dict[str, int] = {}
    for job in jobs:
        for value in (job.reusable_uses, *(step.uses for step in job.steps)):
            if value is None or value.startswith("./"):
                continue
            reference = value.rsplit("@", maxsplit=1)[-1] if "@" in value else ""
            location = _uses_line(text, value, starts_by_value.get(value, 0))
            starts_by_value[value] = location.next_start
            immutable = (
                _OCI_DIGEST.fullmatch(reference) is not None
                if value.startswith("docker://")
                else _FULL_SHA.fullmatch(reference) is not None
            )
            output.append(ActionReference(value, location.line, immutable))
    return tuple(output)


def _uses_line(text: str, value: str, start: int) -> UsesLocation:
    pattern = rf"(?m)^\s*-?\s*uses\s*:\s*['\"]?{re.escape(value)}['\"]?\s*(?:#.*)?$"
    match = re.search(pattern, text[start:])
    if match is None:
        return UsesLocation(1, start)
    absolute = start + match.start()
    return UsesLocation(text.count("\n", 0, absolute) + 1, start + match.end())


def _creates_pull_request(jobs: tuple[WorkflowJobInspection, ...]) -> bool:
    for job in jobs:
        for step in job.steps:
            if step.uses and step.uses.lower().startswith("peter-evans/create-pull-request@"):
                return True
            if step.run and re.search(
                r"\bgh\s+pr\s+create\b",
                _strip_shell_comments(step.run),
                re.IGNORECASE,
            ):
                return True
    return False


def _cancel_in_progress(value: object) -> bool | None:
    if not isinstance(value, dict) or "cancel-in-progress" not in value:
        return None
    cancel = value["cancel-in-progress"]
    return cancel if isinstance(cancel, bool) else None


def _validate_path(path: str) -> None:
    parsed = PurePosixPath(path)
    if (
        parsed.is_absolute()
        or parsed.parts[:2] != (".github", "workflows")
        or len(parsed.parts) != _WORKFLOW_PATH_PARTS
        or parsed.suffix not in {".yml", ".yaml"}
    ):
        WorkflowInputError.fail("workflow path must be a direct .github/workflows/*.yml path")


def _strip_shell_comments(script: str) -> str:
    return "\n".join(_strip_shell_comment(line) for line in script.splitlines())


def _strip_shell_comment(line: str) -> str:
    single = False
    double = False
    escaped = False
    for index, character in enumerate(line):
        if character == "\\" and not single:
            escaped = not escaped
            continue
        if character == "'" and not double:
            single = not single
        elif character == '"' and not single and not escaped:
            double = not double
        elif character == "#" and not single and not double:
            return line[:index]
        escaped = False
    return line


def _uses_non_default_token(value: str) -> bool:
    return any(match.group(1).upper() != "GITHUB_TOKEN" for match in _SECRET.finditer(value))


def _has_any(value: str, *needles: str) -> bool:
    return any(needle in value for needle in needles)
