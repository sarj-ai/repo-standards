from __future__ import annotations

from datetime import date, timedelta
import re
import tomllib
from typing import TYPE_CHECKING

from pydantic import TypeAdapter

from .canonical import canonical_path
from .errors import ConfigurationError
from .models import (
    Baseline,
    CommitMessageConfig,
    CommitMessageEnforcement,
    Component,
    ComponentId,
    DocumentationConfig,
    ExceptionRecord,
    Manifest,
    PolicyId,
    PullRequestCommitHistoryConfig,
    PullRequestCommitHistoryTransition,
    PullRequestConfig,
    PullRequestReviewPolicyConfig,
    RepositoryId,
    RuleId,
)


if TYPE_CHECKING:
    from pathlib import Path


_ID = re.compile(r"^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_MAX_EXCEPTION_DURATION = timedelta(days=90)
_MAX_INPUT_BYTES = 1_048_576
_MAX_COMPONENTS = 10_000
_MAX_EXCEPTIONS = 1_000
_BASELINE_SCHEMA_VERSION = 2
_DEFAULT_MAXIMUM_COMMITS = 5
_MAXIMUM_COMMITS = 9_999
_MAXIMUM_TRANSITIONS = 64
_MAXIMUM_REVIEW_POLICY_ITEMS = 256
_MAXIMUM_COUNTED_LINES = 100_000_000
_MAXIMUM_GITHUB_LOGIN_LENGTH = 256
_MINIMUM_SHA_PREFIX_LENGTH = 12
_MAXIMUM_SHA_PREFIX_LENGTH = 40
_MAXIMUM_LOGICAL_REF_BYTES = 1_024
_ASCII_CONTROL_LIMIT = 32
_ASCII_DELETE = 127
_OBJECT_MAPPING = TypeAdapter(dict[str, object])


def _read_bounded(path: Path, kind: str) -> bytes:
    try:
        size = path.stat().st_size
        if size > _MAX_INPUT_BYTES:
            ConfigurationError.fail(f"{kind} exceeds {_MAX_INPUT_BYTES} bytes: {path.name}")
        return path.read_bytes()
    except OSError:
        ConfigurationError.fail(f"cannot read {kind}: {path.name}")


def _bounded_content(content: bytes, kind: str) -> bytes:
    if len(content) > _MAX_INPUT_BYTES:
        ConfigurationError.fail(f"{kind} exceeds {_MAX_INPUT_BYTES} bytes")
    return content


def _mapping(value: object, context: str) -> dict[str, object]:
    if not isinstance(value, dict):
        ConfigurationError.fail(f"{context} must be a table/object")
    return {
        key: item
        for key, item in value.items()  # pyright: ignore[reportUnknownVariableType]
        if isinstance(key, str)
    }


def _list(value: object, context: str) -> list[object]:
    if not isinstance(value, list):
        ConfigurationError.fail(f"{context} must be an array")
    return [  # ruff: ignore[unnecessary-comprehension] - narrows untyped JSON/TOML arrays
        item
        for item in value  # pyright: ignore[reportUnknownVariableType]
    ]


def _strict_keys(
    data: dict[str, object], allowed: set[str], required: set[str], context: str
) -> None:
    unknown = sorted(set(data) - allowed)
    missing = sorted(required - set(data))
    if unknown:
        ConfigurationError.fail(f"{context} has unknown fields: {', '.join(unknown)}")
    if missing:
        ConfigurationError.fail(f"{context} is missing fields: {', '.join(missing)}")


def _string(data: dict[str, object], key: str, context: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        ConfigurationError.fail(f"{context}.{key} must be a non-empty string")
    return value


def _identifier(value: str, context: str) -> str:
    if not _ID.fullmatch(value):
        ConfigurationError.fail(f"{context} must be lowercase ASCII segments: {value!r}")
    return value


def _integer(data: dict[str, object], key: str, context: str, *, default: int) -> int:
    value = data.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        ConfigurationError.fail(f"{context}.{key} must be an integer")
    return value


def _logical_branch_ref(value: str, context: str) -> str:
    invalid_character = any(
        ord(character) < _ASCII_CONTROL_LIMIT
        or ord(character) == _ASCII_DELETE
        or character.isspace()
        or character in "~^:?*[\\"
        for character in value
    )
    components = value.split("/")
    invalid = any(
        (
            len(value.encode("utf-8")) > _MAXIMUM_LOGICAL_REF_BYTES,
            value == "@",
            value.startswith(("-", "/", "refs/", "origin/")),
            value.endswith(("/", ".", ".lock")),
            "//" in value,
            ".." in value,
            "@{" in value,
            invalid_character,
            any(not component or component.startswith(".") for component in components),
            any(component.endswith(".lock") for component in components),
        )
    )
    if invalid:
        ConfigurationError.fail(f"{context} must be a safe logical branch name")
    return value


def parse_component(value: object, index: int) -> Component:
    context = f"components[{index}]"
    data = _mapping(value, context)
    allowed = {
        "id",
        "kind",
        "path",
        "owner",
        "product",
        "capability",
    }
    _strict_keys(data, allowed, {"id", "kind", "path", "owner"}, context)
    product = data.get("product")
    capability = data.get("capability")
    if product is not None and not isinstance(product, str):
        ConfigurationError.fail(f"{context}.product must be a string")
    if isinstance(product, str) and not product:
        ConfigurationError.fail(f"{context}.product must not be empty")
    if capability is not None and not isinstance(capability, str):
        ConfigurationError.fail(f"{context}.capability must be a string")
    if isinstance(capability, str) and not capability:
        ConfigurationError.fail(f"{context}.capability must not be empty")
    return Component(
        component_id=ComponentId(_identifier(_string(data, "id", context), f"{context}.id")),
        kind=_identifier(_string(data, "kind", context), f"{context}.kind"),
        path=canonical_path(_string(data, "path", context)),
        owner=_string(data, "owner", context),
        product=_identifier(product, f"{context}.product") if product else None,
        capability=_identifier(capability, f"{context}.capability") if capability else None,
    )


def parse_exception(value: object, index: int) -> ExceptionRecord:
    context = f"exceptions[{index}]"
    data = _mapping(value, context)
    fields = {
        "rule_id",
        "component_id",
        "manifest_anchor",
        "fingerprint",
        "owner",
        "reason",
        "issue",
        "created_on",
        "expires_on",
    }
    _strict_keys(data, fields, fields, context)
    created_on = _string(data, "created_on", context)
    expires_on = _string(data, "expires_on", context)
    fingerprint = _string(data, "fingerprint", context)
    if re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None:
        ConfigurationError.fail(f"{context}.fingerprint must be a SHA-256 hex string")
    if not _DATE.fullmatch(created_on) or not _DATE.fullmatch(expires_on):
        ConfigurationError.fail(f"{context}.created_on and expires_on must be YYYY-MM-DD")
    try:
        created_date = date.fromisoformat(created_on)
        expiry_date = date.fromisoformat(expires_on)
    except ValueError:
        ConfigurationError.fail(f"{context}.created_on and expires_on must be YYYY-MM-DD")
    if expiry_date < created_date:
        ConfigurationError.fail(f"{context}.expires_on must not precede created_on")
    if expiry_date - created_date > _MAX_EXCEPTION_DURATION:
        ConfigurationError.fail(f"{context} may not exceed 90 days")
    return ExceptionRecord(
        rule_id=RuleId(_string(data, "rule_id", context)),
        component_id=ComponentId(
            _identifier(_string(data, "component_id", context), f"{context}.component_id")
        ),
        manifest_anchor=_string(data, "manifest_anchor", context),
        fingerprint=fingerprint,
        owner=_string(data, "owner", context),
        reason=_string(data, "reason", context),
        issue=_string(data, "issue", context),
        created_on=created_on,
        expires_on=expires_on,
    )


def _string_list(value: object, context: str) -> list[str]:
    values = _list(value, context)
    if not all(isinstance(item, str) and item for item in values):
        ConfigurationError.fail(f"{context} must contain non-empty strings")
    return [item for item in values if isinstance(item, str)]


def parse_documentation(value: object) -> DocumentationConfig:
    data = _mapping(value, "documentation")
    _strict_keys(
        data,
        {"entrypoints", "maximum_added_pages", "addition_exemptions"},
        {"entrypoints"},
        "documentation",
    )
    entrypoints = tuple(
        canonical_path(item)
        for item in _string_list(data["entrypoints"], "documentation.entrypoints")
    )
    if not entrypoints or len(entrypoints) != len(set(entrypoints)):
        ConfigurationError.fail("documentation.entrypoints must be non-empty and unique")
    if any(not path.casefold().endswith(".md") for path in entrypoints):
        ConfigurationError.fail("documentation.entrypoints must be Markdown paths")
    maximum_added_pages = _integer(
        data, "maximum_added_pages", "documentation", default=0
    )
    if maximum_added_pages < 0:
        ConfigurationError.fail("documentation.maximum_added_pages must be non-negative")
    addition_exemptions = tuple(
        canonical_path(item)
        for item in _string_list(
            data.get("addition_exemptions", []), "documentation.addition_exemptions"
        )
    )
    if len(addition_exemptions) != len(set(addition_exemptions)):
        ConfigurationError.fail("documentation.addition_exemptions must be unique")
    if any(not path.casefold().endswith((".md", ".mdx")) for path in addition_exemptions):
        ConfigurationError.fail("documentation.addition_exemptions must be Markdown paths")
    return DocumentationConfig(
        entrypoints=entrypoints,
        maximum_added_pages=maximum_added_pages,
        addition_exemptions=addition_exemptions,
    )


def parse_pull_request_commit_history_transition(
    value: object, index: int
) -> PullRequestCommitHistoryTransition:
    context = f"pull_request.commit_history.transitions[{index}]"
    data = _mapping(value, context)
    fields = {"id", "source_ref", "base_ref", "head_prefix", "sha_prefix_length"}
    _strict_keys(data, fields, {"id", "source_ref", "base_ref", "head_prefix"}, context)
    transition_id = _identifier(_string(data, "id", context), f"{context}.id")
    source_ref = _logical_branch_ref(_string(data, "source_ref", context), f"{context}.source_ref")
    base_ref = _logical_branch_ref(_string(data, "base_ref", context), f"{context}.base_ref")
    if source_ref == base_ref:
        ConfigurationError.fail(f"{context}.source_ref and base_ref must differ")
    sha_prefix_length = _integer(
        data,
        "sha_prefix_length",
        context,
        default=_MINIMUM_SHA_PREFIX_LENGTH,
    )
    if not _MINIMUM_SHA_PREFIX_LENGTH <= sha_prefix_length <= _MAXIMUM_SHA_PREFIX_LENGTH:
        ConfigurationError.fail(
            f"{context}.sha_prefix_length must be between "
            f"{_MINIMUM_SHA_PREFIX_LENGTH} and {_MAXIMUM_SHA_PREFIX_LENGTH}"
        )
    head_prefix = _string(data, "head_prefix", context)
    _logical_branch_ref(f"{head_prefix}{'a' * sha_prefix_length}", f"{context}.head_prefix")
    return PullRequestCommitHistoryTransition(
        transition_id=transition_id,
        source_ref=source_ref,
        base_ref=base_ref,
        head_prefix=head_prefix,
        sha_prefix_length=sha_prefix_length,
    )


def parse_pull_request_commit_history(value: object) -> PullRequestCommitHistoryConfig:
    context = "pull_request.commit_history"
    data = _mapping(value, context)
    fields = {"maximum_commits", "advisory_base_ref", "transitions"}
    _strict_keys(data, fields, {"advisory_base_ref"}, context)
    maximum_commits = _integer(
        data,
        "maximum_commits",
        context,
        default=_DEFAULT_MAXIMUM_COMMITS,
    )
    if not 1 <= maximum_commits <= _MAXIMUM_COMMITS:
        ConfigurationError.fail(
            f"{context}.maximum_commits must be between 1 and {_MAXIMUM_COMMITS}"
        )
    advisory_base_ref = _logical_branch_ref(
        _string(data, "advisory_base_ref", context),
        f"{context}.advisory_base_ref",
    )
    raw_transitions = _list(data.get("transitions", []), f"{context}.transitions")
    if len(raw_transitions) > _MAXIMUM_TRANSITIONS:
        ConfigurationError.fail(f"{context} may contain at most {_MAXIMUM_TRANSITIONS} transitions")
    transitions = tuple(
        parse_pull_request_commit_history_transition(item, index)
        for index, item in enumerate(raw_transitions)
    )
    transition_ids = tuple(item.transition_id for item in transitions)
    if len(transition_ids) != len(set(transition_ids)):
        ConfigurationError.fail(f"{context}.transitions must have unique IDs")
    for index, transition in enumerate(transitions):
        for previous in transitions[:index]:
            prefix_overlaps = transition.head_prefix.startswith(
                previous.head_prefix
            ) or previous.head_prefix.startswith(transition.head_prefix)
            if prefix_overlaps:
                ConfigurationError.fail(
                    f"{context}.transitions must not have overlapping head prefixes"
                )
    return PullRequestCommitHistoryConfig(
        advisory_base_ref=advisory_base_ref,
        maximum_commits=maximum_commits,
        transitions=transitions,
    )


def parse_pull_request_review_policy(
    value: object,
    *,
    transitions: tuple[PullRequestCommitHistoryTransition, ...],
) -> PullRequestReviewPolicyConfig:
    context = "pull_request.review_policy"
    data = _mapping(value, context)
    fields = {
        "zero_review_below_counted_lines",
        "two_reviews_above_counted_lines",
        "migration_roots",
        "required_checks",
        "required_body_sections",
        "transition_exemptions",
        "transition_actors",
        "accepted_check_conclusions",
    }
    required = {
        "zero_review_below_counted_lines",
        "two_reviews_above_counted_lines",
        "migration_roots",
        "required_checks",
        "required_body_sections",
    }
    _strict_keys(data, fields, required, context)
    zero_review_below = _integer(
        data,
        "zero_review_below_counted_lines",
        context,
        default=0,
    )
    two_reviews_above = _integer(
        data,
        "two_reviews_above_counted_lines",
        context,
        default=0,
    )
    if not 1 <= zero_review_below <= _MAXIMUM_COUNTED_LINES:
        ConfigurationError.fail(
            f"{context}.zero_review_below_counted_lines must be between "
            f"1 and {_MAXIMUM_COUNTED_LINES}"
        )
    if not zero_review_below <= two_reviews_above <= _MAXIMUM_COUNTED_LINES:
        ConfigurationError.fail(
            f"{context}.two_reviews_above_counted_lines must be between "
            "zero_review_below_counted_lines and "
            f"{_MAXIMUM_COUNTED_LINES}"
        )

    def policy_strings(key: str, *, default: object | None = None) -> tuple[str, ...]:
        fallback: object = [] if default is None else default
        items = tuple(_string_list(data.get(key, fallback), f"{context}.{key}"))
        if len(items) > _MAXIMUM_REVIEW_POLICY_ITEMS:
            ConfigurationError.fail(
                f"{context}.{key} may contain at most {_MAXIMUM_REVIEW_POLICY_ITEMS} items"
            )
        if len(items) != len(set(items)):
            ConfigurationError.fail(f"{context}.{key} must contain unique values")
        return items

    raw_migration_roots = policy_strings("migration_roots")
    migration_roots = tuple(canonical_path(path) for path in raw_migration_roots)
    folded_roots = tuple(path.casefold() for path in migration_roots)
    if len(folded_roots) != len(set(folded_roots)):
        ConfigurationError.fail(f"{context}.migration_roots must contain unique paths")
    if any(any(character in root for character in "*?[") for root in migration_roots):
        ConfigurationError.fail(f"{context}.migration_roots must be exact repository paths")
    for index, root in enumerate(folded_roots):
        if any(
            root.startswith(f"{previous}/") or previous.startswith(f"{root}/")
            for previous in folded_roots[:index]
        ):
            ConfigurationError.fail(f"{context}.migration_roots must not overlap")

    required_checks = policy_strings("required_checks")
    if not required_checks:
        ConfigurationError.fail(f"{context}.required_checks must not be empty")
    required_body_sections = policy_strings("required_body_sections")
    if not required_body_sections:
        ConfigurationError.fail(f"{context}.required_body_sections must not be empty")
    transition_exemptions = policy_strings("transition_exemptions")
    known_transition_ids = {transition.transition_id for transition in transitions}
    unknown_exemptions = sorted(set(transition_exemptions) - known_transition_ids)
    if unknown_exemptions:
        ConfigurationError.fail(
            f"{context}.transition_exemptions references unknown transitions: "
            f"{', '.join(unknown_exemptions)}"
        )
    accepted_check_conclusions = policy_strings(
        "accepted_check_conclusions",
        default=["success"],
    )
    if accepted_check_conclusions not in {("success",), ("success", "skipped")}:
        ConfigurationError.fail(
            f"{context}.accepted_check_conclusions supports success and optional skipped"
        )
    return PullRequestReviewPolicyConfig(
        zero_review_below_counted_lines=zero_review_below,
        two_reviews_above_counted_lines=two_reviews_above,
        migration_roots=migration_roots,
        required_checks=required_checks,
        required_body_sections=required_body_sections,
        transition_exemptions=transition_exemptions,
        transition_actors=_review_policy_transition_actors(
            data,
            context=context,
            transition_exemptions=transition_exemptions,
        ),
        accepted_check_conclusions=accepted_check_conclusions,
    )


def _review_policy_transition_actors(
    data: dict[str, object],
    *,
    context: str,
    transition_exemptions: tuple[str, ...],
) -> tuple[str, ...]:
    actors = tuple(_string_list(data.get("transition_actors", []), f"{context}.transition_actors"))
    if len(actors) > _MAXIMUM_REVIEW_POLICY_ITEMS:
        ConfigurationError.fail(
            f"{context}.transition_actors may contain at most {_MAXIMUM_REVIEW_POLICY_ITEMS} items"
        )
    folded_actors = tuple(actor.casefold() for actor in actors)
    if len(folded_actors) != len(set(folded_actors)):
        ConfigurationError.fail(f"{context}.transition_actors must contain unique GitHub logins")
    if any(
        len(actor) > _MAXIMUM_GITHUB_LOGIN_LENGTH
        or actor != actor.strip()
        or any(character.isspace() or ord(character) < _ASCII_CONTROL_LIMIT for character in actor)
        for actor in actors
    ):
        ConfigurationError.fail(f"{context}.transition_actors must contain exact GitHub logins")
    if transition_exemptions and not actors:
        ConfigurationError.fail(
            f"{context}.transition_actors must not be empty when "
            "transition_exemptions are configured"
        )
    if actors and not transition_exemptions:
        ConfigurationError.fail(f"{context}.transition_actors requires transition_exemptions")
    return actors


def parse_pull_request(value: object) -> PullRequestConfig:
    data = _mapping(value, "pull_request")
    _strict_keys(
        data,
        {"commit_history", "review_policy"},
        {"commit_history"},
        "pull_request",
    )
    commit_history = parse_pull_request_commit_history(data["commit_history"])
    return PullRequestConfig(
        commit_history=commit_history,
        review_policy=parse_pull_request_review_policy(
            data["review_policy"],
            transitions=commit_history.transitions,
        )
        if "review_policy" in data
        else None,
    )


def parse_commit_message(value: object) -> CommitMessageConfig:
    context = "commit_message"
    data = _mapping(value, context)
    _strict_keys(data, {"enforcement"}, set(), context)
    raw = data.get("enforcement", CommitMessageEnforcement.STRICT.value)
    if not isinstance(raw, str):
        ConfigurationError.fail(f"{context}.enforcement must be observe or strict")
    try:
        enforcement = CommitMessageEnforcement(raw)
    except ValueError:
        ConfigurationError.fail(f"{context}.enforcement must be observe or strict")
    return CommitMessageConfig(enforcement=enforcement)


def parse_manifest_bytes(content: bytes) -> Manifest:
    try:
        parsed_manifest: object = tomllib.loads(
            _bounded_content(content, "manifest").decode("utf-8")
        )
        data = _mapping(parsed_manifest, "manifest")
    except OSError, RecursionError, UnicodeError, ValueError, tomllib.TOMLDecodeError:
        ConfigurationError.fail("cannot read manifest")
    fields = {
        "repository_id",
        "components",
        "enabled_rules",
        "exceptions",
        "documentation",
        "pull_request",
        "commit_message",
    }
    required = {"repository_id", "components"}
    _strict_keys(data, fields, required, "manifest")
    raw_components = _list(data["components"], "manifest.components")
    if len(raw_components) > _MAX_COMPONENTS:
        ConfigurationError.fail(f"manifest may contain at most {_MAX_COMPONENTS} components")
    raw_exceptions = _list(data.get("exceptions", []), "exceptions")
    if len(raw_exceptions) > _MAX_EXCEPTIONS:
        ConfigurationError.fail(f"manifest may contain at most {_MAX_EXCEPTIONS} exceptions")
    components = tuple(parse_component(item, index) for index, item in enumerate(raw_components))
    component_ids = [item.component_id for item in components]
    if len(component_ids) != len(set(component_ids)):
        ConfigurationError.fail("manifest contains duplicate component IDs")
    enabled_rules = tuple(_string_list(data.get("enabled_rules", []), "enabled_rules"))
    if len(enabled_rules) != len(set(enabled_rules)):
        ConfigurationError.fail("enabled_rules must be unique")
    return Manifest(
        repository_id=RepositoryId(
            _identifier(_string(data, "repository_id", "manifest"), "repository_id")
        ),
        components=components,
        enabled_rules=enabled_rules,
        exceptions=tuple(parse_exception(item, index) for index, item in enumerate(raw_exceptions)),
        documentation=parse_documentation(data["documentation"])
        if "documentation" in data
        else None,
        pull_request=parse_pull_request(data["pull_request"]) if "pull_request" in data else None,
        commit_message=parse_commit_message(data["commit_message"])
        if "commit_message" in data
        else CommitMessageConfig(),
    )


def load_manifest(path: Path) -> Manifest:
    return parse_manifest_bytes(_read_bounded(path, "manifest"))


def parse_baseline_bytes(content: bytes) -> Baseline:
    try:
        data = _OBJECT_MAPPING.validate_json(_bounded_content(content, "baseline"), strict=True)
    except OSError, RecursionError, UnicodeError, ValueError:
        ConfigurationError.fail("cannot read baseline")
    fields = {
        "schema_version",
        "repository_id",
        "policy",
        "policy_version",
        "scope_digest",
        "fingerprints",
    }
    _strict_keys(data, fields, fields, "baseline")
    if data["schema_version"] != _BASELINE_SCHEMA_VERSION:
        ConfigurationError.fail(f"baseline.schema_version must be {_BASELINE_SCHEMA_VERSION}")
    raw_fingerprints = _list(data["fingerprints"], "baseline.fingerprints")
    if not all(isinstance(item, str) for item in raw_fingerprints):
        ConfigurationError.fail("baseline fingerprints must be strings")
    fingerprints = [item for item in raw_fingerprints if isinstance(item, str)]
    if not all(re.fullmatch(r"[0-9a-f]{64}", item) for item in fingerprints):
        ConfigurationError.fail("baseline fingerprints must be SHA-256 hex strings")
    if len(fingerprints) != len(set(fingerprints)):
        ConfigurationError.fail("baseline contains duplicate fingerprints")
    policy_version = data["policy_version"]
    if not isinstance(policy_version, int) or isinstance(policy_version, bool):
        ConfigurationError.fail("baseline.policy_version must be an integer")
    return Baseline(
        repository_id=RepositoryId(_string(data, "repository_id", "baseline")),
        policy_id=PolicyId(_string(data, "policy", "baseline")),
        policy_version=policy_version,
        scope_digest=_string(data, "scope_digest", "baseline"),
        fingerprints=tuple(sorted(fingerprints)),
    )


def load_baseline(path: Path) -> Baseline:
    return parse_baseline_bytes(_read_bounded(path, "baseline"))
