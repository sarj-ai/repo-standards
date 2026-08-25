from __future__ import annotations

from enum import Enum, StrEnum
from hashlib import sha256
import inspect
import json
from pathlib import Path
import types
from typing import (
    TYPE_CHECKING,
    Annotated,
    ClassVar,
    Literal,
    NamedTuple,
    NewType,
    Self,
    get_args,
    get_origin,
    get_type_hints,
)
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, field_validator, model_validator
from typer.models import ArgumentInfo, CommandInfo, DefaultPlaceholder, OptionInfo, TyperInfo

from repo_standards.core.canonical import canonical_json
from repo_standards.core.catalog import core_rules
from repo_standards.core.models import (
    ExampleLanguage,
    JSONValue,
    Policy,
    Rule,
    RuleCategoryId,
    RuleId,
    RuleTopicId,
)
from repo_standards.core.render import output_schema
from repo_standards.core.rule_reviews import (
    ApprovedRuleReview,
    review_for,
)
from repo_standards.core.taxonomy import CATEGORIES
from repo_standards.openapi import analysis_schema
from repo_standards.openapi import rules as rest_rules
from repo_standards.policy_sarj.policy import POLICY_SPEC, SarjPolicy
from repo_standards.rest import instrumentation_capabilities


if TYPE_CHECKING:
    import typer


_CATALOG_KIND = "repo-standards.catalog"
_CATALOG_SCHEMA_ID = "https://repo-standards.sarj.ai/schema/catalog-v7.schema.json"
_PUBLIC_REFERENCE_HOSTS = frozenset(
    {
        "docs.github.com",
        "json-schema.org",
        "spec.openapis.org",
        "www.rfc-editor.org",
    }
)
_JSON_OBJECT = TypeAdapter(dict[str, JSONValue])
_ANNOTATION_OBJECT = TypeAdapter(dict[str, object])

CommandId = NewType("CommandId", str)
CapabilityId = NewType("CapabilityId", str)
NonEmptyText = Annotated[str, Field(min_length=1)]
PositiveVersion = Annotated[int, Field(gt=0)]
ImmutableReviewReference = Annotated[
    str,
    Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$"),
]
RuleIdValue = Annotated[
    RuleId,
    Field(pattern=r"^[a-z0-9][a-z0-9-]*(/[a-z0-9][a-z0-9-]*){2,}$"),
]
RuleSlug = Annotated[
    str,
    Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$", min_length=3, max_length=64),
]
SourcePath = Annotated[
    str,
    Field(
        min_length=1,
        json_schema_extra={"pattern": r"^(?!/|~)(?!.*(?:^|/)\.\.(?:/|$)).+$"},
    ),
]
HttpsUrl = Annotated[str, Field(pattern=r"^https://")]

_RULE_SLUGS: dict[str, RuleSlug] = {
    "api/artifact/provenance": "artifact-provenance",
    "api/errors/problem-details": "problem-details",
    "api/http/message-semantics": "http-message-semantics",
    "api/references/local-resolution": "local-references",
    "architecture/dependencies/policy": "dependency-policy",
    "architecture/layout/component-paths": "component-paths",
    "architecture/schema/component": "component-identity",
    "repository/migration/consistency": "migration-consistency",
    "repository/artifacts/terraform-examples": "terraform-examples",
    "repository/artifacts/bespoke-iac-verifiers": "bespoke-iac-verifiers",
    "repository/artifacts/terraform-test-files": "terraform-test-files",
    "repository/documentation/placement": "documentation-placement",
    "repository/documentation/reachability": "documentation-reachability",
    "repository/configuration/unresolved-placeholders": "unresolved-placeholders",
    "architecture/delivery/authority": "deployment-authority",
}


class _ParameterResult(NamedTuple):
    descriptor: ParameterDescriptor
    is_option: bool


class _AnnotationParts(NamedTuple):
    base: object
    metadata: tuple[object, ...]


class CatalogModel(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True, strict=True)


class ProductDescriptor(CatalogModel):
    product_id: Literal["repo-standards"]
    name: str
    title: str
    summary: str
    distribution: str
    executables: tuple[str, ...]
    repository_url: str
    website_url: str


class ProvenanceDescriptor(CatalogModel):
    distribution: str
    package_version: str
    repository_url: str
    content_digest: str


class SafetyDescriptor(CatalogModel):
    mutation: bool
    repository_code_execution: bool
    network_default: bool
    network_mode: str
    inspection_input: str


class ExampleDescriptor(CatalogModel):
    id: NonEmptyText
    title: Annotated[str, Field(min_length=1, max_length=56)]
    language: ExampleLanguage
    before: NonEmptyText
    after: NonEmptyText
    expected_severity: Literal["warning", "error"]


class SourcePointer(CatalogModel):
    path: SourcePath
    symbol: NonEmptyText

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        if value.startswith(("/", "~")) or ".." in Path(value).parts:
            message = "catalog source paths must be repository-relative"
            raise ValueError(message)
        return value


class PendingRuleReviewDescriptor(CatalogModel):
    status: Literal["pending"] = "pending"
    reviewed_in: None = None


class ApprovedRuleReviewDescriptor(CatalogModel):
    status: Literal["approved"] = "approved"
    reviewed_in: ImmutableReviewReference


RuleReviewDescriptor = Annotated[
    PendingRuleReviewDescriptor | ApprovedRuleReviewDescriptor,
    Field(discriminator="status"),
]


class TopicDescriptor(CatalogModel):
    topic_id: RuleTopicId
    label: str
    order: int


class CategoryDescriptor(CatalogModel):
    category_id: RuleCategoryId
    label: str
    order: int
    topics: tuple[TopicDescriptor, ...]


class RuleDescriptor(CatalogModel):
    kind: Literal["rule"] = "rule"
    rule_id: RuleIdValue
    slug: RuleSlug
    rule_version: PositiveVersion
    title: Annotated[str, Field(min_length=1, max_length=72)]
    category_id: RuleCategoryId
    topic_id: RuleTopicId
    default_severity: Literal["warning", "error"]
    description: NonEmptyText
    why: NonEmptyText
    fix: NonEmptyText
    references: tuple[HttpsUrl, ...]
    examples: Annotated[tuple[ExampleDescriptor, ...], Field(min_length=1)]
    source: SourcePointer
    review: RuleReviewDescriptor

    @model_validator(mode="after")
    def validate_clarity(self) -> Self:
        prose = (self.description, self.why, self.fix)
        normalized = tuple(" ".join(value.casefold().split()) for value in prose)
        if any(not value for value in normalized) or len(set(normalized)) != len(normalized):
            message = f"rule clarity fields must be nonempty and distinct: {self.rule_id}"
            raise ValueError(message)
        if not self.examples:
            message = f"rule must provide an example pair: {self.rule_id}"
            raise ValueError(message)
        return self

    @field_validator("references")
    @classmethod
    def validate_references(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            parsed = urlsplit(value)
            if parsed.scheme != "https" or not parsed.hostname:
                message = "catalog references must be canonical HTTPS URLs"
                raise ValueError(message)
            host = parsed.hostname.casefold()
            if host not in _PUBLIC_REFERENCE_HOSTS:
                message = f"catalog reference host is not public-approved: {host}"
                raise ValueError(message)
        return values


class PolicyRuleBinding(CatalogModel):
    rule_id: RuleId
    rule_version: PositiveVersion
    severity: Literal["warning", "error"]
    classification: str | None = None
    evidence_level: str | None = None
    precedence: int | None = None
    review_status: Literal["pending", "approved"]
    default_activation: Literal["disabled"] = "disabled"


class PolicyDescriptor(CatalogModel):
    policy_id: str
    policy_version: PositiveVersion
    title: str
    bindings: tuple[PolicyRuleBinding, ...]


class ParameterDescriptor(CatalogModel):
    names: tuple[str, ...]
    value_type: str
    required: bool
    default: JSONValue
    choices: tuple[str, ...]
    help: str
    repeatable: bool


class CommandDescriptor(CatalogModel):
    command_id: CommandId
    path: tuple[str, ...]
    summary: str
    options: tuple[ParameterDescriptor, ...]
    arguments: tuple[ParameterDescriptor, ...]


class CapabilityDescriptor(CatalogModel):
    capability_id: CapabilityId
    title: str
    summary: str
    status: Literal["preview", "beta", "stable"]
    command_ids: tuple[CommandId, ...]
    input_kinds: tuple[str, ...]


class SchemaDescriptor(CatalogModel):
    schema_id: str
    title: str
    schema_version: int
    media_type: Literal["application/schema+json"]
    cli_selector: str
    document: JSONValue


class Catalog(CatalogModel):
    kind: Literal["repo-standards.catalog"] = _CATALOG_KIND
    schema_version: Literal[7] = 7
    catalog_version: str
    product: ProductDescriptor
    provenance: ProvenanceDescriptor
    safety: SafetyDescriptor
    capabilities: tuple[CapabilityDescriptor, ...]
    categories: tuple[CategoryDescriptor, ...]
    policies: tuple[PolicyDescriptor, ...]
    rules: tuple[RuleDescriptor, ...]
    commands: tuple[CommandDescriptor, ...]
    schemas: tuple[SchemaDescriptor, ...]

    @model_validator(mode="after")
    def validate_taxonomy(self) -> Self:
        _validate_taxonomy_graph(self)
        _validate_rule_graph(self)
        _validate_command_graph(self)
        return self


def _validate_taxonomy_graph(catalog: Catalog) -> None:
    category_ids = [category.category_id for category in catalog.categories]
    category_orders = [category.order for category in catalog.categories]
    if len(category_ids) != len(set(category_ids)) or len(category_orders) != len(
        set(category_orders)
    ):
        message = "catalog category ids and orders must be unique"
        raise ValueError(message)
    for category in catalog.categories:
        topic_orders = [topic.order for topic in category.topics]
        if len(topic_orders) != len(set(topic_orders)):
            message = f"catalog topic orders must be unique: {category.category_id}"
            raise ValueError(message)
    topic_parents = {
        topic.topic_id: category.category_id
        for category in catalog.categories
        for topic in category.topics
    }
    if len(topic_parents) != sum(len(category.topics) for category in catalog.categories):
        message = "catalog topic ids must be unique"
        raise ValueError(message)
    used_categories: set[RuleCategoryId] = set()
    used_topics: set[RuleTopicId] = set()
    for rule in catalog.rules:
        if topic_parents.get(rule.topic_id) != rule.category_id:
            message = f"rule has an invalid taxonomy assignment: {rule.rule_id}"
            raise ValueError(message)
        used_categories.add(rule.category_id)
        used_topics.add(rule.topic_id)
    declared_categories = {category.category_id for category in catalog.categories}
    if used_categories != declared_categories or used_topics != set(topic_parents):
        message = "every catalog category and topic must contain a rule"
        raise ValueError(message)


def _validate_rule_graph(catalog: Catalog) -> None:
    if catalog.catalog_version != catalog.provenance.package_version:
        message = "catalog and provenance package versions must match"
        raise ValueError(message)
    fixture_ids = [example.id for rule in catalog.rules for example in rule.examples]
    if len(fixture_ids) != len(set(fixture_ids)):
        message = "catalog example fixture ids must be unique"
        raise ValueError(message)
    rules_by_id = {rule.rule_id: rule for rule in catalog.rules}
    if len(rules_by_id) != len(catalog.rules):
        message = "catalog active rule ids must be unique"
        raise ValueError(message)
    slugs = [rule.slug for rule in catalog.rules]
    if len(slugs) != len(set(slugs)):
        message = "catalog rule slugs must be unique"
        raise ValueError(message)
    policy_ids = {policy.policy_id for policy in catalog.policies}
    if len(policy_ids) != len(catalog.policies):
        message = "catalog policy ids must be unique"
        raise ValueError(message)
    for policy in catalog.policies:
        _validate_policy_bindings(policy, rules_by_id)


def _validate_policy_bindings(
    policy: PolicyDescriptor, rules_by_id: dict[RuleId, RuleDescriptor]
) -> None:
    binding_ids = {binding.rule_id for binding in policy.bindings}
    if len(binding_ids) != len(policy.bindings):
        message = f"catalog policy bindings must be unique: {policy.policy_id}"
        raise ValueError(message)
    for binding in policy.bindings:
        rule = rules_by_id.get(binding.rule_id)
        if rule is None or (
            binding.rule_version != rule.rule_version
            or binding.severity != rule.default_severity
            or binding.review_status != rule.review.status
        ):
            message = f"catalog policy binding does not match its rule: {binding.rule_id}"
            raise ValueError(message)


def _validate_command_graph(catalog: Catalog) -> None:
    command_ids = {command.command_id for command in catalog.commands}
    if len(command_ids) != len(catalog.commands):
        message = "catalog command ids must be unique"
        raise ValueError(message)
    if any(command.command_id != ".".join(command.path) for command in catalog.commands):
        message = "catalog command ids must match command paths"
        raise ValueError(message)
    capability_ids = {capability.capability_id for capability in catalog.capabilities}
    if len(capability_ids) != len(catalog.capabilities):
        message = "catalog capability ids must be unique"
        raise ValueError(message)
    if any(
        command_id not in command_ids
        for capability in catalog.capabilities
        for command_id in capability.command_ids
    ):
        message = "catalog capabilities must reference declared commands"
        raise ValueError(message)
    schema_ids = {schema.schema_id for schema in catalog.schemas}
    if len(schema_ids) != len(catalog.schemas):
        message = "catalog schema ids must be unique"
        raise ValueError(message)


def catalog_schema() -> dict[str, JSONValue]:
    schema = _JSON_OBJECT.validate_python(Catalog.model_json_schema(), strict=True)
    schema["$id"] = _CATALOG_SCHEMA_ID
    return schema


def report_schema() -> dict[str, JSONValue]:
    schema = _schema_object(output_schema())
    required = _schema_required(schema)
    required.extend(["tool", "command", "provenance", "baseline", "ratchet"])
    properties = _schema_properties(schema)
    properties.update(
        {
            "tool": {
                "type": "object",
                "additionalProperties": False,
                "required": ["name", "version"],
                "properties": {
                    "name": {"const": "repo-standards"},
                    "version": {"type": "string"},
                },
            },
            "command": {"enum": ["check", "report"]},
            "provenance": {"type": "object"},
            "baseline": {"type": "object"},
            "ratchet": {"type": "object"},
        }
    )
    schema["required"] = required
    schema["properties"] = properties
    schema["oneOf"] = [
        {
            "properties": {
                "completion": {"const": "complete"},
                "conclusion": {"const": "passed"},
                "diagnostics": {"maxItems": 0},
                "execution_issues": {"maxItems": 0},
            },
            "required": ["completion", "conclusion", "diagnostics", "execution_issues"],
        },
        {
            "properties": {
                "completion": {"const": "complete"},
                "conclusion": {"const": "findings"},
                "diagnostics": {"minItems": 1},
                "execution_issues": {"maxItems": 0},
            },
            "required": ["completion", "conclusion", "diagnostics", "execution_issues"],
        },
        {
            "properties": {
                "completion": {"const": "incomplete"},
                "conclusion": {"const": "inconclusive"},
                "diagnostics": {"maxItems": 0},
                "execution_issues": {"minItems": 1},
            },
            "required": ["completion", "conclusion", "diagnostics", "execution_issues"],
        },
    ]
    return schema


def openapi_report_schema() -> dict[str, JSONValue]:
    schema = _schema_object(analysis_schema())
    required = _schema_required(schema)
    required.extend(["tool", "command", "provenance", "application_code_executed", "summary"])
    properties = _schema_properties(schema)
    properties.update(
        {
            "tool": {
                "type": "object",
                "additionalProperties": False,
                "required": ["name", "version"],
                "properties": {
                    "name": {"const": "repo-standards"},
                    "version": {"type": "string"},
                },
            },
            "command": {"const": "rest.check"},
            "provenance": {"type": "object"},
            "application_code_executed": {"const": False},
            "summary": {
                "type": "object",
                "additionalProperties": False,
                "required": ["diagnostics", "errors", "warnings"],
                "properties": {
                    "diagnostics": {"type": "integer", "minimum": 0},
                    "errors": {"type": "integer", "minimum": 0},
                    "warnings": {"type": "integer", "minimum": 0},
                },
            },
        }
    )
    schema["required"] = required
    schema["properties"] = properties
    return schema


def build_catalog(app: typer.Typer, *, package_version: str) -> Catalog:
    policy = SarjPolicy()
    commands = _commands(app)
    policies = _policies(policy)
    rules = _rules(policy)
    used_taxonomy = {(rule.category_id, rule.topic_id) for rule in rules}
    schemas = _schemas()
    catalog = Catalog(
        catalog_version=package_version,
        product=ProductDescriptor(
            product_id="repo-standards",
            name="repo-standards",
            title="Sarj Repo Standards",
            summary=(
                "Deterministic repository architecture, pull-request, and API contract analysis."
            ),
            distribution="repo-standards",
            executables=("repo-standards",),
            repository_url="https://github.com/sarj-ai/repo-standards",
            website_url="https://repo-standards.sarj.ai/",
        ),
        provenance=ProvenanceDescriptor(
            distribution="repo-standards",
            package_version=package_version,
            repository_url="https://github.com/sarj-ai/repo-standards",
            content_digest="",
        ),
        safety=SafetyDescriptor(
            mutation=False,
            repository_code_execution=False,
            network_default=False,
            network_mode="disabled",
            inspection_input="exact Git tree",
        ),
        capabilities=_capabilities(commands),
        categories=tuple(
            CategoryDescriptor(
                category_id=category.category_id,
                label=category.label,
                order=category.order,
                topics=tuple(
                    TopicDescriptor(
                        topic_id=topic.topic_id,
                        label=topic.label,
                        order=topic.order,
                    )
                    for topic in category.topics
                    if (category.category_id, topic.topic_id) in used_taxonomy
                ),
            )
            for category in CATEGORIES
            if any(category_id == category.category_id for category_id, _topic_id in used_taxonomy)
        ),
        policies=policies,
        rules=rules,
        commands=commands,
        schemas=schemas,
    )
    digest_payload = _JSON_OBJECT.validate_python(catalog.model_dump(mode="json"), strict=True)
    digest = sha256(canonical_json(digest_payload).encode()).hexdigest()
    return catalog.model_copy(
        update={"provenance": catalog.provenance.model_copy(update={"content_digest": digest})}
    )


def _policies(policy: Policy) -> tuple[PolicyDescriptor, ...]:
    governance = {str(item.rule_id): item for item in POLICY_SPEC.rule_governance}
    bindings: list[PolicyRuleBinding] = []
    for rule in sorted(policy.rules(), key=lambda item: str(item.rule_id)):
        item = governance.get(str(rule.rule_id))
        review = review_for(RuleId(str(rule.rule_id)), rule.version)
        bindings.append(
            PolicyRuleBinding(
                rule_id=RuleId(str(rule.rule_id)),
                rule_version=rule.version,
                severity=rule.severity,
                classification=item.classification.value if item else None,
                evidence_level=item.evidence if item else None,
                precedence=item.precedence if item else None,
                review_status=review.status,
            )
        )
    return (
        PolicyDescriptor(
            policy_id=str(policy.policy_id),
            policy_version=policy.policy_version,
            title=POLICY_SPEC.title,
            bindings=tuple(bindings),
        ),
    )


def _rules(policy: Policy) -> tuple[RuleDescriptor, ...]:
    selected: dict[str, tuple[RuleDescriptor, str]] = {}
    for rule in core_rules():
        _add_rule(selected, rule, "src/repo_standards/core/catalog.py")
    for rule in policy.rules():
        _add_rule(selected, rule, "src/repo_standards/policy_sarj/policy.py")
    for rule in rest_rules():
        _add_rule(selected, rule, "src/repo_standards/openapi/catalog.py")
    return tuple(selected[key][0] for key in sorted(selected))


def _add_rule(
    selected: dict[str, tuple[RuleDescriptor, str]], rule: Rule, source_path: str
) -> None:
    rule_id = str(rule.rule_id)
    previous = selected.get(rule_id)
    if previous is not None:
        message = f"duplicate catalog rule {rule_id}: {previous[1]} and {source_path}"
        raise ValueError(message)
    selected[rule_id] = (_rule_descriptor(rule, source_path), source_path)


def _rule_descriptor(rule: Rule, source_path: str) -> RuleDescriptor:
    review = review_for(RuleId(str(rule.rule_id)), rule.version)
    if isinstance(review, ApprovedRuleReview):
        review_descriptor: RuleReviewDescriptor = ApprovedRuleReviewDescriptor(
            reviewed_in=review.reviewed_in,
        )
    else:
        review_descriptor = PendingRuleReviewDescriptor()
    return RuleDescriptor(
        rule_id=RuleId(str(rule.rule_id)),
        slug=_RULE_SLUGS[str(rule.rule_id)],
        rule_version=rule.version,
        title=rule.title,
        category_id=rule.taxonomy.category_id,
        topic_id=rule.taxonomy.topic_id,
        default_severity=rule.default_severity,
        description=rule.description,
        why=rule.why,
        fix=rule.fix,
        references=rule.references,
        examples=tuple(
            ExampleDescriptor(
                id=str(example.example_id),
                title=example.title,
                language=example.language,
                before=example.before,
                after=example.after,
                expected_severity=example.expected_severity,
            )
            for example in rule.examples
        ),
        source=SourcePointer(path=source_path, symbol=str(rule.rule_id)),
        review=review_descriptor,
    )


def _commands(app: typer.Typer) -> tuple[CommandDescriptor, ...]:
    descriptors: list[CommandDescriptor] = []
    _walk_commands(app, (), descriptors)
    return tuple(sorted(descriptors, key=lambda item: item.path))


def _walk_commands(
    current: typer.Typer,
    path: tuple[str, ...],
    descriptors: list[CommandDescriptor],
) -> None:
    for group in current.registered_groups:
        if _placeholder_boolean(value=group.hidden):
            continue
        name = _group_name(group)
        if group.typer_instance is not None:
            _walk_commands(group.typer_instance, (*path, name), descriptors)
    for command in current.registered_commands:
        if command.hidden or command.callback is None:
            continue
        name = command.name or command.callback.__name__.replace("_", "-")
        descriptors.append(_command_descriptor(command, (*path, name)))


def _command_descriptor(command: CommandInfo, path: tuple[str, ...]) -> CommandDescriptor:
    callback = command.callback
    if callback is None:
        message = "registered public command is missing its callback"
        raise ValueError(message)
    signature = inspect.signature(callback)
    hints = _ANNOTATION_OBJECT.validate_python(
        get_type_hints(callback, include_extras=True), strict=True
    )
    options: list[ParameterDescriptor] = []
    arguments: list[ParameterDescriptor] = []
    for name, parameter in signature.parameters.items():
        annotation = hints[name]
        descriptor, is_option = _parameter(name, parameter, annotation)
        (options if is_option else arguments).append(descriptor)
    summary = command.help or inspect.getdoc(callback) or ""
    return CommandDescriptor(
        command_id=CommandId(".".join(path)),
        path=path,
        summary=summary,
        options=tuple(options),
        arguments=tuple(arguments),
    )


def _parameter(name: str, parameter: inspect.Parameter, annotation: object) -> _ParameterResult:
    base, metadata = _annotation_parts(annotation)
    option = next((item for item in metadata if isinstance(item, OptionInfo)), None)
    argument = next((item for item in metadata if isinstance(item, ArgumentInfo)), None)
    is_option = option is not None or argument is None
    help_text = (option.help if option else argument.help if argument else None) or ""
    names = _parameter_names(name, option) if is_option else (name,)
    required = _parameter_is_required(parameter)
    default = None if required else _reflected_default(parameter)
    choices = _choices(base)
    repeatable = get_origin(base) in {list, tuple}
    return _ParameterResult(
        descriptor=ParameterDescriptor(
            names=names,
            value_type=_type_name(base),
            required=required,
            default=_json_value(default),
            choices=choices,
            help=help_text,
            repeatable=repeatable,
        ),
        is_option=is_option,
    )


def _annotation_parts(annotation: object) -> _AnnotationParts:
    if get_origin(annotation) is Annotated:
        arguments: tuple[object, ...] = get_args(annotation)
        return _AnnotationParts(arguments[0], arguments[1:])
    return _AnnotationParts(annotation, ())


def _parameter_names(name: str, option: OptionInfo | None) -> tuple[str, ...]:
    if option is None:
        return (f"--{name.replace('_', '-')}",)
    declared: list[str] = []
    if isinstance(option.default, str) and option.default.startswith("-"):
        declared.append(option.default)
    if option.param_decls:
        declared.extend(option.param_decls)
    return tuple(declared) or (f"--{name.replace('_', '-')}",)


def _choices(annotation: object) -> tuple[str, ...]:
    selected = _non_optional(annotation)
    if isinstance(selected, type) and issubclass(selected, Enum):
        return tuple(_enum_value(item) for item in selected)
    return ()


def _type_name(annotation: object) -> str:
    selected = _non_optional(annotation)
    origin = get_origin(selected)
    if isinstance(origin, type):
        return origin.__name__
    if isinstance(selected, type):
        return selected.__name__
    return str(selected)


def _non_optional(annotation: object) -> object:
    origin = get_origin(annotation)
    if origin is types.UnionType:
        arguments: tuple[object, ...] = get_args(annotation)
        return next((item for item in arguments if item is not type(None)), annotation)
    return annotation


def _enum_value(value: Enum) -> str:
    if isinstance(value, StrEnum):
        return str(value)
    return value.name


def _group_name(group: TyperInfo) -> str:
    if isinstance(group.name, str):
        return group.name
    return "group"


def _placeholder_boolean(*, value: bool | DefaultPlaceholder) -> bool:
    return value if isinstance(value, bool) else False


def _parameter_is_required(parameter: inspect.Parameter) -> bool:
    return parameter.default is inspect.Parameter.empty  # pyright: ignore[reportAny] - inspect boundary


def _reflected_default(parameter: inspect.Parameter) -> JSONValue:
    return _json_value(parameter.default)  # pyright: ignore[reportAny] - inspect boundary


def _json_value(value: object) -> JSONValue:
    encoded = json.dumps({"value": value}, default=_json_default, ensure_ascii=True, sort_keys=True)
    envelope = _JSON_OBJECT.validate_json(encoded, strict=True)
    return envelope["value"]


def _json_default(value: object) -> str:
    match value:
        case Path():
            return value.as_posix()
        case Enum():
            return _enum_value(value)
        case _:
            return str(value)


def _capabilities(commands: tuple[CommandDescriptor, ...]) -> tuple[CapabilityDescriptor, ...]:
    command_ids = tuple(item.command_id for item in commands)
    rest_inputs = tuple(sorted({item.framework for item in instrumentation_capabilities()}))
    return (
        CapabilityDescriptor(
            capability_id=CapabilityId("repository"),
            title="Repository architecture",
            summary="Inspect exact Git trees and evaluate versioned repository policy.",
            status="stable",
            command_ids=tuple(
                item for item in command_ids if item in {"check", "inspect", "report", "rules"}
            ),
            input_kinds=("git-tree", "repository-manifest"),
        ),
        CapabilityDescriptor(
            capability_id=CapabilityId("pull-request-size"),
            title="Pull-request review size",
            summary="Count reviewable churn while excluding tests and declared generated output.",
            status="stable",
            command_ids=(CommandId("pull-request.size"),),
            input_kinds=("git-diff", "git-attributes"),
        ),
        CapabilityDescriptor(
            capability_id=CapabilityId("rest"),
            title="REST and OpenAPI",
            summary="Analyze committed API contracts without executing application code.",
            status="preview",
            command_ids=tuple(item for item in command_ids if item.startswith("rest.")),
            input_kinds=rest_inputs,
        ),
    )


def _schemas() -> tuple[SchemaDescriptor, ...]:
    documents = (
        ("report", "Repository analysis report", 3, "report", report_schema()),
        (
            "openapi-analysis",
            "OpenAPI analysis report",
            3,
            "openapi-analysis",
            openapi_report_schema(),
        ),
        ("catalog", "Repo Standards public catalog", 7, "catalog", catalog_schema()),
    )
    return tuple(
        SchemaDescriptor(
            schema_id=schema_id,
            title=title,
            schema_version=schema_version,
            media_type="application/schema+json",
            cli_selector=selector,
            document=_JSON_OBJECT.validate_python(dict(document), strict=True),
        )
        for schema_id, title, schema_version, selector, document in documents
    )


def _schema_object(value: object) -> dict[str, JSONValue]:
    return _JSON_OBJECT.validate_python(value, strict=True)


def _schema_required(schema: dict[str, JSONValue]) -> list[JSONValue]:
    required = schema.get("required")
    if not isinstance(required, list) or not all(isinstance(item, str) for item in required):
        message = "installed schema has an incompatible required collection"
        raise TypeError(message)
    return list(required)


def _schema_properties(schema: dict[str, JSONValue]) -> dict[str, JSONValue]:
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        message = "installed schema has an incompatible properties object"
        raise TypeError(message)
    return _JSON_OBJECT.validate_python(properties, strict=True)
