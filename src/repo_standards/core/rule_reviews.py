from __future__ import annotations

from dataclasses import dataclass

from .errors import ConfigurationError
from .models import RuleId


@dataclass(frozen=True, slots=True)
class RuleVersion:
    rule_id: RuleId
    version: int

    def __post_init__(self) -> None:
        if self.version < 1:
            message = "rule versions must be positive"
            raise ValueError(message)


def activated_rule_versions(
    requested_rules: tuple[str, ...], *, current_rules: frozenset[RuleVersion]
) -> frozenset[RuleVersion]:
    requested = tuple(_parse_rule_version(value) for value in requested_rules)
    if len(requested) != len(set(requested)):
        ConfigurationError.fail("enabled rule ID and version selectors must be unique")
    obsolete = sorted(f"{item.rule_id}@{item.version}" for item in set(requested) - current_rules)
    if obsolete:
        ConfigurationError.fail(
            "enabled rule selectors are obsolete; use the current registry version: "
            + ", ".join(obsolete)
        )
    return frozenset(requested)


def activated_rule_ids(
    requested_rule_ids: tuple[str, ...], *, current_rules: frozenset[RuleVersion]
) -> frozenset[RuleVersion]:
    if any("@" in value for value in requested_rule_ids):
        ConfigurationError.fail("manifest enabled_rules must use versionless rule IDs")
    requested = tuple(RuleId(value) for value in requested_rule_ids)
    if len(requested) != len(set(requested)):
        ConfigurationError.fail("manifest enabled_rules must be unique")
    current_by_id = {item.rule_id: item for item in current_rules}
    unavailable = sorted(str(item) for item in set(requested) - current_by_id.keys())
    if unavailable:
        ConfigurationError.fail(f"rules are not available: {', '.join(unavailable)}")
    return frozenset(current_by_id[item] for item in requested)


def _parse_rule_version(value: str) -> RuleVersion:
    rule_id, separator, version_text = value.rpartition("@")
    if not separator or not rule_id or not version_text.isascii() or not version_text.isdecimal():
        ConfigurationError.fail(
            f"enabled rules must use an exact rule-id@version selector: {value}"
        )
    version = int(version_text)
    if version < 1:
        ConfigurationError.fail(f"enabled rule versions must be positive: {value}")
    return RuleVersion(RuleId(rule_id), version)
