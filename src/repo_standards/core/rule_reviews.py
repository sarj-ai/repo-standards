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


def activated_rule_ids(
    requested_rule_ids: tuple[str, ...], *, current_rules: frozenset[RuleVersion]
) -> frozenset[RuleVersion]:
    if any("@" in value for value in requested_rule_ids):
        ConfigurationError.fail("enabled rules must use versionless rule IDs")
    requested = tuple(RuleId(value) for value in requested_rule_ids)
    if len(requested) != len(set(requested)):
        ConfigurationError.fail("enabled rules must be unique")
    current_by_id = {item.rule_id: item for item in current_rules}
    unavailable = sorted(str(item) for item in set(requested) - current_by_id.keys())
    if unavailable:
        ConfigurationError.fail(f"rules are not available: {', '.join(unavailable)}")
    return frozenset(current_by_id[item] for item in requested)
