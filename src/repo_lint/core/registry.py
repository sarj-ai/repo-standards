from __future__ import annotations

from dataclasses import dataclass
from importlib import metadata

from .errors import ConfigurationError
from .models import Policy, PolicyId


POLICY_API_VERSION = 1
_ENTRY_POINT_GROUP = "repo_lint.policies.v1"


@dataclass(frozen=True, slots=True)
class PolicyRegistry:
    policies: tuple[Policy, ...]

    @classmethod
    def from_installed(cls) -> PolicyRegistry:
        loaded: list[Policy] = []
        for entry in sorted(
            metadata.entry_points(group=_ENTRY_POINT_GROUP), key=lambda item: item.name
        ):
            provider: object = entry.load()  # pyright: ignore[reportAny]
            if not isinstance(provider, type):
                ConfigurationError.fail(f"policy provider is not a class: {entry.name}")
            instance: object = provider()  # pyright: ignore[reportAny]
            if not isinstance(instance, Policy):
                ConfigurationError.fail(f"policy provider is incompatible: {entry.name}")
            if entry.name != instance.policy_id:
                ConfigurationError.fail(
                    f"policy entry point ID does not match provider: {entry.name}"
                )
            loaded.append(instance)
        registry = cls(tuple(loaded))
        registry._validate()
        return registry

    def resolve(self, policy_id: str) -> Policy:
        selected = [policy for policy in self.policies if policy.policy_id == policy_id]
        if len(selected) != 1:
            ConfigurationError.fail(f"policy is unavailable or ambiguous: {policy_id}")
        return selected[0]

    def policy_ids(self) -> tuple[PolicyId, ...]:
        return tuple(policy.policy_id for policy in self.policies)

    def _validate(self) -> None:
        ids = self.policy_ids()
        if len(ids) != len(set(ids)):
            ConfigurationError.fail("installed policy IDs are duplicated")
