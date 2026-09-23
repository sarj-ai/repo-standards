from __future__ import annotations

from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from .models import RuleDefinition


def core_rules() -> tuple[RuleDefinition, ...]:
    return ()
