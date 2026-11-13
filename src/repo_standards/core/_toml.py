from __future__ import annotations

import tomllib
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from .outcome import ConfigValue


def parse_toml_object(content: bytes) -> dict[str, ConfigValue]:
    return tomllib.loads(content.decode("utf-8"))
