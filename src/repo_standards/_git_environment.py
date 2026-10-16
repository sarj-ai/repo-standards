from __future__ import annotations

import os
from types import MappingProxyType


GIT_ENVIRONMENT = MappingProxyType(
    {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
    }
)
GIT_NO_PAGER_ENVIRONMENT = MappingProxyType({**GIT_ENVIRONMENT, "GIT_PAGER": "cat"})
