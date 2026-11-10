from __future__ import annotations

import re

import yaml

from tests.test_public_content import OBJECT_LIST, OBJECT_MAP, REPOSITORY_ROOT


def test_docs_uv_consumers_share_setup_reuse_condition() -> None:
    document = OBJECT_MAP.validate_python(
        yaml.load(
            (REPOSITORY_ROOT / ".github/workflows/docs.yml").read_text(encoding="utf-8"),
            Loader=yaml.BaseLoader,
        ),
        strict=True,
    )
    jobs = OBJECT_MAP.validate_python(document["jobs"], strict=True)
    build = OBJECT_MAP.validate_python(jobs["build"], strict=True)
    steps = OBJECT_LIST.validate_python(build["steps"], strict=True)
    producers = [
        step for step in steps if str(step.get("uses", "")).startswith("astral-sh/setup-uv@")
    ]
    assert len(producers) == 1
    condition = producers[0].get("if")
    assert isinstance(condition, str)
    assert condition
    consumers = [
        step for step in steps if re.search(r"(?m)^\s*uvx?(?:\s|$)", str(step.get("run", "")))
    ]
    assert consumers
    assert not [step["name"] for step in consumers if step.get("if") != condition]
