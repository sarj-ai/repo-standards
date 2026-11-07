from __future__ import annotations

import hashlib
from pathlib import Path


def test_vendored_merge_risk_skill_preserves_the_upstream_bytes() -> None:
    # Exact upstream bytes are the compatibility contract; format checks cannot prove it.
    skill = Path(__file__).parents[2] / ".agents" / "skills" / "merge-risk" / "SKILL.md"

    assert hashlib.sha256(skill.read_bytes()).hexdigest() == (
        "1a11fcb7503eeb92a901755c0f729216cfdb8674a4ac2b0890e019d594e1ae17"
    )
