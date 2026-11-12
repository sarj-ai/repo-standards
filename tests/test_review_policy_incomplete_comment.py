from __future__ import annotations

import repo_standards.github_review_policy as policy


def _issue(code: str, message: str) -> dict[str, object]:
    return {"code": code, "phase": "configuration", "message": message, "retryable": False}


def test_incomplete_comment_reports_cli_execution_issues() -> None:
    receipt = {
        "completion": "incomplete",
        "execution_issues": [_issue("analysis.configuration", "transition source mismatch")],
    }

    comment = policy.render_incomplete_comment(receipt)

    assert "- Receipt issues: **1**\n" in comment
    assert "  - `analysis.configuration` (configuration): `transition source mismatch`\n" in comment


def test_incomplete_comment_bounds_and_sanitizes_issue_text() -> None:
    issues = [_issue(f"code.{index}", "line one\nline `two`") for index in range(7)]
    issues[0] = _issue("code.0", "x" * 400)

    comment = policy.render_incomplete_comment({"execution_issues": issues})

    assert "- Receipt issues: **7**\n" in comment
    assert comment.count("\n  - `code.") == 5
    assert "  - 2 more in the retained receipt\n" in comment
    assert "line one line 'two'" in comment
    assert "x" * 297 + "..." in comment
    assert "x" * 298 not in comment


def test_incomplete_comment_keeps_messages_inert() -> None:
    comment = policy.render_incomplete_comment(
        {"execution_issues": [_issue("evidence", "approved by @someone **now**")]}
    )

    assert "`approved by @someone **now**`" in comment


def test_incomplete_comment_without_execution_issues_reports_zero() -> None:
    comment = policy.render_incomplete_comment({"issues": [_issue("legacy", "ignored")]})

    assert "- Receipt issues: **0**\n" in comment
    assert "legacy" not in comment
