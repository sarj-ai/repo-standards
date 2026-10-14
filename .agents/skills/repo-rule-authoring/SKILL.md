---
name: repo-rule-authoring
description: Propose, implement, and calibrate repository-policy rules using deterministic Git-tree evidence and warning-first governance.
---

# Repo rule authoring

State `Routing: repo-standards, because <evidence>`. Source/configuration semantics
belong in code-standards; filename, topology, ownership, and Git facts belong here.

- **Propose:** read only. Return the defect, owner/gap, harm, overlap, labeled
  cases, severity, limitations, and required authorization.
- **Implement:** read [rule-anatomy.md](references/rule-anatomy.md). Add source,
  metadata, versions, and governance atomically; write meaningful cases first. Reuse adequate
  coverage instead of requiring a new test for every review comment.
- **Calibrate:** read [calibration.md](references/calibration.md). Verify immutable
  local corpora, classify findings, and compare correctness and performance.
- **Review/promote:** require a separate immutable review commit. Authoring does
  not approve the rule or authorize consumer activation.

Start judgment-heavy rules as pending warnings. Preserve safe false negatives,
use syntax-aware evidence, and emit one diagnostic per defect. Do not infer authorship or intent.
A placement warning cannot justify deleting a test; review the asserted contract.

The developer-only calibration helper is
`scripts/calibrate_rules.py`; its commands and private-report rules are in the
calibration reference. Cloning, fetching, installation, publishing, commits, and consumer
mutation require session authorization. Never activate consumers implicitly.
