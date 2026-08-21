---
name: repo-rule-authoring
description: Propose, implement, and calibrate repo-standards lint rules when deterministic evidence, false-positive review, or pending-rule governance matters.
---

# Repo rule authoring

Use this skill for repository-policy rules, not ordinary application lint fixes.

## Modes

- **Propose:** read only. Return a RuleProblem, upstream/catalog overlap, labeled cases,
  severity, limitations, and the authorization needed for implementation. Do not write files.
- **Implement:** read [rule-anatomy.md](references/rule-anatomy.md), write labeled cases first,
  then add implementation, catalog metadata, governance, versions, and tests atomically.
- **Calibrate:** read [calibration.md](references/calibration.md), verify immutable corpora, run
  the helper, inspect and classify findings, compare performance, and refine until clean.
- **Review or promote:** require a separate immutable review commit. Never approve a rule in its
  authoring commit or activate consumers without explicit rollout authorization.

New judgment-heavy rules start as pending warnings. Prefer syntax-aware evidence, emit one
diagnostic per semantic defect, and preserve false negatives when avoiding them would require
guessing. Never infer AI authorship or intent.

The calibration helper is developer-only and is not a shipped CLI:

```bash
uv run python .agents/skills/repo-rule-authoring/scripts/calibrate_rules.py verify \
  --corpus "$PRIVATE_CORPUS"
uv run python .agents/skills/repo-rule-authoring/scripts/calibrate_rules.py evaluate \
  --corpus "$PRIVATE_CORPUS" --rule RULE_ID --fixtures-passed \
  --private-output /private/tmp/rule-private.json \
  --public-output /private/tmp/rule-public.json
```

Do not clone, fetch, install, publish, commit, or mutate consumers unless the user separately
authorizes that action.
