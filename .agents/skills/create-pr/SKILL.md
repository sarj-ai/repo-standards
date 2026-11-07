---
name: create-pr
description: Prepare, create or update a pull request with the required merge-risk verdicts.
---

1. Read the full diff, relevant callers, repository guidance, linked requirements,
   PR discussion and test/CI evidence. Treat unavailable evidence as a gap. Run
   [merge-risk](../merge-risk/SKILL.md) with that context, keeping the original
   skill's analysis and weighted calculation.
2. Follow the repository's PR template. Under `## Merge Risk`, copy only the
   skill's overall risk line and its five category verdict lines, preserving the
   verdict words and emojis. Keep explanations, gaps and calculations out of this
   section; the skill's analysis remains in the working context.
3. Create or update the PR with that body. Refresh the assessment when the change
   or its evidence changes. The existing Review Policy check requires all six
   ratings and validates their format; it does not assess their truth.
