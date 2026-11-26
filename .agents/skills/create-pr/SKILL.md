---
name: create-pr
description: Open feature PRs with one commit and follow the repository's configured description policy.
---

1. Before opening a feature PR, confirm no open or closed PR already uses the
   branch. Fetch its exact target and current remote head. On a clean trusted
   checkout, run the installed, pinned owner command (inside the repository's
   normal check supervisor when required):

   ```bash
   repo-standards pull-request prepare . --base origin/<target> --message "type: concrete outcome" --trust-repository-code
   ```

   This is the PR-opening standard: publish one commit before creating the PR,
   including drafts. Do not bypass native hooks. Stop on incomplete preparation
   or changed hook output, review preserved edits, and rerun applicable checks.
   The command never pushes. Keep promotion, release, sync and existing-PR
   histories intact. Do not squash during pre-push hooks or after the PR exists.
2. Verify the prepared tree equals the reviewed tree and the PR range has exactly
   one commit. If the branch was already pushed, ensure the fetched remote head
   is an ancestor of the recorded original local head; otherwise stop and
   reconcile other work. Push with an explicit lease on that exact remote SHA
   (`--force-with-lease=refs/heads/<branch>:<remote-sha>`). For a new remote branch,
   use an empty expected lease to avoid overwriting a concurrent creation.
   Preserve pre-push hooks. Verify the remote SHA matches the prepared head.
3. Follow the repository's current template and trusted base review policy.
   For commit subjects and PR titles, name the concrete outcome:
   `fix: preserve retry limit after reconnect`, rather than `fix: enhance retry robustness`.
   Add a commit body only for useful rationale or required trailers. In the PR
   body, explain the problem and resulting behavior, then relevant validation
   and material caveats. Link detailed evidence; omit task diaries, repeated
   summaries and generic claims such as "comprehensive improvements". Scale
   detail to the change; preserve required sections and breaking-change guidance.
   Run [merge-risk](../merge-risk/SKILL.md) when `Merge Risk` is required (the
   default). Under that heading, copy only the skill's overall rating and five
   category verdicts, preserving their words and emojis. If the repository sets
   `require_merge_risk = false` and omits that heading from its required sections,
   omit it. Keep material caveats in the repository's remaining sections.
4. Create the PR only after preparation and push succeed. For an existing PR,
   update its description and evidence without repeating the opening squash.
   Refresh any required assessment when scope or evidence changes. Reuse valid
   check receipts for reviews and votes; repeat checks only for changed inputs,
   failures or a concrete unresolved risk, retaining every required gate.
