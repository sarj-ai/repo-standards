# Delivery and CI/CD policy

## Hotfix propagation

When a repository has production, preview, and development branches, a fix merged directly to
production must flow back through every longer-lived integration branch:

```text
production -> preview -> development
```

With conventional names this is `main -> preview -> dev`. The
`sarj/delivery/hotfix-backsync` rule treats both edges as one invariant: implementing only
`main -> preview` or only `preview -> dev` is incomplete.

A conforming implementation uses pull requests and required CI rather than unreviewed direct
pushes. Automation should reconcile on source-branch updates and on a schedule or manual
dispatch, serialize reconciliation without cancelling an in-flight merge, reuse a stable
automation branch or pull request, verify the immutable source commit and pull-request head,
and stop for conflicts instead of resolving them automatically. Guarding against target-head
movement is additionally recommended. For unattended chained
workflows, its credential must be capable of triggering
downstream CI; GitHub's repository `GITHUB_TOKEN` intentionally suppresses most recursively
triggered workflow runs.

The current rule verifies committed workflow structure and live repository governance. When
live evidence is requested, it also verifies that the selected Git revision is the live
default-branch head, preventing a feature or stale branch from being used as proof. It does
not yet prove that the workflow is enabled in Actions or that a recent reconciliation run
succeeded. Those runtime-health checks remain explicitly unverified rather than being inferred
from the presence of YAML.

The current GitHub protection evidence proves that a branch is protected and has required
checks; it does not yet prove that every direct-push bypass is disabled. The rule therefore
establishes guarded PR-based automation, not complete PR-only enforcement of every actor.

## Configuration

Delivery configuration belongs in the inspected repository's normal manifest, usually
`.repo-lint/repository.toml`:

```toml
[delivery]
provider = "github"
repository = "owner/repository"
production_branch = "release"
preview_branch = "staging"
development_branch = "develop"
sync_workflows = [
  ".github/workflows/sync-release-to-staging.yml",
  ".github/workflows/sync-staging-to-develop.yml",
]
```

| Field | Default | Meaning |
| --- | --- | --- |
| `provider` | `"github"` | Delivery host; GitHub is the only supported provider. |
| `repository` | inspected repository | Optional GitHub `owner/name` override. |
| `production_branch` | `"main"` | Production source branch. |
| `preview_branch` | `"preview"` | Intermediate integration branch. |
| `development_branch` | `"dev"` | Development integration branch. |
| `sync_workflows` | `[]` | Repository-relative workflow paths that provide evidence. |

The three branch names must be distinct. Workflow paths identify evidence to inspect; they do
not authorize the linter to install, dispatch, or edit those workflows.

Delivery policy is introduced in Sarj policy version 4. Updating from version 3, or changing
the `[delivery]` table, changes policy applicability and the scope digest. Ratchet baselines
must therefore be regenerated and reviewed rather than copied forward silently.

If `[delivery]` is absent, GitHub inspection activates the rule only when all three conventional
branches exist. If the table is present, its branch names express intent even when external
GitHub evidence is unavailable. An offline run can validate declared configuration and tracked
workflow structure, but it cannot prove branch rules, auto-merge settings, or successful runs;
required facts that cannot be observed remain inconclusive.

## Evidence and conclusions

Delivery diagnostics preserve where each fact came from:

| Evidence level | What it establishes |
| --- | --- |
| `declared` | Intent from `[delivery]` or other trusted repository configuration. |
| `verified` | Structure observed in tracked files from the exact selected Git tree. |
| `external` | Live GitHub branches, rulesets, settings, and required checks. |
| `unknown` | A required fact could not be obtained or safely classified. |

A workflow file is evidence of design, not proof of operation. Passing the critical rule
requires the applicable evidence for both synchronization edges. Authentication failure,
rate limiting, or insufficient token scopes must be reported as
incomplete/inconclusive instead of being converted to a pass.

## Advisory CI/CD rules

The policy also detects high-value practices derived from mature repositories:

- third-party Actions pinned to full commit SHAs;
- explicit non-broad workflow permissions;
- bounded executable jobs and serialized backsync reconciliation;
- lock-enforcing dependency installs for recognized package managers;
- blocking failure semantics for recognized vulnerability scanners;
- `merge_group` coverage when an active merge queue is observed;
- protected long-lived branches and required checks visible to the GitHub evidence token;
- the presence of CODEOWNERS and supported dependency-update configuration.

These judgment-heavy checks begin as warnings. They can be promoted only after corpus
calibration demonstrates deterministic evidence and acceptable false-positive rates. The
hotfix-backsync invariant is the only new delivery rule eligible to be an error initially.

## Non-remediation boundary

The linter reports what is absent or unsafe and provides reviewable remediation steps. It does
not create branches, push commits, open or merge pull requests, resolve conflicts, modify
rulesets, enable auto-merge, dispatch workflows, publish releases, or deploy software. Target
repository code and workflows are never executed during inspection.
