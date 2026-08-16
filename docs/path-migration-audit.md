# Path migration audit protocol

This checklist turns a repository relocation into a sequence of independently
reversible, exact-tree changes. It applies to path migrations declared in
`.repo-lint/repository.toml`; it does not authorize runtime identity changes.

## Rule problem

The observable bad pattern is a declared old-to-new component path where the
selected Git tree does not contain the target, still contains undeclared files
under the source, drops a relocated package from a native workspace, tracks
generated install outputs, or batches multiple independently reversible moves.
These states can skip installs, builds, tests, ownership checks, and CI or make
review and rollback unbounded while the manifest itself remains syntactically
valid.

The rules intentionally do not infer source dependencies, runtime identities,
or desired compatibility from names. They do not execute repository code,
inspect untracked files, require every package to be a workspace member, or
forbid a separately declared compatibility component.

Native package-manager validation can detect some broken workspace declarations
after installation. It cannot join a reviewed migration source to its target in
one immutable Git tree. No existing core or Sarj rule performs that comparison;
`core/layout/non-overlapping-root` only checks declared ownership roots.

## Adversarial checklist

Before each move:

- Record the exact base commit, component ID, source, target, owner, package and
  import names, build entrypoints, deploy artifact names, and persistent runtime
  identifiers.
- Require a clean disposable worktree and one component move per commit.
- Confirm the source is selected by every relevant workspace, build context,
  CI path filter, code generator, deployment trigger, and ownership rule.
- Capture native lockfiles and immutable artifact identifiers before relocation.

On the candidate commit:

- Require `core/migration/batch-too-large` to be absent. One declared component
  move per exact tree is the default bounded review and rollback slice; a larger
  orchestration must be decomposed into a reviewed sequence.
- Require `core/migration/tracked-install-artifacts` to be absent. Track native
  lockfiles, but never `node_modules/**` or `.yarn/install-state.gz`; one
  accidental install can otherwise add tens of thousands of platform-specific
  files to a mechanical relocation.
- Require `core/migration/target-missing` to be absent.
- Inspect every `core/migration/source-retained` match; declare a real
  compatibility component rather than silently sharing an ownership root.
- Require `core/migration/workspace-membership-lost` to be absent, then run the
  native package manager's immutable install and complete workspace build/test.
- Search the exact committed tree for the literal old path in workflow, build,
  deployment, ownership, code-generation, documentation, and tool configuration.
- Compare dependency-boundary scan coverage before and after the move. Zero
  scanned files is incomplete evidence, not a pass.
- Compare package names, import roots, executable entrypoints, container image
  names, service accounts, cloud resources, database/migration identities,
  queues/topics, metrics, secrets, state backends, and deployment targets. A
  path-only change must not alter them.
- Build immutable artifacts before and after the move and compare their public
  metadata and entrypoints. Rehearse rollback using the previous artifact.

After merge, remove a `migration_paths` entry only when the old root has no
tracked files or references, all consumers use the target, native workspace and
dependency scans cover the same units, and the rollback observation window has
closed.

## Deferred deterministic evidence

Three useful rules require a bounded two-tree adapter and are deliberately not
implemented from insufficient evidence:

- `stale-old-path-reference`: scan parser-classified text/config blobs at the
  candidate tree while excluding the manifest's own `from` value; report exact
  locations and distinguish executable configuration from prose.
- `dependency-scan-coverage-regressed`: ingest a typed boundary-scanner summary
  for both commits and compare component file counts, exclusions, and parsed
  dependency edges. Empty declarations alone do not prove missing scans.
- `runtime-identity-changed`: compare typed package, entrypoint, deployment,
  Terraform plan, migration-history, and artifact metadata across base and
  candidate commits. Names in source text are not sufficient evidence.

The adapter must use immutable commit IDs, bounded parser-backed inputs, exact
locations, and explicit incomplete results when either side lacks evidence.
