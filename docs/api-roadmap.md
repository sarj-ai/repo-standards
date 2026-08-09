# LLM-first API and migration roadmap

The product remains a hermetic CLI and typed library for now. A network microservice would add
authentication, source-upload, tenancy, retention, and availability risks without improving local
analysis. A future fleet service may store signed reports; it must not become the authoritative
analyzer.

## Stable V1 direction

Every machine command should eventually return one versioned envelope with:

- `completion` separate from `conclusion`;
- exact input revision, tree/manifest/policy digests, and dirty-state provenance;
- structured execution issues with stable code, phase, location, retryability, and remediation;
- typed diagnostics with rule metadata, evidence, affected components, semantic finding ID, and
  current occurrence/evidence digest;
- explicit ratchet classification (`new`, `known`, `resolved`, `excepted`);
- bounded `next_actions` and non-executable migration guidance;
- producer, policy API, ruleset, manifest schema, and report protocol versions.

Human text, canonical JSON, SARIF, and a future MCP adapter must be projections of that single
model. Machine formats keep stdout pure; operational logs use stderr. Incomplete analysis always
exits 2—even in advisory/report mode.

## Recommended command surface

```text
repo-lint inspect ROOT
repo-lint report ROOT
repo-lint check ROOT [--baseline PATH]
repo-lint plan ROOT [--component ID]
repo-lint diff BEFORE_REPORT AFTER_REPORT
repo-lint doctor ROOT
repo-lint capabilities
repo-lint rules [--policy ID]
repo-lint explain RULE_ID [--policy ID]
repo-lint schema DOCUMENT [--version N]
```

`report` never blocks on policy findings. `check` does. Both fail on incomplete coverage. The public
surface should remove the ambiguous `check --mode report` shape before a stable release.

## Piecemeal convert-then-merge

Migration units are component-scoped and content-addressed. Each records source/target paths,
identities that must remain stable, dependency closure, expected changed paths, preconditions,
validation evidence, rollback, and merge blockers. State is derived from observed evidence rather
than self-declared as complete.

The safe sequence is:

1. inspect and classify every component;
2. establish its final disjoint target path and compatibility commitments;
3. convert one repository/component at a time while preserving package/import/runtime identities;
4. attach a deterministic before/after evidence report to its PR;
5. preflight all converted repository tips together for path, package, import, migration-stream,
   workflow, and deployment collisions;
6. merge histories only after every independently converted tip passes;
7. converge toolchains, packages, and remove aliases in later waves.

The linter remains read-only. A generator is appropriate later only for manifest skeletons,
baseline deletion, and explicit plan files. It must write only with an explicit output flag, never
move code or perform global replacement, and must emit a reviewable plan before any mutation.

## Generalization boundary

The core engine and neutral CLI must not contain Sarj product names. Installed, trusted policy
packages supply organization vocabulary through a versioned policy API. Sarj's policy controls
`platform`, `vb`, and `najm`; another company can install a different policy without forking core.
Plugins are loaded only from the pinned tool environment—never from the repository being analyzed.

The current prototype includes a deterministic policy registry, explicit package compatibility
bounds, artifact-level installation tests, a report schema, structured issue types, and a
capabilities handshake. Before publishing a stable API, add a high-level
`check_repository(request, registry)` facade, independently versioned schemas for every command,
SARIF, and bounded report querying. MCP should be a thin adapter after those contracts stabilize.
