# Proposed repository structure policy

This is the target policy to lint toward, not a command to reorganize every repository at once.
Each component is converted in its source repository before histories are merged.

V1 machine enforcement covers application/library/contract/generated-client/migration/tool paths,
Terraform/Cloud Build/Kubernetes/Cloudflare deployment paths, controlled Sarj products, declared
dependency direction, and narrow capability warnings. Package-name templates, generated
provenance, consumer-count evidence, thin-workflow internals, action pins, and live deployment
state remain guidance/roadmap items; inventory alone does not assert they pass.

```text
applications/<product>/<component>/
libraries/python/<product>/<capability>/
libraries/typescript/<product>/<capability>/
libraries/{python,typescript}/shared/<capability>/
clients/generated/<product>/<api>/<language>/
migrations/<product>/<store>/
deployments/<product>/{terraform,cloud-build,kubernetes,cloudflare}/
tools/{ci,mcp,development}/<capability>/
docs/{architecture,products/<product>,runbooks}/
```

Sarj's controlled product IDs are `platform`, `vb`, and `najm`. Product IDs are policy-pack data,
not engine constants. Another company can supply an open or controlled product registry in its own
policy package.

## Applications and reusable libraries

An application is independently deployable or runnable. Applications do not import another
application's implementation. Shared behavior starts product-owned and is promoted to a library
when a second real consumer exists. It becomes organization-shared only after consumers from at
least two products exist and it imports no product implementation.

Avoid `common`, `core`, `helpers`, `shared`, and `utils` capabilities. Name the cohesive contract:
`request-signing`, `conversation-events`, `phone-normalization`, or similar. A library owns one
public API, tests, release/versioning policy, and dependency direction. Consumers use package
coordinates or declared workspace edges; two workspace roots never co-own the same source tree.

Generated clients are isolated from hand-written libraries. Their generator inputs, output roots,
published coordinates, and generated provenance are declared explicitly. Migration streams are
immutable ordered artifacts under `migrations`, not deployable applications and not generic
`datastores`.

## Toolchain islands

Conversion does not force Python 3.11/3.13/3.14, Yarn, pnpm, and npm projects into one workspace.
Keep one lock per existing install graph until compatibility and package-manager convergence have
their own reviewed migration. A root task dispatcher may invoke each island's frozen checks but
must not silently replace its package manager or lock.

## GitHub Actions

Workflow files stay in `.github/workflows` because GitHub requires that location. Keep them thin:
event/permission declarations, environment selection, concurrency, and calls to pinned reusable
workflows or versioned scripts. Put substantial deterministic logic in `tools/ci/<capability>` so it
is locally testable. Pin third-party actions by full commit SHA, use `contents: read` by default, no
`pull_request_target` for untrusted code, no secrets in PR jobs, and one stable aggregate required
check that fails if any expected lane is absent, skipped, cancelled, or failed.

Every protected branch and merge queue runs the same gate. Preserve workflow/job display names
during repository renames so branch protection does not silently lose required contexts. Artifact
build and publish are separate; publishing uses protected environments, OIDC, attestations, and
immutable source revisions.

## Cloud Build and deployments

Place Cloud Build definitions under
`deployments/<product>/cloud-build/<component>/cloudbuild.yaml`. Keep a small root compatibility
entry point only where an external trigger cannot yet change its path. Docker build contexts,
Terraform roots, Kubernetes/Cloudflare definitions, and service identities are separate declared
coordinates; their names are not derived by global string replacement.

Repository/package migration leaves cloud projects, IAM principals, service accounts, databases,
queues, secrets, runtime services, domains, and telemetry labels unchanged unless a separate
operational migration explicitly covers them. Terraform plans must show no destroy/replace for a
path-only conversion. GitHub OIDC and build triggers are cutover dependencies, not cosmetic names.

## Component conversion gate

For each component:

1. inventory current path, packages/imports, entry points, generated outputs, build context,
   deployment identities, consumers, and owners;
2. choose its final disjoint path and record a path-only migration;
3. preserve package/import/runtime/deployment identities in that wave;
4. update only path-sensitive workspace, CI, Docker, and Terraform references;
5. compare normalized artifacts, imports/exports, tests, lock resolution, generated drift, and
   zero-change infrastructure plans;
6. merge the conversion PR, freeze its SHA, and run a cross-repository collision preflight;
7. merge histories only after every source repository independently passes at its converted tip.

Package renames, toolchain convergence, shared-library extraction, and removal of compatibility
aliases are later waves. Published package names are never treated like reversible directory
renames.
