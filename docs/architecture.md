# Architecture

## Trust boundary

Manifest analysis parses explicitly selected TOML and JSON. Inspection also invokes the trusted
Git executable from the tool environment with fixed arguments and replacement objects disabled.
Neither path imports target modules, executes configuration, runs Git hooks, invokes package
managers/language tools, loads repository plugins, or follows an input outside the selected tree.

The company-neutral engine owns parsing contracts, canonicalization, exact fingerprints, analysis
modes, baselines, and rendering. Installed policy packages own organization vocabulary and rules.
Core has no default policy and no product names.

## Entity and edge model

Repository manifests declare stable components. A path is evidence about a component; it is not
the component's identity. Finding identity is keyed to its component and semantic manifest anchor,
not current observed path text. V1 old-to-new mappings validate a unique, non-no-op target mapping;
the richer evidence/plan semantics described in the roadmap are not implemented yet.

Dependencies are typed because source imports, build inputs, runtime calls, generated artifacts,
data ownership, and deployment ordering have different safety implications. Policies evaluate only
the relevant edge types instead of treating every relationship as source coupling.

## Sarj policy

Sarj currently controls the product IDs `platform`, `vb`, and `najm`. Application implementation is
component-owned under `applications/<product>/<component>`. Product libraries live under
`libraries/<language>/<product>/<capability>`; only proven multi-product libraries use the
`shared` product segment. Generated clients, deployments, contracts, tools, and ordered database
migrations have distinct top-level roots. Migrations use `migrations/<product>/<store>` and are not
misclassified as deployable applications or generic datastores.

The policy is explicit data and installed code, not a core default. A future adopter can replace it
with a different policy without forking the engine.

## Deliberate V1 limits

V1 validates declared repository facts. It does not attempt to replace Import Linter,
dependency-cruiser, Terraform, GitHub, or cloud control planes. Later adapters may ingest their
deterministic outputs, but operational evidence remains separate from static declarations.
