# Architecture

## Trust boundary

The analyzer parses explicitly selected TOML and JSON only. It does not import target modules,
execute configuration, run Git hooks, invoke language tools, load repository plugins, or follow an
input file outside the selected repository root.

The company-neutral engine owns parsing contracts, canonicalization, exact fingerprints, analysis
modes, baselines, and rendering. Installed policy packages own organization vocabulary and rules.
Core has no default policy and no product names.

## Entity and edge model

Repository manifests declare stable components. A path is evidence about a component; it is not
the component's identity. That separation lets an explicit old-to-new path mapping preserve finding
identity during a physical migration.

Dependencies are typed because source imports, build inputs, runtime calls, generated artifacts,
data ownership, and deployment ordering have different safety implications. Policies evaluate only
the relevant edge types instead of treating every relationship as source coupling.

## Sarj policy

Sarj currently controls the product IDs `platform`, `vb`, and `najm`. Application implementation is
component-owned under `products/<product>/components/<component>`. Product libraries have separate
release/consumer boundaries. Cross-product runtime services belong to `foundation`; non-deployable
cross-product libraries and contracts belong to `shared`.

The policy is explicit data and installed code, not a core default. A future adopter can replace it
with a different policy without forking the engine.

## Deliberate V1 limits

V1 validates declared repository facts. It does not attempt to replace Import Linter,
dependency-cruiser, Terraform, GitHub, or cloud control planes. Later adapters may ingest their
deterministic outputs, but operational evidence remains separate from static declarations.
