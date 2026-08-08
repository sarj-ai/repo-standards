# Initial rule evaluation

Status: `ship-warning` for judgment-heavy naming guidance; provisional error for unambiguous
manifest contradictions and declared dependency-boundary violations.

## Rule problems

| Rule family | Observable pattern | Harm | Non-goals |
|---|---|---|---|
| Component roots | One declared root contains another | Ambiguous ownership and affected analysis | Detecting semantic duplication |
| Component paths | A non-legacy declaration conflicts with the selected policy template | Conversion and merge targets drift | Renaming imports, packages, cloud resources, or historical paths |
| Application imports | Declared source/package edge between applications | Prevents independent implementation release | Runtime API calls |
| Cross-product imports | Product code imports another product's implementation | Hidden ownership and release coupling | Shared contracts and runtime calls |
| Shared imports | Shared library imports product code | Reversed dependency direction and false reuse | Product code consuming shared code |
| Vague capability | Reusable asset declares `common`, `core`, `helpers`, `shared`, or `utils` | Dependency-magnet risk | Guessing a replacement name or forcing extraction |

No maintained upstream tool owns cross-format repository manifests and declared product topology.
Language import rules remain with Import Linter and dependency-cruiser; V1 consumes only explicit
typed edges and does not duplicate their resolvers.

Labeled tests cover exact positives, minimal negatives, runtime-call near misses, malformed input,
path traversal, fingerprint stability, baseline additions/stale entries, and warning severity. Live
corpus enforcement remains report-only until every match is reviewed and performance is measured.
