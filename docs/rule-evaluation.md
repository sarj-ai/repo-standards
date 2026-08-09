# Initial rule evaluation

Status: `ship-warning` for judgment-heavy naming guidance; provisional error for unambiguous
manifest contradictions and declared dependency-boundary violations.

The installed rule catalog is authoritative. Run `repo-lint rules --policy sarj` for every rule's
stable ID, severity, rationale, and positive/negative examples.

No maintained upstream tool owns cross-format repository manifests and declared product topology.
Language import rules remain with Import Linter and dependency-cruiser; this policy consumes only explicit
typed edges and does not duplicate their resolvers.

Labeled tests cover exact positives, minimal negatives, runtime-call near misses, malformed input,
path traversal, fingerprint stability, baseline additions/stale entries, and warning severity. Live
corpus enforcement remains report-only until every match is reviewed and performance is measured.
