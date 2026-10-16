# Rule anatomy

Define the observable defect, harm, exact evidence, non-goals, exclusions, bad and good examples,
and strongest safe remediation before coding. Search the owning upstream linter and current catalog;
record why configuration or an existing rule is insufficient.

Write executable cases for exact positives, negatives, near misses, nesting, generated content,
malformed input, duplicate diagnostics, suppression, and nearby-rule precedence. A public rule needs
one immutable ID and version, warning-first governance, catalog slug, classification, evidence level,
precedence, executable examples, and a separate approval review.

Each case must reject a named wrong outcome or preserve a distinct boundary, compatibility,
suppression, or precedence contract. Build rejected-input cases from otherwise-valid evidence and
introduce one defect unless combinations or rejection precedence are the contract. Use sparse
tables for the same action and oracle; retain fixture, order, runtime, and case-mark distinctions.
Integration cases must exercise the actual boundary they
claim to cover; a fake cannot establish its real collaborator's contract. Reuse sufficient cases
before adding more. Before removing or relocating a check, show that retained coverage rejects the
same wrong outcomes; passing runs and coverage counts alone do not establish equivalence.

Implementation and metadata changes require a package minor bump for new rules and a policy-version
bump when manifest behavior changes. Do not add generated README, changelog, summary, or handoff files.
No autofix is permitted unless semantic preservation and second-pass convergence are proven.
