# Diagnostics for humans and LLMs

Each diagnostic has a stable namespaced rule ID, semantic rule version, fingerprint, severity,
evidence level, component, subject kind, observed/expected values, repository-relative location,
manifest anchor, prerequisites, and structured remediation.

Fingerprints exclude messages, absolute paths, line offsets, timestamps, usernames, and tool
versions. Message improvements and physical moves therefore do not manufacture new debt when the
component and semantic construct are unchanged.

Baselines bind to a policy-scope digest rather than the mutable component inventory. Adding,
removing, or moving components therefore remains analyzable: new semantic fingerprints are debt,
resolved fingerprints are stale, and explicit migration mappings preserve intended move context.

Remediation is deliberately non-executable. It includes ordered actions, validation expectations,
rollback considerations, and an optional manifest fragment. V1 always emits
`auto_applicable: false`; consumers must not turn suggestions into shell commands without review.

For bounded LLM context, begin with `summary`, then select diagnostics by `rule_id`, `component_id`,
or fingerprint. The canonical JSON contract makes it unnecessary to parse human prose to learn the
verdict, evidence level, prerequisites, or next safe step.
