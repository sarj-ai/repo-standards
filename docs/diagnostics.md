# Diagnostics for humans and LLMs

Each diagnostic has a stable namespaced rule ID, semantic rule version, fingerprint, severity,
evidence level, component, subject kind, observed/expected values, repository-relative location,
manifest anchor, prerequisites, and structured remediation.

Fingerprints exclude messages, absolute paths, line offsets, timestamps, usernames, and tool
versions. They include the normalized observed and expected identity, so a changed occurrence is
visible rather than being silently treated as the same evidence.

Baselines bind to a policy-scope digest rather than the mutable component inventory. Adding,
removing, or moving components therefore remains analyzable: new semantic fingerprints are debt
and resolved fingerprints are stale. The current policy validates migration mappings but does not preserve
finding identity across a move or attach Git-tree and operational evidence to diagnostics.

Remediation is deliberately non-executable. It includes ordered actions, validation expectations,
and no shell commands or repository mutation. The capability contract declares `autofix: false`.
