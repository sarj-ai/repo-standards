# Security

Report undisclosed vulnerabilities privately through the
[GitHub security advisory form](https://github.com/sarj-ai/repo-standards/security/advisories/new).
Do not include secrets or customer data in public issues.

The default branch and latest published release receive security fixes.
Maintainers aim to acknowledge reports within two business days, investigate
confirmed issues, and coordinate a fix and disclosure with the reporter.
Release notes identify fixed, publicly disclosed vulnerabilities and their
advisory identifiers when available.

## Open source assurance programme

This programme covers reviewed source and package distributions of
[Repo Standards](https://github.com/sarj-ai/repo-standards) and
[Code Standards](https://github.com/sarj-ai/code-standards), including their locked
Python dependencies and bundled npm components. Each admitted version receives
a recorded review from 2026-11-27 onward. Separately downloaded analysis engines,
downstream consumer environments and other company products are outside this scope.
Repository maintainers own the programme, release approval, security triage and
the programme's evidence records.

### Responsibilities and competence

Release owners must understand license grants, attribution, source and binary
distribution, modified components, integration and incompatible obligations.
Security owners must understand dependency inventories, scanner results,
exploitability, severity, remediation and coordinated disclosure. Maintainers
record participants, assigned roles, assessed competence, policy awareness and
available resources in the programme review record. Resolve unfamiliar legal
obligations with designated legal expertise before approving distribution.

### Review and release

For each release, retain its source revision, dependency lockfiles, component
names and versions, origins, integrity hashes, licenses, modifications, review
decisions and required notices. Review new and changed components for rights,
restrictions and obligations in their actual integration and distribution form.
Unresolved license compatibility or redistribution questions block approval.
Preserve upstream attribution and include applicable license texts and notices
in source and binary artifacts. REUSE checks file licensing; it does not replace
this compatibility review.

Run the repository's required tests, static analysis and dependency audits before
release. Triage confirmed vulnerabilities by exploitability and severity, record
the remediation or justified disposition, and verify the fix before release.
Scheduled CI and dependency monitoring check for newly disclosed vulnerabilities
after release. Publish warranted notices through security advisories and release
notes, including affected versions, impact, fixes and available mitigations.

Keep component records, compliance artifacts, decisions and supplied release
artifacts for at least three years after the last distribution, and longer when
the applicable license requires it. Preserve the records in release archives and
maintainer-controlled programme records.

### Inquiries, contributions and review

Use [public issues](https://github.com/sarj-ai/repo-standards/issues) for licensing
and component inquiries, and the private reporting form above for vulnerabilities.
Maintainers record inquiries, acknowledge them, investigate, obtain specialist
review where needed, and track corrective action through resolution.

Contributions use reviewed pull requests and the repository's AGENTS instructions.
Contributors must have the right to supply their changes, retain upstream notices,
identify new dependencies and license obligations, and add tests for new behavior.
Maintainers communicate this policy during contribution and release review.

Review the programme at least every 18 months and after material changes to scope,
staffing or process. Record the review date, participants, competency and awareness
assessment, resources, license findings, vulnerability dispositions, audit results,
corrective actions and approval. Track inquiry response times, unresolved licensing
questions, known-vulnerability age and release-check outcomes. Any conformance
statement must identify its standard, scope, evidence and review date.

### Initial security assurance review

The 2026-11-27 review assigns programme ownership, component review, release
approval, security triage and evidence retention to the maintainer `nmaswood`.
The participant confirmed the stated competence, policy awareness and available
maintainer time and CI resources. This is a programme role record, not a claim
that the repositories have only one contributor.

Maintainer-controlled records retain dependency archives, source revisions,
lockfiles, artifact digests, scanner findings and dispositions. The initial
inventory contains 94 Python component records backed by 61 unique verified
archives, and 123 bundled npm source archives. Runtime dependency audits,
required CI and the published security-reporting process support follow-up.
Conformance review uses the OpenChain ISO/IEC 18974 checklist for this scope;
it does not certify the entire company or every downstream installation.
