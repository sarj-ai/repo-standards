# Organization corpus calibration

The initial private calibration analyzed the default branch of every repository visible in the
`sarj-ai` organization on 2026-08-08. Raw repository names, paths, SHAs, and reports remain in a
permission-restricted temporary directory and are not committed.

## Five loops

1. **Bootstrap smoke:** manifest-only analysis was not actionable for legacy repositories. This
   led to the tracked-files-only `inspect` command.
2. **Active repositories:** all 41 non-empty active repositories were inspected from exact Git
   trees. Forty completed; one failed closed on a non-portable backslash path.
3. **Archived repositories:** all 38 non-empty archived repositories were inspected. Thirty-seven
   completed; one failed closed on a tracked symlink.
4. **Deterministic replay:** all 79 non-empty repositories were scanned again and every report was
   byte-identical. Runtime was observed below 20 seconds on one development host; that is not a
   portable benchmark or release guarantee.
5. **Final release replay:** after API, topology, documentation, packaging, and Standards changes,
   all 79 non-empty repositories were scanned: 76 completed and three reviewed hazards failed
   closed (a backslash path, a tracked symlink, and a bidirectional-control path). All 79 reports
   carried commit/tree provenance and were byte-identical on repeat.

The 80-repository inventory contained one empty repository. The final fail-closed inventory observed
296 Python/npm project manifests, 138 GitHub Actions workflow files, 12 Cloud Build files, 64
Dockerfiles, and 195 Terraform roots. Those are inventory facts, not proof that packages, CI, or
infrastructure are correct. The inspector deliberately makes no registry, package-manager, import,
build, or deployment claim.

## What the corpus changed

- Analysis reads `HEAD` through Git objects rather than trusting a dirty checkout.
- Only bounded inert metadata blobs are parsed; target repository code is never imported.
- Symlinks, submodules, unsafe paths, Unicode/case collisions, malformed metadata, oversized
  inputs, and Git failures remain fail-closed.
- Empty repositories are recorded by fleet orchestration and skipped because they have no tree.
- Asset-heavy repositories can be calibrated with size-filtered bare clones, avoiding multi-GB
  checkouts without weakening path coverage.

This is report-only calibration. No naming or layout rule should become blocking from these
inventory counts alone. Promotion still requires labeled rule fixtures, reviewed matches, zero
known false positives, deterministic output, and an empty or exact shrink-only baseline.
