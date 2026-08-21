# Calibration protocol

Use exact committed Git trees. Private source paths and sidecar manifests belong only in a regular,
non-symlink JSON overlay with mode `0600`. The shareable report may contain only aggregate private
counts under `<private-corpus>`; never include private names, paths, snippets, pins, hashes, or
per-repository counts.

Classify inspected findings as `tp`, `fp`, or `unclassified`. Inspect every hit when feasible;
otherwise select by a documented hash-ranked seed. Zero findings is not correctness evidence, so
seed executable positive and negative fixtures. Any FP, fixture miss, duplicate location, partial
analysis, nondeterminism, privacy failure, or unexplained performance regression means `revise`.

Run each source in a fresh process without executing repository code. Record selected files/bytes,
elapsed time, duplicate locations, exclusions, blind spots, and exact reproduction commands. Compare
cold and warm candidate runs with the same runner and corpus baseline. A new judgment-heavy rule may
be recommended only as `ship-warning`; promotion is a later reviewed release.

Corpus JSON shape:

```json
{
  "schema_version": 1,
  "sources": [
    {
      "report_name": "<private-corpus-01>",
      "visibility": "private",
      "path": "/absolute/local/repository",
      "commit": "40-character commit",
      "manifest_path": "/absolute/0600/sidecar.toml"
    }
  ]
}
```

After inspecting the private report, write a separate `0600` classification ledger and rerun with
`--labels /absolute/private/labels.json`:

```json
{"schema_version": 1, "labels": {"finding-sha256": "tp"}}
```

Every live finding must be labeled `tp` or `fp`; unknown findings and stale labels fail closed.
