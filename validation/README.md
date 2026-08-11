# Internet-Derived Validation Corpus

A 50-report corpus derived from the public [URLhaus](https://urlhaus.abuse.ch/)
recent CSV feed, used to check that the pipeline handles externally sourced
URL/IOC reports end to end.

**Safety scope:** public CSV metadata only. No malware binaries, no detonation,
no live sample execution. Nothing here is a real payload.

## Regenerating

```bash
python validation/rebuild_corpus.py
```

The original sandbox reports were never checked in, which once made this
snapshot impossible to rebuild. `rebuild_corpus.py` reconstructs them from
`internet_validation_manifest_50.json`, which preserved every input field, so
the corpus is now reproducible **offline** and pinned to the same 50 indicators.
Re-running after a code change shows exactly what that change did.

Useful flags:

| Flag | Effect |
|---|---|
| `--check` | Report counts without writing artifacts |
| `--output DIR` | Write artifacts somewhere else |
| `--keep-inputs DIR` | Also save the reconstructed source reports |

Runs are deterministic: the timestamp is pinned, so two rebuilds are
byte-identical. The script exits non-zero if any rule fails structural
validation.

## Current results

| Metric | Value |
|---|---|
| Reports | 50 |
| Behaviors | 203 |
| IOCs | 156 |
| Sigma rules | 200 |
| Wazuh rules | 200 (200 unique IDs) |
| Structural validation errors | 0 |
| Validation warnings | 40 (advisory) |

The 40 warnings are all `Missing ATT&CK tags`, on rules built from generic IP
connection evidence where no technique maps without application-protocol or
remote-service context. That is the intended conservative behavior, not a
failure.

## Reconstruction fidelity

The rebuilt inputs reproduce the original snapshot exactly on behavior counts,
IOC counts, IOC values, and Sigma/Wazuh rule counts across all 50 reports.

One deliberate difference remains: the original artifacts tagged HTTP behavior
with both `T1071` and its sub-technique `T1071.001`. The bare parent technique
is no longer in `COMMON_ATTACK_MAPPINGS`, so current runs emit only the specific
sub-technique. That is a mapping improvement predating the rebuild, not a
regression.

Regenerating also cleared three defects the old snapshot had baked in:

| Defect in the old snapshot | Status |
|---|---|
| Behavior counts filed under `## Source Data Limitations` (all 50 reports) | fixed |
| `fields:` carrying Sigma modifiers, e.g. `QueryName\|contains` (44 of 200 rules) | fixed |
| Selector values emitted without Sigma escaping | fixed |

## Files

- `rebuild_corpus.py` — regenerates everything below from the manifest
- `internet_validation_manifest_50.json` — per-report input manifest (the source of truth)
- `internet_validation_summary_50.json` / `.md` — aggregate counts, rewritten by each rebuild
- `report_names_and_findings_50.md` — per-report notes from the original run
- `internet_outputs_50/` — the generated artifact tree. Not checked in: it is
  550 reproducible files, so run `rebuild_corpus.py` to materialize it locally.

## Scope

This exercises broad externally sourced URL/IOC report handling. It does not
prove compatibility with every sandbox/vendor schema, and it is not a substitute
for validating rules against a real Sigma backend or Wazuh manager.
