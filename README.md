# MalForge

[![CI](https://github.com/rootverdict/MalForge/actions/workflows/ci.yml/badge.svg)](https://github.com/rootverdict/MalForge/actions/workflows/ci.yml)

Local malware behavior to detection-rule pipeline for sandbox JSON reports. The project parses Cuckoo, CAPE, and ANY.RUN reports, extracts behavior, maps to MITRE ATT&CK, generates Sigma rules, converts them to Wazuh XML, scores and validates output, creates synthetic test events, and builds analyst-facing reports.

## Safety

This project uses sandbox JSON reports only. It does not execute malware, launch samples, make enrichment network calls, or deploy rules to Wazuh. VirusTotal and MISP settings currently create local request descriptors only.

## Features

- Parse Cuckoo, CAPE, and ANY.RUN JSON reports
- Normalize report artifacts into a common schema
- Extract process, registry, file, network, and persistence behaviors, plus behaviors implied by sandbox signatures
- Extract local IOCs from normalized reports and behavior evidence
- Map behaviors to MITRE ATT&CK techniques and generate ATT&CK Navigator layers
- Generate Sigma rules and convert them to Wazuh rules and XML
- Match Windows Wazuh rules beneath their corresponding Sysmon EventChannel parent rule or group
- Preserve non-reused Wazuh ID assignments through a persistent local registry in sequential, single-writer runs
- Validate generated rules and assign heuristic risk scores
- Generate safe synthetic positive and negative test events
- Apply local review metadata and deterministic version metadata
- Trace every generated rule back to its source behavior, evidence, and ATT&CK IDs
- Match URL and domain IOCs against a local URLhaus CSV export, without downloading it
- Build JSON summaries and Markdown reports
- Run single-report and batch pipelines from the CLI

## Architecture Flow

```text
Sandbox JSON
  -> Ingestion
  -> Normalized Report
  -> Behavior Extraction
  -> IOC Extraction
  -> ATT&CK Mapping
  -> Navigator Layer
  -> Sigma Generation
  -> Wazuh Conversion
  -> Validation + Risk Scoring + Test Events
  -> Review + Version Metadata
  -> Summary + Markdown Report
  -> Optional write to output/
```

## Folder Structure

```text
core/         Shared models, schema helpers, and orchestration
ingestion/    Sandbox-specific JSON normalization
extractor/    Behavior extraction
ioc/          IOC extraction
attck/        ATT&CK mapping and Navigator layer generation
generators/   Sigma rule generation
converters/   Wazuh rule conversion and XML rendering
quality/      Validation, scoring, and synthetic test events
review/       Review metadata and version stamping
reporting/    JSON summaries and Markdown reporting
enrichment/   Offline enrichment helpers, no network calls
samples/      Safe example sandbox reports
tests/        Unit and pipeline coverage
output/       Generated local artifacts
```

## Setup

Requirements:

- Python 3.11 or newer

Windows PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

To install the packaged `malforge` command, run `python -m pip install .` from the repository root. Runtime needs only `PyYAML`; use `python -m pip install ".[dev]"` to also pull in `pytest` for the test suite.

If `pytest` is not on your shell `PATH`, use `python -m pytest`.

## Usage

Single report:

```bash
python main.py --report samples/cuckoo_sample.json --sandbox auto --output output
```

Batch mode:

```bash
python main.py --input-dir samples --sandbox auto --output output
```

No-write mode:

```bash
python main.py --report samples/cuckoo_sample.json --sandbox auto --no-write
```

Verbose mode:

```bash
python main.py --report samples/cuckoo_sample.json --sandbox auto --output output --verbose
```

Offline enrichment:

```bash
python main.py --report samples/cape_sample.json --enrich --urlhaus-csv /path/to/urlhaus.csv
```

Custom Wazuh ID range:

```bash
python main.py --report samples/cuckoo_sample.json --wazuh-id-start 130000 --wazuh-id-end 139999
```

The full option list is in [`docs/usage.md`](docs/usage.md) and [`RUNBOOK.md`](RUNBOOK.md).

## Output Files

The pipeline writes only under `output/`:

- `output/sigma/*.yml` or `*.json`
- `output/wazuh/*.xml`
- `output/test_events/*.json`
- `output/reports/*_report.md`
- `output/reports/*_summary.json`
- `output/iocs/*_iocs.json`
- `output/iocs/*_iocs.txt`
- `output/navigator/*_navigator_layer.json`

Every artifact basename contains a 12-character canonical source-report fingerprint, which prevents routine overwrites when reports share a sample name. `output/wazuh/.rule_ids.json` preserves stable Wazuh IDs across sequential single-report and batch runs. Keep this registry with the output set, do not deploy it as a Wazuh rule file, and allow only one process at a time to write a given output directory.

## Testing

```bash
python -m pytest
python -m compileall -q attck converters core enrichment extractor generators ingestion ioc quality reporting review tests main.py
make test
```

## VM Lab Note

Suggested lab layout for a portfolio demo:

- `Dev VM`: runs this project and processes sandbox JSON reports
- `Wazuh VM`: receives generated XML only in later manual lab stages
- `Windows 10 endpoint`: source of log format assumptions such as Sysmon-style process, file, registry, and network telemetry

Generated Wazuh rule `116767` fired successfully in the lab from a Windows endpoint Sysmon Event ID `1` using parent rule `61603`.

The current project does not automate any deployment to those systems.

## Internet-Derived Validation

A 50-report validation corpus derived from the public URLhaus recent CSV feed. This used public URL/IOC metadata only: no malware binaries, no detonation, and no live sample execution.

The corpus is reproducible offline and pinned to the same 50 indicators, so re-running it after a code change shows exactly what changed:

```bash
python validation/rebuild_corpus.py
```

Current result:

- Input reports: 50
- Successful CLI runs: 50
- Failed CLI runs: 0
- Markdown reports generated: 50
- Sigma rules generated: 200
- Wazuh rules generated: 200 (200 unique IDs)
- Structural validation errors: 0
- Validation warnings: 40 (advisory `Missing ATT&CK tags` on generic IP-connection rules)

Two rebuilds are byte-identical, and the script exits non-zero if any rule fails structural validation.

Evidence files, with reconstruction details in [`validation/README.md`](validation/README.md):

- `validation/rebuild_corpus.py`
- `validation/internet_validation_manifest_50.json`
- `validation/internet_validation_summary_50.json`
- `validation/internet_validation_summary_50.md`

This validates broad externally sourced URL/IOC report handling. It does not prove compatibility with every possible sandbox/vendor schema.

The URLhaus validation set also includes a Mozi `elf/mips` sample-style report. For that case the pipeline now emits Linux/generic telemetry rules instead of Windows/Sysmon rules, preserves raw IP values as generic network evidence without forcing an application-protocol or Remote Services mapping, preserves direct HTTP URL evidence as web-protocol behavior, tags non-standard ports with T1571, and reports missing payload hashes as source-data limitations when URL-only metadata does not include MD5/SHA1/SHA256 values.

## Current Limitations

- VirusTotal and MISP enrichment modules build local descriptors but do not make API calls
- The CLI requires `PyYAML`; Sigma output is YAML in normal installs. The lower-level output helper can fall back to JSON only if reused without `PyYAML`.
- ATT&CK mapping targets ATT&CK 19.1 and remains intentionally rule-based. Techniques use the v19 `Stealth` (TA0005) and `Defense Impairment` (TA0112) tactics that replaced `Defense Evasion`, so Navigator layers require a v19-aware Navigator build.
- Validation and risk scoring are heuristic, not vendor-native validation engines. Rules are not checked against `pysigma` or the Wazuh rule tester.
- Sigma selectors are derived from single evidence values, so command-line selectors stay sample-specific and are not generalized into behavioral patterns
- Synthetic test events are local JSON-like dictionaries only. Negative events are constructed not to collide with the observed value, but they are not executed against a rule engine.
- Pipeline output writing currently targets local files only
- Only `paths.output_dir`, `wazuh.*`, and `integrations.*` in `config.yaml` are read; output subdirectory names are fixed by the pipeline

## Roadmap

Version boundaries are tracked in [`docs/version_scope.md`](docs/version_scope.md). V1 is intentionally limited to the safe local CLI pipeline; V2 collects practical analyst workflow improvements after that base is stable.

- Enable IOC enrichment with optional local/offline caching
- Expand ATT&CK mapping depth and confidence tuning
- Improve Sigma selector fidelity and rule grouping
- Add optional Wazuh deployment packaging and manager-side validation
- Export consolidated pipeline manifests
- Add automated release and artifact publishing

## License

MalForge is released under the [MIT License](LICENSE).



