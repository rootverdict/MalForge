# MalForge

[![CI](https://github.com/rootverdict/MalForge/actions/workflows/ci.yml/badge.svg)](https://github.com/rootverdict/MalForge/actions/workflows/ci.yml)

Local malware behavior to detection-rule pipeline for sandbox JSON reports. The project parses Cuckoo, CAPE, and ANY.RUN reports, extracts behavior, maps to MITRE ATT&CK, generates Sigma rules, converts them to Wazuh XML, scores and validates output, creates synthetic test events, and builds analyst-facing reports.

## Safety

This project uses sandbox JSON reports only. It does not execute malware, launch samples, make enrichment network calls, or deploy rules to Wazuh. VirusTotal and MISP settings currently create local request descriptors only.

## Features

- Parse Cuckoo, CAPE, and ANY.RUN JSON reports
- Normalize report artifacts into a common schema
- Extract process, registry, file, network, and persistence behaviors
- Extract local IOCs from normalized reports and behavior evidence
- Map behaviors to MITRE ATT&CK techniques and generate ATT&CK Navigator layers
- Generate Sigma rules and convert them to Wazuh rules and XML
- Match Windows Wazuh rules beneath their corresponding Sysmon EventChannel parent rule or group
- Preserve non-reused Wazuh ID assignments through a persistent local registry in sequential, single-writer runs
- Validate generated rules and assign heuristic risk scores
- Generate safe synthetic positive and negative test events
- Apply local review metadata and deterministic version metadata
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
samples/      Safe example sandbox reports
tests/        Unit and pipeline coverage
output/       Generated local artifacts
```

## Setup

```bash
python3 -m pip install --user -r requirements.txt --break-system-packages
```

To install the packaged `malforge` command, run `python3 -m pip install .` from the repository root.

If `pytest` is not on your shell `PATH`, use `python3 -m pytest`.

## Usage

Single report:

```bash
python3 main.py --report samples/cuckoo_sample.json --sandbox auto --output output
```

Batch mode:

```bash
python3 main.py --input-dir samples --sandbox auto --output output
```

No-write mode:

```bash
python3 main.py --report samples/cuckoo_sample.json --sandbox auto --no-write
```

Verbose mode:

```bash
python3 main.py --report samples/cuckoo_sample.json --sandbox auto --output output --verbose
```

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
python3 -m pytest
python3 -m compileall .
make test
```

## VM Lab Note

Suggested lab layout for a portfolio demo:

- `Dev VM`: runs this project and processes sandbox JSON reports
- `Wazuh VM`: receives generated XML only in later manual lab stages
- `Windows 10 endpoint`: source of log format assumptions such as Sysmon-style process, file, registry, and network telemetry

Generated Wazuh rule `116767` fired successfully in the lab from `MBDG-Win10` Sysmon Event ID `1` using parent rule `61603`.

The current project does not automate any deployment to those systems.

## Internet-Derived Validation

A historical 50-report validation corpus was generated from the public URLhaus recent CSV feed. This used public URL/IOC metadata only: no malware binaries, no detonation, and no live sample execution. The checked-in artifact snapshot predates the persistent ID registry and fingerprinted filename format; use a fresh pipeline run for deployable content.

Validation result:

- Input reports generated: 50
- Successful CLI runs: 50
- Failed CLI runs: 0
- Markdown reports generated: 50
- Sigma rules generated: 200
- Wazuh rules generated: 200
- Validation warnings: 0

Evidence files:

- `validation/internet_validation_manifest_50.json`
- `validation/internet_validation_summary_50.json`
- `validation/internet_validation_summary_50.md`

This validates broad externally sourced URL/IOC report handling. It does not prove compatibility with every possible sandbox/vendor schema.

The URLhaus validation set also includes a Mozi `elf/mips` sample-style report. For that case the pipeline now emits Linux/generic telemetry rules instead of Windows/Sysmon rules, preserves raw IP values as generic network evidence without forcing an application-protocol or Remote Services mapping, preserves direct HTTP URL evidence as web-protocol behavior, tags non-standard ports with T1571, and reports missing payload hashes as source-data limitations when URL-only metadata does not include MD5/SHA1/SHA256 values.

## Current Limitations

- VirusTotal and MISP enrichment modules build local descriptors but do not make API calls
- Sigma output uses YAML only if `PyYAML` is available; otherwise JSON fallback is used
- ATT&CK mapping targets ATT&CK 19.1 and remains intentionally rule-based
- Validation and risk scoring are heuristic, not vendor-native validation engines
- Synthetic test events are local JSON-like dictionaries only
- Pipeline output writing currently targets local files only

## Roadmap

- Enable IOC enrichment with optional local/offline caching
- Expand ATT&CK mapping depth and confidence tuning
- Improve Sigma selector fidelity and rule grouping
- Add optional Wazuh deployment packaging and manager-side validation
- Export consolidated pipeline manifests
- Add automated release and artifact publishing

## License

MalForge is released under the [MIT License](LICENSE).



