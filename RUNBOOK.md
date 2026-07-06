# MBDG Runbook

Single reference file for setup, usage, testing, outputs, and troubleshooting.

## Project

`malware-behavior-detection-generator`

Local pipeline that:
- reads sandbox JSON reports only
- extracts malware behavior
- maps behavior to MITRE ATT&CK
- generates Sigma rules
- converts Sigma to Wazuh XML
- validates and scores rules
- generates synthetic test events
- writes local reports and summaries

## Safety

- No live malware execution
- No sample detonation
- No external network calls by default
- No Wazuh deployment automation
- Enrichment is local/offline only unless you add more later

## Requirements

- `python3`
- `pip`
- Linux/macOS shell or equivalent terminal

## Install

Preferred:

```bash
python3 -m pip install -r requirements.txt
```

If your system Python is externally managed:

```bash
python3 -m pip install --user -r requirements.txt --break-system-packages
```

## Project Layout

```text
main.py                 CLI entrypoint
config.yaml             local config
core/                   schema, models, pipeline
ingestion/              cuckoo, cape, anyrun parsers
extractor/              behavior extraction
ioc/                    IOC extraction
attck/                  ATT&CK mapping + navigator
generators/             Sigma generation
converters/             Wazuh conversion
quality/                validation, scoring, test events
review/                 review metadata + versioning
reporting/              summary + markdown report
enrichment/             local enrichment helpers
samples/                safe demo reports
tests/                  pytest suite
output/                 generated artifacts
```

## Quick Start

Run one sample report:

```bash
python3 main.py --report samples/cuckoo_sample.json --sandbox auto --output output
```

Run without writing files:

```bash
python3 main.py --report samples/cuckoo_sample.json --sandbox auto --no-write
```

Run all sample reports:

```bash
python3 main.py --input-dir samples --sandbox auto --output output
```

Verbose run:

```bash
python3 main.py --report samples/cuckoo_sample.json --sandbox auto --output output --verbose
```

## CLI Options

```text
--report PATH            Run a single sandbox JSON report
--input-dir PATH         Run all .json reports in a directory
--sandbox                cuckoo | cape | anyrun | auto
--output PATH            Output directory root, default: output
--no-write               Run pipeline without writing artifacts
--enrich                 Enable local enrichment hooks
--urlhaus-csv PATH       Local URLhaus CSV for offline URL/domain enrichment
--wazuh-id-start N       Override Wazuh custom rule ID start
--wazuh-id-end N         Override Wazuh custom rule ID end
--verbose                Print additional output details
```

## Useful Commands

Install dependencies:

```bash
make install
```

Run sample:

```bash
make run
```

Run tests:

```bash
make test
```

Compile check:

```bash
make lint
```

List project tree:

```bash
make tree
```

Clean generated output files:

```bash
make clean
```

## Testing

Primary:

```bash
python3 -m pytest
```

If `pytest` is not on `PATH`, always use:

```bash
python3 -m pytest
```

Compile validation:

```bash
python3 -m compileall .
```

## Offline Enrichment

Current supported offline enrichment:
- URLhaus CSV for URL and domain IOC matching

Example:

```bash
python3 main.py \
  --report samples/cape_sample.json \
  --sandbox auto \
  --enrich \
  --urlhaus-csv /path/to/urlhaus.csv \
  --output output
```

What it does:
- loads the CSV locally
- matches extracted `url` and `domain` IOCs
- tags matches with `source:urlhaus`
- raises IOC confidence to `0.9`

What it does not do:
- no API calls
- no VirusTotal lookup
- no MISP lookup

## Wazuh ID Range

Default configured range:

```text
100000-119999
```

Override from CLI:

```bash
python3 main.py \
  --report samples/cuckoo_sample.json \
  --wazuh-id-start 130000 \
  --wazuh-id-end 139999
```

## Output Files

Generated files are written only under `output/`.

```text
output/sigma/*.yml or *.json
output/wazuh/*.xml
output/test_events/*.json
output/reports/*_report.md
output/reports/*_summary.json
output/iocs/*_iocs.json
output/iocs/*_iocs.txt
output/navigator/*_navigator_layer.json
```

## Typical Workflow

1. Install dependencies
2. Run one sample report
3. Review:
   - `output/reports/*_report.md`
   - `output/reports/*_summary.json`
   - `output/sigma/`
   - `output/wazuh/`
4. Run `python3 -m pytest`
5. If needed, rerun with:
   - `--no-write`
   - `--verbose`
   - `--enrich`
   - custom Wazuh ID bounds

## Known Working Lab Note

Validated lab proof:

`Generated Wazuh rule 116767 fired successfully in the lab from MBDG-Win10 Sysmon Event ID 1 using parent rule 61603.`

## Troubleshooting

`pytest: command not found`

Use:

```bash
python3 -m pytest
```

`Could not detect sandbox type from report`

- confirm the JSON is one of:
  - Cuckoo
  - CAPE
  - ANY.RUN
- if needed, force the parser with:

```bash
--sandbox cuckoo
--sandbox cape
--sandbox anyrun
```

`Unsupported sandbox type`

- the report shape is not supported by the current parsers

`Sandbox report exceeds maximum supported size`

- trim the report
- remove embedded oversized content
- or increase the limit in code if you intentionally want large reports

`Wazuh rule ID space exhausted`

- rerun with a larger custom range:

```bash
--wazuh-id-start 130000 --wazuh-id-end 139999
```

`No JSON reports found in input directory`

- check the directory path
- ensure files end in `.json`

## Current Scope

Implemented:
- sandbox ingestion
- behavior extraction
- IOC extraction
- ATT&CK mapping
- Sigma generation
- Wazuh conversion
- validation
- risk scoring
- synthetic test events
- explainability traces
- reporting
- offline URLhaus hook

Not implemented:
- live VT/MISP enrichment
- STIX export
- Splunk/KQL/ESQL export
- dashboard
- database
- Wazuh deployment automation

## Best Commands To Remember

Run one report:

```bash
python3 main.py --report samples/cuckoo_sample.json --sandbox auto --output output
```

Run tests:

```bash
python3 -m pytest
```

Run offline enrichment:

```bash
python3 main.py --report samples/cape_sample.json --enrich --urlhaus-csv /path/to/urlhaus.csv
```

Use a custom Wazuh ID range:

```bash
python3 main.py --report samples/cuckoo_sample.json --wazuh-id-start 130000 --wazuh-id-end 139999
```
