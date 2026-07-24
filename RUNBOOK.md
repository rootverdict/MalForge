# MBDG Runbook

Single reference file for setup, usage, testing, outputs, and troubleshooting.

> Local interview prep: if `tools/generate_code_reference.py` exists, run `python tools/generate_code_reference.py` immediately before relying on generated symbol locations or line numbers.

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

- Python 3.11 or newer
- `pip`
- Windows PowerShell, Linux/macOS shell, or equivalent terminal

## Install

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

Install the packaged command from the repository root when desired:

```bash
python -m pip install .
malforge --help
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
python main.py --report samples/cuckoo_sample.json --sandbox auto --output output
```

Run without writing files:

```bash
python main.py --report samples/cuckoo_sample.json --sandbox auto --no-write
```

Run all sample reports:

```bash
python main.py --input-dir samples --sandbox auto --output output
```

Verbose run:

```bash
python main.py --report samples/cuckoo_sample.json --sandbox auto --output output --verbose
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

This preserves `output/wazuh/.rule_ids.json` so later sequential runs retain their existing Wazuh ID assignments.

## Testing

Primary:

```bash
python -m pytest
```

If `pytest` is not on `PATH`, use the activated virtual environment:

```bash
python -m pytest
```

Compile validation:

```bash
python -m compileall -q attck converters core enrichment extractor generators ingestion ioc quality reporting review tests main.py
```

## Offline Enrichment

Current supported offline enrichment:
- URLhaus CSV for URL and domain IOC matching

Example:

```bash
python main.py \
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
python main.py \
  --report samples/cuckoo_sample.json \
  --wazuh-id-start 130000 \
  --wazuh-id-end 139999
```

Written runs keep stable, non-reused assignments in `output/wazuh/.rule_ids.json` when one process writes the output directory at a time. Preserve that file when adding more reports to the same output set, and do not run concurrent writers against that directory. If the configured range is exhausted, the run stops instead of reusing an ID.

Windows process rules use the Wazuh Sysmon Event ID 1 parent rule. Registry rules use the Event ID 12, 13, and 14 parent rules; file, network, and DNS rules use the matching `sysmon_event*` group. Linux/generic rules continue to use JSON decoding.

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

Artifact names include a 12-character fingerprint of the canonical raw source report. This prevents routine overwrites when reports share a sample filename.

## Environment Configuration

The CLI accepts the following optional environment variables (CLI arguments take precedence):

```text
CONFIG_PATH
OUTPUT_DIR
WAZUH_RULE_ID_START
WAZUH_RULE_ID_END
WAZUH_RULE_ID_OFFSET
URLHAUS_CSV
VIRUSTOTAL_API_KEY
MISP_URL
MISP_API_KEY
```

VirusTotal and MISP credentials currently enable local lookup descriptors only; no network request is sent.

## Typical Workflow

1. Install dependencies
2. Run one sample report
3. Review:
   - `output/reports/*_report.md`
   - `output/reports/*_summary.json`
   - `output/sigma/`
   - `output/wazuh/`
4. Run `python -m pytest`
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
python -m pytest
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
python main.py --report samples/cuckoo_sample.json --sandbox auto --output output
```

Run tests:

```bash
python -m pytest
```

Run offline enrichment:

```bash
python main.py --report samples/cape_sample.json --enrich --urlhaus-csv /path/to/urlhaus.csv
```

Use a custom Wazuh ID range:

```bash
python main.py --report samples/cuckoo_sample.json --wazuh-id-start 130000 --wazuh-id-end 139999
```
