# Usage

## Install Dependencies

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

To install the packaged command, run `python -m pip install .`; the CLI is then available as `malforge`.

## Run Tests

```bash
python -m pytest
```

If `pytest` is not on your shell `PATH`, use `python -m pytest` from the activated virtual environment.

## Run a Sample Report

```bash
python main.py --report samples/cuckoo_sample.json --sandbox auto --output output
```

## Run Batch Mode

```bash
python main.py --input-dir samples --sandbox auto --output output
```

## Run Without Writing Artifacts

```bash
python main.py --report samples/cuckoo_sample.json --sandbox auto --no-write
```

## All CLI Options

```text
--report PATH            Run a single sandbox JSON report
--input-dir PATH         Run every .json report in a directory
--sandbox NAME           cuckoo | cape | anyrun | auto (default: auto)
--output PATH            Output directory root (default: output)
--no-write               Run the pipeline without writing artifacts
--enrich                 Build local enrichment descriptors for extracted IOCs
--urlhaus-csv PATH       Offline URLhaus CSV export for URL/domain matching
--wazuh-id-start N       Override the starting Wazuh custom rule ID
--wazuh-id-end N         Override the ending Wazuh custom rule ID
--verbose                Print artifact paths and validation warning details
```

`--wazuh-id-start` and `--wazuh-id-end` must be supplied together. Enrichment
never performs a network call: `--enrich` builds local request descriptors, and
`--urlhaus-csv` matches against a file you already downloaded.

## Run Offline Enrichment

```bash
python main.py --report samples/cape_sample.json --enrich --urlhaus-csv /path/to/urlhaus.csv
```

## Interpret Output Files

- `output/sigma/`
  Detection content in YAML for normal CLI installs; the lower-level output helper can fall back to JSON only if reused without `PyYAML`
- `output/wazuh/`
  Wazuh XML output plus the persistent `.rule_ids.json` allocation registry
- `output/test_events/`
  Synthetic positive and negative log-like events
- `output/reports/`
  Markdown report and JSON summary
- `output/iocs/`
  JSON and text IOC lists
- `output/navigator/`
  ATT&CK Navigator layer JSON

Artifact basenames end with a 12-character canonical source-report fingerprint to prevent routine overwrites when reports reuse a sample name. Preserve `output/wazuh/.rule_ids.json` between sequential runs so Wazuh IDs remain stable and non-reused. Only one process at a time may write a given output directory.

## Clean Output

```bash
make clean
```

This removes generated artifacts under `output/` but keeps the directory structure, `.gitkeep` files, and `output/wazuh/.rule_ids.json`.

## Troubleshooting

- `pytest: command not found`
  Use `python -m pytest` from the activated virtual environment
- `error: Report path does not exist`
  Check the `--report` path or use `--input-dir`
- No output files appear
  Make sure `--no-write` is not set
- Output is JSON instead of YAML in `output/sigma/`
  The normal CLI install includes `PyYAML`; JSON output means the lower-level output helper is being reused without that dependency
