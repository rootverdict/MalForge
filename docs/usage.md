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
