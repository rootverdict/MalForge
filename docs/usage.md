# Usage

## Install Dependencies

```bash
python3 -m pip install --user -r requirements.txt --break-system-packages
```

To install the packaged command, run `python3 -m pip install .`; the CLI is then available as `malforge`.

## Run Tests

```bash
python3 -m pytest
```

If `pytest` is not on your shell `PATH`, this `python3 -m pytest` form is the expected command in this environment.

## Run a Sample Report

```bash
python3 main.py --report samples/cuckoo_sample.json --sandbox auto --output output
```

## Run Batch Mode

```bash
python3 main.py --input-dir samples --sandbox auto --output output
```

## Run Without Writing Artifacts

```bash
python3 main.py --report samples/cuckoo_sample.json --sandbox auto --no-write
```

## Interpret Output Files

- `output/sigma/`
  Detection content in YAML when `PyYAML` is available, otherwise JSON
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
  Use `python3 -m pytest`
- `error: Report path does not exist`
  Check the `--report` path or use `--input-dir`
- No output files appear
  Make sure `--no-write` is not set
- Output is JSON instead of YAML in `output/sigma/`
  `PyYAML` may be unavailable; the pipeline falls back to JSON safely
