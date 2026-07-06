# Architecture

## Overview

The project is a local analysis pipeline that turns sandbox JSON reports into detection engineering artifacts. It is intentionally separated into thin layers so each phase can be tested independently.

## Layers

### `ingestion/`

- Detects and parses raw Cuckoo, CAPE, and ANY.RUN report formats
- Produces a normalized report dictionary with shared top-level keys

### `extractor/`

- Converts normalized report artifacts into typed `Behavior` objects
- Categories:
  - process
  - registry
  - file
  - network
  - persistence

### `ioc/`

- Extracts typed `IOC` objects from normalized reports and behavior evidence
- Handles hashes, IPs, domains, URLs, file paths, registry keys, and mutexes

### `attck/`

- Maps `Behavior` objects to `AttackMapping` objects
- Produces ATT&CK Navigator layer JSON

### `generators/`

- Generates `SigmaRule` objects from extracted behavior and ATT&CK context

### `converters/`

- Converts `SigmaRule` objects into `WazuhRule` objects
- Renders parseable Wazuh XML

### `quality/`

- Validates Sigma and Wazuh rules
- Assigns deterministic heuristic risk scores
- Creates safe synthetic positive and negative test events

### `review/`

- Applies local review state metadata
- Applies deterministic version metadata and content hashes

### `reporting/`

- Builds machine-readable summary dictionaries
- Builds Markdown analyst reports

### `core/`

- Shared models
- Schema helpers
- Pipeline orchestration
- Local output writing helpers

## Pipeline Flow

```text
Raw sandbox JSON
  -> sandbox detection
  -> ingestion parser
  -> normalized report
  -> behavior extraction
  -> IOC extraction
  -> ATT&CK mapping
  -> Navigator layer
  -> Sigma rule generation
  -> Wazuh conversion
  -> validation
  -> risk scoring
  -> synthetic test event generation
  -> review metadata
  -> version metadata
  -> summary generation
  -> Markdown report generation
  -> optional local write to output/
```

## Artifact Generation Points

- Normalized report: `ingestion/*`
- Behaviors: `extractor/*`
- IOCs: `ioc/ioc_extractor.py`
- ATT&CK mappings: `attck/mapper.py`
- Navigator layer: `attck/navigator.py`
- Sigma rules: `generators/sigma_generator.py`
- Wazuh rules/XML: `converters/wazuh_converter.py`
- Validation results: `quality/validator.py`
- Risk scores: `quality/risk_scorer.py`
- Synthetic test events: `quality/test_event_generator.py`
- Review records: `review/reviewer.py`
- Version metadata: `review/versioner.py`
- Summary and Markdown: `reporting/summary.py`, `reporting/report_generator.py`
- End-to-end orchestration: `core/pipeline.py`

## Output Layout

```text
output/
  sigma/
  wazuh/
  test_events/
  reports/
  iocs/
  navigator/
```
