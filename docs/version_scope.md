# Version Scope

This file defines what belongs in each product version so development stays focused. When a useful idea appears, classify it here before building it.

## V1: Local Detection Artifact Pipeline

V1 is the smallest complete version of MalForge that proves the main workflow end to end:

```text
Sandbox JSON report
  -> normalized behavior
  -> ATT&CK context
  -> detection artifacts
  -> local validation evidence
  -> analyst report
```

### Included In V1

- Parse Cuckoo, CAPE, and ANY.RUN JSON reports from local files.
- Auto-detect sandbox source when possible.
- Normalize sandbox data into shared report models.
- Extract process, registry, file, network, persistence, and IOC evidence.
- Map extracted behavior to MITRE ATT&CK with deterministic rule-based logic.
- Generate ATT&CK Navigator layers.
- Generate Sigma rules from extracted behavior.
- Convert generated Sigma rules to Wazuh XML.
- Assign stable Wazuh rule IDs for sequential, single-writer local runs.
- Validate generated Sigma and Wazuh structures with local heuristic checks.
- Assign deterministic local risk scores.
- Generate safe synthetic positive and negative test events.
- Apply local review and deterministic version metadata.
- Generate JSON summaries and Markdown analyst reports.
- Support single-report and batch CLI execution.
- Write artifacts only to local output folders.
- Keep the project safe: no malware execution, no sample detonation, no deployment automation, and no required network calls.
- Maintain focused tests for ingestion, extraction, mapping, generation, conversion, validation, reporting, and pipeline orchestration.

### Excluded From V1

- Live malware execution or sample detonation.
- Automatic rule deployment to Wazuh, SIEMs, EDRs, or cloud platforms.
- Vendor-native rule validation engines.
- Live VirusTotal, MISP, URLhaus, or other enrichment API calls.
- Web UI, dashboard, or hosted service mode.
- Multi-user workflow, authentication, permissions, or collaboration features.
- Database-backed persistence.
- Distributed batch processing or queue workers.
- Real-time monitoring.
- Automated release publishing.
- Broad sandbox/vendor support beyond Cuckoo, CAPE, and ANY.RUN.
- AI-generated detections that change behavior nondeterministically.

## V1 Done Criteria

V1 is considered complete when:

- The CLI can process the checked-in sample reports in single-report and batch mode.
- Generated artifacts include Sigma, Wazuh XML, test events, IOCs, Navigator layers, summaries, and Markdown reports where source evidence supports them.
- `python -m pytest` passes.
- Output writing stays local and deterministic.
- README, usage docs, and architecture docs describe the implemented workflow accurately.
- Current limitations are explicit and match the V1 exclusions above.

## V2: Practical Analyst Expansion

V2 starts only after the V1 boundary is stable. It should improve usefulness without changing the safety posture by default.

### Candidate V2 Features

- Optional enrichment execution with local caching and clear offline mode.
- Better ATT&CK confidence scoring and technique rationale.
- Improved Sigma selector fidelity, grouping, and false-positive notes.
- Optional Wazuh packaging for manual import.
- Optional manager-side validation workflow for a controlled lab.
- Consolidated run manifests that link every generated artifact to source evidence.
- Richer report sections for analyst triage and QA review.
- Expanded sandbox schema coverage when real fixtures exist.
- More realistic synthetic test event fixtures.
- Maintainability refactors for complex helpers, including IOC extraction, validation, and report rendering.
- Release packaging and artifact publishing automation.

## Later Versions

Later versions can include larger product shifts:

- Web UI or desktop UI.
- Hosted service mode.
- Database-backed projects and history.
- Team workflow and approval gates.
- Integrations with SIEM, SOAR, ticketing, or storage platforms.
- Distributed processing.
- Scheduled ingestion.
- Advanced analytics across many reports.

## Scope Rules

- If a change is required for the local CLI pipeline to work end to end, it can be V1.
- If a change improves quality but is not required for the core local workflow, consider V2.
- If a change requires credentials, external services, deployment, scheduling, or persistent infrastructure, it is not V1.
- If a change increases safety risk, it needs an explicit design note before implementation.
- If a change makes output nondeterministic, it should stay out of V1 unless there is a deterministic fallback.
- If the answer is unclear, default to V2 and keep V1 moving.
