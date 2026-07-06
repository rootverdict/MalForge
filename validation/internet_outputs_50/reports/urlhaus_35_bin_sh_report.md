# Malware Behavior Detection Report

## Sample Overview
- Sandbox: cuckoo
- Sample name: urlhaus_35_bin.sh
- MD5: n/a
- SHA256: n/a
- Generated at: 2026-07-01T10:00:18+00:00

## Behavior Summary

## Source Data Limitations
- Missing payload hashes: md5, sha1, sha256
- Note: Payload hashes unavailable from source report.
- file: 1
- network: 2
- process: 1

## IOC Summary
- file_path: 1
- ipv4: 1
- url: 1

### IOC Values
- ipv4: 182.120.9.25
- url: http://182.120.9.25:43181/bin.sh
- file_path: /tmp/urlhaus_35_bin.sh

## ATT&CK Mappings
- T1059
- T1071
- T1071.001
- T1105
- T1571

## Generated Sigma Rules
- f5943798-da4a-5589-b919-105d4c01dda2
- 9da4ced0-6178-5e70-a9c9-15357f7e82a6
- 3f1edb02-fc90-5336-9831-79868de77b4e
- 174babc5-8311-5828-80b6-377ae4a1cf45

## Generated Wazuh Rules
- 108289
- 107719
- 116029
- 106993

## Rule Generation Rationale
- Sigma f5943798-da4a-5589-b919-105d4c01dda2: Process created: urlhaus_35_bin.sh (urlhaus_35_bin.sh --urlhaus-validation)
  ATT&CK: T1059
  Why: Process selector chosen for linux_or_iot telemetry from executable and command line evidence using: cmdline|contains, exe|endswith.
- Sigma 9da4ced0-6178-5e70-a9c9-15357f7e82a6: File dropped to user-accessible path: /tmp/urlhaus_35_bin.sh
  ATT&CK: T1105
  Why: File selector chosen for linux_or_iot telemetry from observed file path evidence using: file.path|contains.
- Sigma 3f1edb02-fc90-5336-9831-79868de77b4e: IP connection observed: 182.120.9.25
  ATT&CK: T1071
  Why: Network selector chosen for linux_or_iot telemetry from observed IP evidence using: destination.ip.
- Sigma 174babc5-8311-5828-80b6-377ae4a1cf45: HTTP connection observed: http://182.120.9.25:43181/bin.sh
  ATT&CK: T1071.001, T1571
  Why: Network selector chosen for linux_or_iot telemetry from observed IP evidence using: destination.ip, url|contains.
- Wazuh 108289: f5943798-da4a-5589-b919-105d4c01dda2
  Why: Rule converted using Linux/generic JSON field matching; no Windows Sysmon parent or win.eventdata fields are used.
- Wazuh 107719: 9da4ced0-6178-5e70-a9c9-15357f7e82a6
  Why: Rule converted using Linux/generic JSON field matching; no Windows Sysmon parent or win.eventdata fields are used.
- Wazuh 116029: 3f1edb02-fc90-5336-9831-79868de77b4e
  Why: Rule converted using Linux/generic JSON field matching; no Windows Sysmon parent or win.eventdata fields are used.
- Wazuh 106993: 174babc5-8311-5828-80b6-377ae4a1cf45
  Why: Rule converted using Linux/generic JSON field matching; no Windows Sysmon parent or win.eventdata fields are used.

## Validation Warnings
- No validation warnings.

## Risk Scoring
- Average risk score: 62.75
- Average ATT&CK confidence: 0.74

## Review Status
- unreviewed

## Output Artifact List
- Navigator techniques: 5
- Sigma rule count: 4
- Wazuh rule count: 4