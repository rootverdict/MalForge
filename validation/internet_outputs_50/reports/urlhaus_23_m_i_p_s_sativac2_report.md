# Malware Behavior Detection Report

## Sample Overview
- Sandbox: cuckoo
- Sample name: urlhaus_23_m-i.p-s.SativaC2
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
- ipv4: 85.204.125.67
- url: http://85.204.125.67:8080/m-i.p-s.SativaC2
- file_path: /tmp/urlhaus_23_m-i.p-s.SativaC2

## ATT&CK Mappings
- T1059
- T1071
- T1071.001
- T1105
- T1571

## Generated Sigma Rules
- c0c3202d-a912-5fc2-9644-4d4a00c7769d
- 0952089b-e07c-5cbb-bdeb-d27bd15f6bf8
- 7ad1782e-d8eb-5e18-9c16-b4ea64b90454
- 32485a0b-72b8-5234-96eb-d788a7ebc24f

## Generated Wazuh Rules
- 108764
- 110128
- 117321
- 102534

## Rule Generation Rationale
- Sigma c0c3202d-a912-5fc2-9644-4d4a00c7769d: Process created: urlhaus_23_m-i.p-s.SativaC2 (urlhaus_23_m-i.p-s.SativaC2 --urlhaus-validation)
  ATT&CK: T1059
  Why: Process selector chosen for non_windows telemetry from executable and command line evidence using: cmdline|contains, exe|endswith.
- Sigma 0952089b-e07c-5cbb-bdeb-d27bd15f6bf8: File dropped to user-accessible path: /tmp/urlhaus_23_m-i.p-s.SativaC2
  ATT&CK: T1105
  Why: File selector chosen for non_windows telemetry from observed file path evidence using: file.path|contains.
- Sigma 7ad1782e-d8eb-5e18-9c16-b4ea64b90454: IP connection observed: 85.204.125.67
  ATT&CK: T1071
  Why: Network selector chosen for non_windows telemetry from observed IP evidence using: destination.ip.
- Sigma 32485a0b-72b8-5234-96eb-d788a7ebc24f: HTTP connection observed: http://85.204.125.67:8080/m-i.p-s.SativaC2
  ATT&CK: T1071.001, T1571
  Why: Network selector chosen for non_windows telemetry from observed IP evidence using: destination.ip, url|contains.
- Wazuh 108764: c0c3202d-a912-5fc2-9644-4d4a00c7769d
  Why: Rule converted using Linux/generic JSON field matching; no Windows Sysmon parent or win.eventdata fields are used.
- Wazuh 110128: 0952089b-e07c-5cbb-bdeb-d27bd15f6bf8
  Why: Rule converted using Linux/generic JSON field matching; no Windows Sysmon parent or win.eventdata fields are used.
- Wazuh 117321: 7ad1782e-d8eb-5e18-9c16-b4ea64b90454
  Why: Rule converted using Linux/generic JSON field matching; no Windows Sysmon parent or win.eventdata fields are used.
- Wazuh 102534: 32485a0b-72b8-5234-96eb-d788a7ebc24f
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