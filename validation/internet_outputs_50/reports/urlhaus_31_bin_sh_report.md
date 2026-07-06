# Malware Behavior Detection Report

## Sample Overview
- Sandbox: cuckoo
- Sample name: urlhaus_31_bin.sh
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
- ipv4: 123.12.20.109
- url: http://123.12.20.109:60932/bin.sh
- file_path: /tmp/urlhaus_31_bin.sh

## ATT&CK Mappings
- T1059
- T1071
- T1071.001
- T1105
- T1571

## Generated Sigma Rules
- c50f6e8f-caca-561b-a58d-32ae3c688d91
- 9213e44d-1d68-51b3-8700-18e59f697226
- 20b89528-693e-5714-9ca6-41e3933c1f4d
- c3d9dd41-cc53-5325-996b-ff7c87db851e

## Generated Wazuh Rules
- 103263
- 115113
- 101288
- 101601

## Rule Generation Rationale
- Sigma c50f6e8f-caca-561b-a58d-32ae3c688d91: Process created: urlhaus_31_bin.sh (urlhaus_31_bin.sh --urlhaus-validation)
  ATT&CK: T1059
  Why: Process selector chosen for linux_or_iot telemetry from executable and command line evidence using: cmdline|contains, exe|endswith.
- Sigma 9213e44d-1d68-51b3-8700-18e59f697226: File dropped to user-accessible path: /tmp/urlhaus_31_bin.sh
  ATT&CK: T1105
  Why: File selector chosen for linux_or_iot telemetry from observed file path evidence using: file.path|contains.
- Sigma 20b89528-693e-5714-9ca6-41e3933c1f4d: IP connection observed: 123.12.20.109
  ATT&CK: T1071
  Why: Network selector chosen for linux_or_iot telemetry from observed IP evidence using: destination.ip.
- Sigma c3d9dd41-cc53-5325-996b-ff7c87db851e: HTTP connection observed: http://123.12.20.109:60932/bin.sh
  ATT&CK: T1071.001, T1571
  Why: Network selector chosen for linux_or_iot telemetry from observed IP evidence using: destination.ip, url|contains.
- Wazuh 103263: c50f6e8f-caca-561b-a58d-32ae3c688d91
  Why: Rule converted using Linux/generic JSON field matching; no Windows Sysmon parent or win.eventdata fields are used.
- Wazuh 115113: 9213e44d-1d68-51b3-8700-18e59f697226
  Why: Rule converted using Linux/generic JSON field matching; no Windows Sysmon parent or win.eventdata fields are used.
- Wazuh 101288: 20b89528-693e-5714-9ca6-41e3933c1f4d
  Why: Rule converted using Linux/generic JSON field matching; no Windows Sysmon parent or win.eventdata fields are used.
- Wazuh 101601: c3d9dd41-cc53-5325-996b-ff7c87db851e
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