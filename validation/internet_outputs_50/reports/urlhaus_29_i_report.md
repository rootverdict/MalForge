# Malware Behavior Detection Report

## Sample Overview
- Sandbox: cuckoo
- Sample name: urlhaus_29_i
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
- url: http://123.12.20.109:60932/i
- file_path: /tmp/urlhaus_29_i

## ATT&CK Mappings
- T1059
- T1071
- T1071.001
- T1105
- T1571

## Generated Sigma Rules
- 3dc97856-82de-5d9f-948c-3edc1d29ae0e
- b107d0bc-2f18-5067-8094-faf3dd71f300
- 20b89528-693e-5714-9ca6-41e3933c1f4d
- d0fed712-b9e2-5029-bbb9-0d28ac908a04

## Generated Wazuh Rules
- 118414
- 100124
- 101288
- 119265

## Rule Generation Rationale
- Sigma 3dc97856-82de-5d9f-948c-3edc1d29ae0e: Process created: urlhaus_29_i (urlhaus_29_i --urlhaus-validation)
  ATT&CK: T1059
  Why: Process selector chosen for linux_or_iot telemetry from executable and command line evidence using: cmdline|contains, exe|endswith.
- Sigma b107d0bc-2f18-5067-8094-faf3dd71f300: File dropped to user-accessible path: /tmp/urlhaus_29_i
  ATT&CK: T1105
  Why: File selector chosen for linux_or_iot telemetry from observed file path evidence using: file.path|contains.
- Sigma 20b89528-693e-5714-9ca6-41e3933c1f4d: IP connection observed: 123.12.20.109
  ATT&CK: T1071
  Why: Network selector chosen for linux_or_iot telemetry from observed IP evidence using: destination.ip.
- Sigma d0fed712-b9e2-5029-bbb9-0d28ac908a04: HTTP connection observed: http://123.12.20.109:60932/i
  ATT&CK: T1071.001, T1571
  Why: Network selector chosen for linux_or_iot telemetry from observed IP evidence using: destination.ip, url|contains.
- Wazuh 118414: 3dc97856-82de-5d9f-948c-3edc1d29ae0e
  Why: Rule converted using Linux/generic JSON field matching; no Windows Sysmon parent or win.eventdata fields are used.
- Wazuh 100124: b107d0bc-2f18-5067-8094-faf3dd71f300
  Why: Rule converted using Linux/generic JSON field matching; no Windows Sysmon parent or win.eventdata fields are used.
- Wazuh 101288: 20b89528-693e-5714-9ca6-41e3933c1f4d
  Why: Rule converted using Linux/generic JSON field matching; no Windows Sysmon parent or win.eventdata fields are used.
- Wazuh 119265: d0fed712-b9e2-5029-bbb9-0d28ac908a04
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