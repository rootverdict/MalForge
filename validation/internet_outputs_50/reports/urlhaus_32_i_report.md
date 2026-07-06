# Malware Behavior Detection Report

## Sample Overview
- Sandbox: cuckoo
- Sample name: urlhaus_32_i
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
- url: http://182.120.9.25:43181/i
- file_path: /tmp/urlhaus_32_i

## ATT&CK Mappings
- T1059
- T1071
- T1071.001
- T1105
- T1571

## Generated Sigma Rules
- 378c7345-b971-5ef9-a2eb-8ecf3026f008
- 7d3014eb-da85-5b12-996b-4b7ccd224d33
- 3f1edb02-fc90-5336-9831-79868de77b4e
- 4ba8a83f-6238-5963-abc6-5e9b0b42537a

## Generated Wazuh Rules
- 102058
- 104177
- 116029
- 109726

## Rule Generation Rationale
- Sigma 378c7345-b971-5ef9-a2eb-8ecf3026f008: Process created: urlhaus_32_i (urlhaus_32_i --urlhaus-validation)
  ATT&CK: T1059
  Why: Process selector chosen for linux_or_iot telemetry from executable and command line evidence using: cmdline|contains, exe|endswith.
- Sigma 7d3014eb-da85-5b12-996b-4b7ccd224d33: File dropped to user-accessible path: /tmp/urlhaus_32_i
  ATT&CK: T1105
  Why: File selector chosen for linux_or_iot telemetry from observed file path evidence using: file.path|contains.
- Sigma 3f1edb02-fc90-5336-9831-79868de77b4e: IP connection observed: 182.120.9.25
  ATT&CK: T1071
  Why: Network selector chosen for linux_or_iot telemetry from observed IP evidence using: destination.ip.
- Sigma 4ba8a83f-6238-5963-abc6-5e9b0b42537a: HTTP connection observed: http://182.120.9.25:43181/i
  ATT&CK: T1071.001, T1571
  Why: Network selector chosen for linux_or_iot telemetry from observed IP evidence using: destination.ip, url|contains.
- Wazuh 102058: 378c7345-b971-5ef9-a2eb-8ecf3026f008
  Why: Rule converted using Linux/generic JSON field matching; no Windows Sysmon parent or win.eventdata fields are used.
- Wazuh 104177: 7d3014eb-da85-5b12-996b-4b7ccd224d33
  Why: Rule converted using Linux/generic JSON field matching; no Windows Sysmon parent or win.eventdata fields are used.
- Wazuh 116029: 3f1edb02-fc90-5336-9831-79868de77b4e
  Why: Rule converted using Linux/generic JSON field matching; no Windows Sysmon parent or win.eventdata fields are used.
- Wazuh 109726: 4ba8a83f-6238-5963-abc6-5e9b0b42537a
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