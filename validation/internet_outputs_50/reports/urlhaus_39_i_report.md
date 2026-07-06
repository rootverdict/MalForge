# Malware Behavior Detection Report

## Sample Overview
- Sandbox: cuckoo
- Sample name: urlhaus_39_i
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
- ipv4: 14.0.131.161
- url: http://14.0.131.161:38465/i
- file_path: /tmp/urlhaus_39_i

## ATT&CK Mappings
- T1059
- T1071
- T1071.001
- T1105
- T1571

## Generated Sigma Rules
- 3626265c-a0ef-55fa-af01-5753f5e2b0e6
- 285c4988-94c7-5b44-ad98-c711bd4cbaef
- d558818c-7fce-5224-92b7-459169d882f2
- 3ec22d8b-edbe-5029-ae47-9759641603f1

## Generated Wazuh Rules
- 104254
- 113333
- 105063
- 118846

## Rule Generation Rationale
- Sigma 3626265c-a0ef-55fa-af01-5753f5e2b0e6: Process created: urlhaus_39_i (urlhaus_39_i --urlhaus-validation)
  ATT&CK: T1059
  Why: Process selector chosen for linux_or_iot telemetry from executable and command line evidence using: cmdline|contains, exe|endswith.
- Sigma 285c4988-94c7-5b44-ad98-c711bd4cbaef: File dropped to user-accessible path: /tmp/urlhaus_39_i
  ATT&CK: T1105
  Why: File selector chosen for linux_or_iot telemetry from observed file path evidence using: file.path|contains.
- Sigma d558818c-7fce-5224-92b7-459169d882f2: IP connection observed: 14.0.131.161
  ATT&CK: T1071
  Why: Network selector chosen for linux_or_iot telemetry from observed IP evidence using: destination.ip.
- Sigma 3ec22d8b-edbe-5029-ae47-9759641603f1: HTTP connection observed: http://14.0.131.161:38465/i
  ATT&CK: T1071.001, T1571
  Why: Network selector chosen for linux_or_iot telemetry from observed IP evidence using: destination.ip, url|contains.
- Wazuh 104254: 3626265c-a0ef-55fa-af01-5753f5e2b0e6
  Why: Rule converted using Linux/generic JSON field matching; no Windows Sysmon parent or win.eventdata fields are used.
- Wazuh 113333: 285c4988-94c7-5b44-ad98-c711bd4cbaef
  Why: Rule converted using Linux/generic JSON field matching; no Windows Sysmon parent or win.eventdata fields are used.
- Wazuh 105063: d558818c-7fce-5224-92b7-459169d882f2
  Why: Rule converted using Linux/generic JSON field matching; no Windows Sysmon parent or win.eventdata fields are used.
- Wazuh 118846: 3ec22d8b-edbe-5029-ae47-9759641603f1
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