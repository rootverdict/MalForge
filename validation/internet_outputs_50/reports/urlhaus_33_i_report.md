# Malware Behavior Detection Report

## Sample Overview
- Sandbox: cuckoo
- Sample name: urlhaus_33_i
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
- ipv4: 219.157.58.156
- url: http://219.157.58.156:47845/i
- file_path: /tmp/urlhaus_33_i

## ATT&CK Mappings
- T1059
- T1071
- T1071.001
- T1105
- T1571

## Generated Sigma Rules
- 7eb1fd97-82b7-5be5-ae94-b9174e8bc499
- 99266dc6-97eb-58c3-a3b5-0a8445504be7
- 96f18031-f465-5ab4-b25e-6d301d5e2a1a
- 3682b7c7-199b-5d18-af12-eff74835ce35

## Generated Wazuh Rules
- 119638
- 107392
- 114424
- 118985

## Rule Generation Rationale
- Sigma 7eb1fd97-82b7-5be5-ae94-b9174e8bc499: Process created: urlhaus_33_i (urlhaus_33_i --urlhaus-validation)
  ATT&CK: T1059
  Why: Process selector chosen for linux_or_iot telemetry from executable and command line evidence using: cmdline|contains, exe|endswith.
- Sigma 99266dc6-97eb-58c3-a3b5-0a8445504be7: File dropped to user-accessible path: /tmp/urlhaus_33_i
  ATT&CK: T1105
  Why: File selector chosen for linux_or_iot telemetry from observed file path evidence using: file.path|contains.
- Sigma 96f18031-f465-5ab4-b25e-6d301d5e2a1a: IP connection observed: 219.157.58.156
  ATT&CK: T1071
  Why: Network selector chosen for linux_or_iot telemetry from observed IP evidence using: destination.ip.
- Sigma 3682b7c7-199b-5d18-af12-eff74835ce35: HTTP connection observed: http://219.157.58.156:47845/i
  ATT&CK: T1071.001, T1571
  Why: Network selector chosen for linux_or_iot telemetry from observed IP evidence using: destination.ip, url|contains.
- Wazuh 119638: 7eb1fd97-82b7-5be5-ae94-b9174e8bc499
  Why: Rule converted using Linux/generic JSON field matching; no Windows Sysmon parent or win.eventdata fields are used.
- Wazuh 107392: 99266dc6-97eb-58c3-a3b5-0a8445504be7
  Why: Rule converted using Linux/generic JSON field matching; no Windows Sysmon parent or win.eventdata fields are used.
- Wazuh 114424: 96f18031-f465-5ab4-b25e-6d301d5e2a1a
  Why: Rule converted using Linux/generic JSON field matching; no Windows Sysmon parent or win.eventdata fields are used.
- Wazuh 118985: 3682b7c7-199b-5d18-af12-eff74835ce35
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