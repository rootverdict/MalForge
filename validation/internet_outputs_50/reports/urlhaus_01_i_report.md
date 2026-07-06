# Malware Behavior Detection Report

## Sample Overview
- Sandbox: cuckoo
- Sample name: urlhaus_01_i
- MD5: n/a
- SHA256: n/a
- Generated at: 2026-07-01T10:00:17+00:00

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
- ipv4: 110.37.53.25
- url: http://110.37.53.25:58088/i
- file_path: /tmp/urlhaus_01_i

## ATT&CK Mappings
- T1059
- T1071
- T1071.001
- T1105
- T1571

## Generated Sigma Rules
- 5926a944-d773-5152-9ac2-a36cf56ab6ef
- 67dd559d-2748-5681-bb05-0cb592d08675
- 6bff468a-7308-5aaf-b2b6-d08cb4b2570c
- 4b44756b-bb80-59fc-88f6-059ac1970b25

## Generated Wazuh Rules
- 111315
- 112913
- 119645
- 114370

## Rule Generation Rationale
- Sigma 5926a944-d773-5152-9ac2-a36cf56ab6ef: Process created: urlhaus_01_i (urlhaus_01_i --urlhaus-validation)
  ATT&CK: T1059
  Why: Process selector chosen for linux_or_iot telemetry from executable and command line evidence using: cmdline|contains, exe|endswith.
- Sigma 67dd559d-2748-5681-bb05-0cb592d08675: File dropped to user-accessible path: /tmp/urlhaus_01_i
  ATT&CK: T1105
  Why: File selector chosen for linux_or_iot telemetry from observed file path evidence using: file.path|contains.
- Sigma 6bff468a-7308-5aaf-b2b6-d08cb4b2570c: IP connection observed: 110.37.53.25
  ATT&CK: T1071
  Why: Network selector chosen for linux_or_iot telemetry from observed IP evidence using: destination.ip.
- Sigma 4b44756b-bb80-59fc-88f6-059ac1970b25: HTTP connection observed: http://110.37.53.25:58088/i
  ATT&CK: T1071.001, T1571
  Why: Network selector chosen for linux_or_iot telemetry from observed IP evidence using: destination.ip, url|contains.
- Wazuh 111315: 5926a944-d773-5152-9ac2-a36cf56ab6ef
  Why: Rule converted using Linux/generic JSON field matching; no Windows Sysmon parent or win.eventdata fields are used.
- Wazuh 112913: 67dd559d-2748-5681-bb05-0cb592d08675
  Why: Rule converted using Linux/generic JSON field matching; no Windows Sysmon parent or win.eventdata fields are used.
- Wazuh 119645: 6bff468a-7308-5aaf-b2b6-d08cb4b2570c
  Why: Rule converted using Linux/generic JSON field matching; no Windows Sysmon parent or win.eventdata fields are used.
- Wazuh 114370: 4b44756b-bb80-59fc-88f6-059ac1970b25
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