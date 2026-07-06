# Malware Behavior Detection Report

## Sample Overview
- Sandbox: cuckoo
- Sample name: urlhaus_36_Mozi.m
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
- ipv4: 112.27.10.150
- url: http://112.27.10.150:34339/Mozi.m
- file_path: /tmp/urlhaus_36_Mozi.m

## ATT&CK Mappings
- T1059
- T1071
- T1071.001
- T1105
- T1571

## Generated Sigma Rules
- a70fa687-730e-5562-addc-629faaebb2f3
- 27887604-0626-532b-8f00-0f1e7d1e361d
- a101fd5c-8b65-54ca-8fda-ff0a2fc4fd7f
- f4d6d5b8-f0ba-52dc-a5a2-59c5978557af

## Generated Wazuh Rules
- 116614
- 106281
- 109636
- 115595

## Rule Generation Rationale
- Sigma a70fa687-730e-5562-addc-629faaebb2f3: Process created: urlhaus_36_Mozi.m (urlhaus_36_Mozi.m --urlhaus-validation)
  ATT&CK: T1059
  Why: Process selector chosen for linux_or_iot telemetry from executable and command line evidence using: cmdline|contains, exe|endswith.
- Sigma 27887604-0626-532b-8f00-0f1e7d1e361d: File dropped to user-accessible path: /tmp/urlhaus_36_Mozi.m
  ATT&CK: T1105
  Why: File selector chosen for linux_or_iot telemetry from observed file path evidence using: file.path|contains.
- Sigma a101fd5c-8b65-54ca-8fda-ff0a2fc4fd7f: IP connection observed: 112.27.10.150
  ATT&CK: T1071
  Why: Network selector chosen for linux_or_iot telemetry from observed IP evidence using: destination.ip.
- Sigma f4d6d5b8-f0ba-52dc-a5a2-59c5978557af: HTTP connection observed: http://112.27.10.150:34339/Mozi.m
  ATT&CK: T1071.001, T1571
  Why: Network selector chosen for linux_or_iot telemetry from observed IP evidence using: destination.ip, url|contains.
- Wazuh 116614: a70fa687-730e-5562-addc-629faaebb2f3
  Why: Rule converted using Linux/generic JSON field matching; no Windows Sysmon parent or win.eventdata fields are used.
- Wazuh 106281: 27887604-0626-532b-8f00-0f1e7d1e361d
  Why: Rule converted using Linux/generic JSON field matching; no Windows Sysmon parent or win.eventdata fields are used.
- Wazuh 109636: a101fd5c-8b65-54ca-8fda-ff0a2fc4fd7f
  Why: Rule converted using Linux/generic JSON field matching; no Windows Sysmon parent or win.eventdata fields are used.
- Wazuh 115595: f4d6d5b8-f0ba-52dc-a5a2-59c5978557af
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