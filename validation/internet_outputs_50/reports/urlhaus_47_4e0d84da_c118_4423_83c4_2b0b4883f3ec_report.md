# Malware Behavior Detection Report

## Sample Overview
- Sandbox: cuckoo
- Sample name: urlhaus_47_4e0d84da-c118-4423-83c4-2b0b4883f3ec
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
- domain: 1
- file_path: 1
- url: 1

### IOC Values
- domain: lvt.vip1xbet.net
- url: https://lvt.vip1xbet.net/4e0d84da-c118-4423-83c4-2b0b4883f3ec
- file_path: C:\Users\Public\Downloads\urlhaus_47_4e0d84da-c118-4423-83c4-2b0b4883f3ec

## ATT&CK Mappings
- T1059
- T1071.001
- T1071.004
- T1105

## Generated Sigma Rules
- 8afc3706-d0f7-509b-b495-509e7bd85ab4
- b3ce27d2-df40-5311-8d06-dfc2c119b876
- d75d2ceb-b7c4-50a8-ab31-ee6c71d9c0d9
- c88175f3-27fe-5c20-be22-a8096752a527

## Generated Wazuh Rules
- 102369
- 107820
- 111431
- 119611

## Rule Generation Rationale
- Sigma 8afc3706-d0f7-509b-b495-509e7bd85ab4: Process created: urlhaus_47_4e0d84da-c118-4423-83c4-2b0b4883f3ec (urlhaus_47_4e0d84da-c118-4423-83c4-2b0b4883f3ec --urlhaus-validation)
  ATT&CK: T1059
  Why: Process selector chosen for windows telemetry from executable and command line evidence using: CommandLine|contains, Image|endswith.
- Sigma b3ce27d2-df40-5311-8d06-dfc2c119b876: File dropped to user-accessible path: C:\Users\Public\Downloads\urlhaus_47_4e0d84da-c118-4423-83c4-2b0b4883f3ec
  ATT&CK: T1105
  Why: File selector chosen for windows telemetry from observed file path evidence using: TargetFilename|contains.
- Sigma d75d2ceb-b7c4-50a8-ab31-ee6c71d9c0d9: DNS lookup observed: lvt.vip1xbet.net
  ATT&CK: T1071.004
  Why: Network selector chosen for windows telemetry from observed DNS/domain evidence using: QueryName|contains.
- Sigma c88175f3-27fe-5c20-be22-a8096752a527: HTTP connection observed: https://lvt.vip1xbet.net/4e0d84da-c118-4423-83c4-2b0b4883f3ec
  ATT&CK: T1071.001
  Why: Network selector chosen for windows telemetry from observed network evidence using: DestinationHostname|contains.
- Wazuh 102369: 8afc3706-d0f7-509b-b495-509e7bd85ab4
  Why: Process creation converted using Sysmon parent rule 61603 and win.eventdata image and commandLine fields when available.
- Wazuh 107820: b3ce27d2-df40-5311-8d06-dfc2c119b876
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 111431: d75d2ceb-b7c4-50a8-ab31-ee6c71d9c0d9
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 119611: c88175f3-27fe-5c20-be22-a8096752a527
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.

## Validation Warnings
- No validation warnings.

## Risk Scoring
- Average risk score: 77.5
- Average ATT&CK confidence: 0.7875

## Review Status
- unreviewed

## Output Artifact List
- Navigator techniques: 4
- Sigma rule count: 4
- Wazuh rule count: 4