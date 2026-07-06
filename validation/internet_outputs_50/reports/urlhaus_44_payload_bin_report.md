# Malware Behavior Detection Report

## Sample Overview
- Sandbox: cuckoo
- Sample name: urlhaus_44_payload.bin
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
- file_path: 2
- url: 1

### IOC Values
- domain: squvbf6p.btyek.one
- url: https://squvbf6p.btyek.one/?ublib=3ad123de-3852-4784-9864-dc443665a2e0
- file_path: C:\Users\Public\Downloads\urlhaus_44_payload.bin
- file_path: urlhaus_44_payload.bin

## ATT&CK Mappings
- T1059
- T1071.001
- T1071.004
- T1105

## Generated Sigma Rules
- 50e6d467-9432-5656-a206-36688570a2e5
- ebaa20ae-857f-5e7e-b5c8-03e6e0ab9f89
- 71c59458-a019-54d4-aadd-9da162f054d9
- dfca469a-1a8e-5ebf-bc84-980eae038dd4

## Generated Wazuh Rules
- 114223
- 114722
- 104560
- 119690

## Rule Generation Rationale
- Sigma 50e6d467-9432-5656-a206-36688570a2e5: Process created: urlhaus_44_payload.bin (urlhaus_44_payload.bin --urlhaus-validation)
  ATT&CK: T1059
  Why: Process selector chosen for windows telemetry from executable and command line evidence using: CommandLine|contains, Image|endswith.
- Sigma ebaa20ae-857f-5e7e-b5c8-03e6e0ab9f89: File dropped to user-accessible path: C:\Users\Public\Downloads\urlhaus_44_payload.bin
  ATT&CK: T1105
  Why: File selector chosen for windows telemetry from observed file path evidence using: TargetFilename|contains.
- Sigma 71c59458-a019-54d4-aadd-9da162f054d9: DNS lookup observed: squvbf6p.btyek.one
  ATT&CK: T1071.004
  Why: Network selector chosen for windows telemetry from observed DNS/domain evidence using: QueryName|contains.
- Sigma dfca469a-1a8e-5ebf-bc84-980eae038dd4: HTTP connection observed: https://squvbf6p.btyek.one/?ublib=3ad123de-3852-4784-9864-dc443665a2e0
  ATT&CK: T1071.001
  Why: Network selector chosen for windows telemetry from observed network evidence using: DestinationHostname|contains.
- Wazuh 114223: 50e6d467-9432-5656-a206-36688570a2e5
  Why: Process creation converted using Sysmon parent rule 61603 and win.eventdata image and commandLine fields when available.
- Wazuh 114722: ebaa20ae-857f-5e7e-b5c8-03e6e0ab9f89
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 104560: 71c59458-a019-54d4-aadd-9da162f054d9
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 119690: dfca469a-1a8e-5ebf-bc84-980eae038dd4
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