# Malware Behavior Detection Report

## Sample Overview
- Sandbox: cuckoo
- Sample name: urlhaus_45_bin.sh
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
- ipv4: 222.141.47.94
- url: http://222.141.47.94:48327/bin.sh
- file_path: C:\Users\Public\Downloads\urlhaus_45_bin.sh

## ATT&CK Mappings
- T1059
- T1071
- T1071.001
- T1105
- T1571

## Generated Sigma Rules
- 6051a320-9af4-569b-8d79-29d13244bc68
- e736691e-eb6d-5b5c-b9bf-4e26a094d72d
- 6a683bce-b97f-5f02-be0e-0ba862e1f152
- 6a4ae7ce-6d30-5635-998f-2c831b8973f2

## Generated Wazuh Rules
- 101628
- 100545
- 108909
- 100241

## Rule Generation Rationale
- Sigma 6051a320-9af4-569b-8d79-29d13244bc68: Process created: urlhaus_45_bin.sh (urlhaus_45_bin.sh --urlhaus-validation)
  ATT&CK: T1059
  Why: Process selector chosen for windows telemetry from executable and command line evidence using: CommandLine|contains, Image|endswith.
- Sigma e736691e-eb6d-5b5c-b9bf-4e26a094d72d: File dropped to user-accessible path: C:\Users\Public\Downloads\urlhaus_45_bin.sh
  ATT&CK: T1105
  Why: File selector chosen for windows telemetry from observed file path evidence using: TargetFilename|contains.
- Sigma 6a683bce-b97f-5f02-be0e-0ba862e1f152: IP connection observed: 222.141.47.94
  ATT&CK: T1071
  Why: Network selector chosen for windows telemetry from observed IP evidence using: DestinationIp.
- Sigma 6a4ae7ce-6d30-5635-998f-2c831b8973f2: HTTP connection observed: http://222.141.47.94:48327/bin.sh
  ATT&CK: T1071.001, T1571
  Why: Network selector chosen for windows telemetry from observed IP evidence using: DestinationIp.
- Wazuh 101628: 6051a320-9af4-569b-8d79-29d13244bc68
  Why: Process creation converted using Sysmon parent rule 61603 and win.eventdata image and commandLine fields when available.
- Wazuh 100545: e736691e-eb6d-5b5c-b9bf-4e26a094d72d
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 108909: 6a683bce-b97f-5f02-be0e-0ba862e1f152
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 100241: 6a4ae7ce-6d30-5635-998f-2c831b8973f2
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.

## Validation Warnings
- No validation warnings.

## Risk Scoring
- Average risk score: 77.5
- Average ATT&CK confidence: 0.74

## Review Status
- unreviewed

## Output Artifact List
- Navigator techniques: 5
- Sigma rule count: 4
- Wazuh rule count: 4