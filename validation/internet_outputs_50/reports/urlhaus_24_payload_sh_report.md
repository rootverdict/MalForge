# Malware Behavior Detection Report

## Sample Overview
- Sandbox: cuckoo
- Sample name: urlhaus_24_payload.sh
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
- ipv4: 85.204.125.67
- url: http://85.204.125.67:8080/payload.sh
- file_path: C:\Users\Public\Downloads\urlhaus_24_payload.sh

## ATT&CK Mappings
- T1059
- T1071
- T1071.001
- T1105
- T1571

## Generated Sigma Rules
- b947a38f-1275-5fc2-afb6-f3008cdcb2b5
- e71ad6d8-c786-5b2b-bf0c-ffaeb7496186
- 7ad1782e-d8eb-5e18-9c16-b4ea64b90454
- 1487f7ee-6a72-5e70-a530-25e4b12880f1

## Generated Wazuh Rules
- 112659
- 106333
- 117321
- 116049

## Rule Generation Rationale
- Sigma b947a38f-1275-5fc2-afb6-f3008cdcb2b5: Process created: urlhaus_24_payload.sh (urlhaus_24_payload.sh --urlhaus-validation)
  ATT&CK: T1059
  Why: Process selector chosen for windows telemetry from executable and command line evidence using: CommandLine|contains, Image|endswith.
- Sigma e71ad6d8-c786-5b2b-bf0c-ffaeb7496186: File dropped to user-accessible path: C:\Users\Public\Downloads\urlhaus_24_payload.sh
  ATT&CK: T1105
  Why: File selector chosen for windows telemetry from observed file path evidence using: TargetFilename|contains.
- Sigma 7ad1782e-d8eb-5e18-9c16-b4ea64b90454: IP connection observed: 85.204.125.67
  ATT&CK: T1071
  Why: Network selector chosen for windows telemetry from observed IP evidence using: DestinationIp.
- Sigma 1487f7ee-6a72-5e70-a530-25e4b12880f1: HTTP connection observed: http://85.204.125.67:8080/payload.sh
  ATT&CK: T1071.001, T1571
  Why: Network selector chosen for windows telemetry from observed IP evidence using: DestinationIp.
- Wazuh 112659: b947a38f-1275-5fc2-afb6-f3008cdcb2b5
  Why: Process creation converted using Sysmon parent rule 61603 and win.eventdata image and commandLine fields when available.
- Wazuh 106333: e71ad6d8-c786-5b2b-bf0c-ffaeb7496186
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 117321: 7ad1782e-d8eb-5e18-9c16-b4ea64b90454
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 116049: 1487f7ee-6a72-5e70-a530-25e4b12880f1
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