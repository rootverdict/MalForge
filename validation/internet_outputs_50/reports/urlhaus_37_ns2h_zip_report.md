# Malware Behavior Detection Report

## Sample Overview
- Sandbox: cuckoo
- Sample name: urlhaus_37_NS2H.zip
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
- domain: easyfiles.cc
- url: https://easyfiles.cc/2026/6/ce0a3ffe-dc52-470b-8686-99cd20029255/NS2H.zip
- file_path: C:\Users\Public\Downloads\urlhaus_37_NS2H.zip

## ATT&CK Mappings
- T1059
- T1071.001
- T1071.004
- T1105

## Generated Sigma Rules
- a28177e4-35d4-539b-a435-e9b8e6b4ce28
- fc626222-fa92-544e-9594-725a3efd775e
- becfb152-5a83-57c8-a7b3-fab4d6aea638
- e9db57a4-2e0d-508b-a93e-43dba4c84dd4

## Generated Wazuh Rules
- 111453
- 105363
- 107509
- 119429

## Rule Generation Rationale
- Sigma a28177e4-35d4-539b-a435-e9b8e6b4ce28: Process created: urlhaus_37_NS2H.zip (urlhaus_37_NS2H.zip --urlhaus-validation)
  ATT&CK: T1059
  Why: Process selector chosen for windows telemetry from executable and command line evidence using: CommandLine|contains, Image|endswith.
- Sigma fc626222-fa92-544e-9594-725a3efd775e: File dropped to user-accessible path: C:\Users\Public\Downloads\urlhaus_37_NS2H.zip
  ATT&CK: T1105
  Why: File selector chosen for windows telemetry from observed file path evidence using: TargetFilename|contains.
- Sigma becfb152-5a83-57c8-a7b3-fab4d6aea638: DNS lookup observed: easyfiles.cc
  ATT&CK: T1071.004
  Why: Network selector chosen for windows telemetry from observed DNS/domain evidence using: QueryName|contains.
- Sigma e9db57a4-2e0d-508b-a93e-43dba4c84dd4: HTTP connection observed: https://easyfiles.cc/2026/6/ce0a3ffe-dc52-470b-8686-99cd20029255/NS2H.zip
  ATT&CK: T1071.001
  Why: Network selector chosen for windows telemetry from observed network evidence using: DestinationHostname|contains.
- Wazuh 111453: a28177e4-35d4-539b-a435-e9b8e6b4ce28
  Why: Process creation converted using Sysmon parent rule 61603 and win.eventdata image and commandLine fields when available.
- Wazuh 105363: fc626222-fa92-544e-9594-725a3efd775e
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 107509: becfb152-5a83-57c8-a7b3-fab4d6aea638
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 119429: e9db57a4-2e0d-508b-a93e-43dba4c84dd4
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