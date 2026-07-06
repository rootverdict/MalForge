# Malware Behavior Detection Report

## Sample Overview
- Sandbox: cuckoo
- Sample name: urlhaus_28_file_88c4af189a4c6c59.exe
- MD5: n/a
- SHA256: n/a
- Generated at: 2026-07-01T10:00:18+00:00

## Behavior Summary

## Source Data Limitations
- Missing payload hashes: md5, sha1, sha256
- Note: Payload hashes unavailable from source report.
- file: 2
- network: 2
- process: 1

## IOC Summary
- file_path: 2
- ipv4: 1
- url: 1

### IOC Values
- ipv4: 91.92.242.236
- url: http://91.92.242.236/files-129312398/files/file_88c4af189a4c6c59.exe
- file_path: C:\Users\Public\Downloads\urlhaus_28_file_88c4af189a4c6c59.exe
- file_path: urlhaus_28_file_88c4af189a4c6c59.exe

## ATT&CK Mappings
- T1059
- T1071
- T1071.001
- T1105

## Generated Sigma Rules
- aa7d7222-fedb-5072-94b6-b19671d9cafa
- ca46716b-abb2-5f7e-a47e-1a997983162b
- b0187ff2-6e92-55fd-a98d-c654b7145ecd
- 9d7b9d7d-67a5-56f4-bfd9-9f822bf7ee1e

## Generated Wazuh Rules
- 103801
- 117649
- 104942
- 113190

## Rule Generation Rationale
- Sigma aa7d7222-fedb-5072-94b6-b19671d9cafa: Process created: urlhaus_28_file_88c4af189a4c6c59.exe (urlhaus_28_file_88c4af189a4c6c59.exe --urlhaus-validation)
  ATT&CK: T1059
  Why: Process selector chosen for windows telemetry from executable and command line evidence using: CommandLine|contains, Image|endswith.
- Sigma ca46716b-abb2-5f7e-a47e-1a997983162b: File dropped to user-accessible path: C:\Users\Public\Downloads\urlhaus_28_file_88c4af189a4c6c59.exe
  ATT&CK: T1105
  Why: File selector chosen for windows telemetry from observed file path evidence using: TargetFilename|contains.
- Sigma b0187ff2-6e92-55fd-a98d-c654b7145ecd: IP connection observed: 91.92.242.236
  ATT&CK: T1071
  Why: Network selector chosen for windows telemetry from observed IP evidence using: DestinationIp.
- Sigma 9d7b9d7d-67a5-56f4-bfd9-9f822bf7ee1e: HTTP connection observed: http://91.92.242.236/files-129312398/files/file_88c4af189a4c6c59.exe
  ATT&CK: T1071.001
  Why: Network selector chosen for windows telemetry from observed IP evidence using: DestinationIp.
- Wazuh 103801: aa7d7222-fedb-5072-94b6-b19671d9cafa
  Why: Process creation converted using Sysmon parent rule 61603 and win.eventdata image and commandLine fields when available.
- Wazuh 117649: ca46716b-abb2-5f7e-a47e-1a997983162b
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 104942: b0187ff2-6e92-55fd-a98d-c654b7145ecd
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 113190: 9d7b9d7d-67a5-56f4-bfd9-9f822bf7ee1e
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.

## Validation Warnings
- No validation warnings.

## Risk Scoring
- Average risk score: 77.5
- Average ATT&CK confidence: 0.71

## Review Status
- unreviewed

## Output Artifact List
- Navigator techniques: 4
- Sigma rule count: 4
- Wazuh rule count: 4