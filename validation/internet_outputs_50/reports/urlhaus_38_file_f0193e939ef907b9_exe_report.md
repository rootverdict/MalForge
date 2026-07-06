# Malware Behavior Detection Report

## Sample Overview
- Sandbox: cuckoo
- Sample name: urlhaus_38_file_f0193e939ef907b9.exe
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
- url: http://91.92.242.236/files-129312398/files/file_f0193e939ef907b9.exe
- file_path: C:\Users\Public\Downloads\urlhaus_38_file_f0193e939ef907b9.exe
- file_path: urlhaus_38_file_f0193e939ef907b9.exe

## ATT&CK Mappings
- T1059
- T1071
- T1071.001
- T1105

## Generated Sigma Rules
- e925dd50-9246-5618-bb1e-aec78ec0a203
- e582ab25-2e58-5341-b448-20b58b384d13
- b0187ff2-6e92-55fd-a98d-c654b7145ecd
- b04068b8-9aca-5895-a9b1-f0f75c513afb

## Generated Wazuh Rules
- 112607
- 114852
- 104942
- 109267

## Rule Generation Rationale
- Sigma e925dd50-9246-5618-bb1e-aec78ec0a203: Process created: urlhaus_38_file_f0193e939ef907b9.exe (urlhaus_38_file_f0193e939ef907b9.exe --urlhaus-validation)
  ATT&CK: T1059
  Why: Process selector chosen for windows telemetry from executable and command line evidence using: CommandLine|contains, Image|endswith.
- Sigma e582ab25-2e58-5341-b448-20b58b384d13: File dropped to user-accessible path: C:\Users\Public\Downloads\urlhaus_38_file_f0193e939ef907b9.exe
  ATT&CK: T1105
  Why: File selector chosen for windows telemetry from observed file path evidence using: TargetFilename|contains.
- Sigma b0187ff2-6e92-55fd-a98d-c654b7145ecd: IP connection observed: 91.92.242.236
  ATT&CK: T1071
  Why: Network selector chosen for windows telemetry from observed IP evidence using: DestinationIp.
- Sigma b04068b8-9aca-5895-a9b1-f0f75c513afb: HTTP connection observed: http://91.92.242.236/files-129312398/files/file_f0193e939ef907b9.exe
  ATT&CK: T1071.001
  Why: Network selector chosen for windows telemetry from observed IP evidence using: DestinationIp.
- Wazuh 112607: e925dd50-9246-5618-bb1e-aec78ec0a203
  Why: Process creation converted using Sysmon parent rule 61603 and win.eventdata image and commandLine fields when available.
- Wazuh 114852: e582ab25-2e58-5341-b448-20b58b384d13
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 104942: b0187ff2-6e92-55fd-a98d-c654b7145ecd
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 109267: b04068b8-9aca-5895-a9b1-f0f75c513afb
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