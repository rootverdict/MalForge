# Malware Behavior Detection Report

## Sample Overview
- Sandbox: cuckoo
- Sample name: urlhaus_34_file_ac12f1da1bdab1e0.exe
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
- url: http://91.92.242.236/files-129312398/files/file_ac12f1da1bdab1e0.exe
- file_path: C:\Users\Public\Downloads\urlhaus_34_file_ac12f1da1bdab1e0.exe
- file_path: urlhaus_34_file_ac12f1da1bdab1e0.exe

## ATT&CK Mappings
- T1059
- T1071
- T1071.001
- T1105

## Generated Sigma Rules
- b1820c8c-a134-5318-9891-720415a68a71
- 1ea98ce1-4fbb-5892-925f-84498192456c
- b0187ff2-6e92-55fd-a98d-c654b7145ecd
- 92fd40f4-c741-5d78-83a6-cfc447dea77f

## Generated Wazuh Rules
- 111464
- 111915
- 104942
- 109168

## Rule Generation Rationale
- Sigma b1820c8c-a134-5318-9891-720415a68a71: Process created: urlhaus_34_file_ac12f1da1bdab1e0.exe (urlhaus_34_file_ac12f1da1bdab1e0.exe --urlhaus-validation)
  ATT&CK: T1059
  Why: Process selector chosen for windows telemetry from executable and command line evidence using: CommandLine|contains, Image|endswith.
- Sigma 1ea98ce1-4fbb-5892-925f-84498192456c: File dropped to user-accessible path: C:\Users\Public\Downloads\urlhaus_34_file_ac12f1da1bdab1e0.exe
  ATT&CK: T1105
  Why: File selector chosen for windows telemetry from observed file path evidence using: TargetFilename|contains.
- Sigma b0187ff2-6e92-55fd-a98d-c654b7145ecd: IP connection observed: 91.92.242.236
  ATT&CK: T1071
  Why: Network selector chosen for windows telemetry from observed IP evidence using: DestinationIp.
- Sigma 92fd40f4-c741-5d78-83a6-cfc447dea77f: HTTP connection observed: http://91.92.242.236/files-129312398/files/file_ac12f1da1bdab1e0.exe
  ATT&CK: T1071.001
  Why: Network selector chosen for windows telemetry from observed IP evidence using: DestinationIp.
- Wazuh 111464: b1820c8c-a134-5318-9891-720415a68a71
  Why: Process creation converted using Sysmon parent rule 61603 and win.eventdata image and commandLine fields when available.
- Wazuh 111915: 1ea98ce1-4fbb-5892-925f-84498192456c
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 104942: b0187ff2-6e92-55fd-a98d-c654b7145ecd
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 109168: 92fd40f4-c741-5d78-83a6-cfc447dea77f
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