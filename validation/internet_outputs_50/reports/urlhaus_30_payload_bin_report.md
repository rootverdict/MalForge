# Malware Behavior Detection Report

## Sample Overview
- Sandbox: cuckoo
- Sample name: urlhaus_30_payload.bin
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
- domain: mdftw8lo.btyek.website
- url: https://mdftw8lo.btyek.website/?ublib=bf723810-216b-4253-949d-cd83a30499d4
- file_path: C:\Users\Public\Downloads\urlhaus_30_payload.bin
- file_path: urlhaus_30_payload.bin

## ATT&CK Mappings
- T1059
- T1071.001
- T1071.004
- T1105

## Generated Sigma Rules
- d44c2b12-b533-5511-b862-70b69b81ae54
- f869743c-89d1-5642-a897-2fcc60fd7999
- 5a58eb61-cfd5-5782-803a-54d887d37989
- 4715f890-3e2d-5bd4-8f71-ecf3fc7ccb29

## Generated Wazuh Rules
- 100830
- 109346
- 109451
- 114363

## Rule Generation Rationale
- Sigma d44c2b12-b533-5511-b862-70b69b81ae54: Process created: urlhaus_30_payload.bin (urlhaus_30_payload.bin --urlhaus-validation)
  ATT&CK: T1059
  Why: Process selector chosen for windows telemetry from executable and command line evidence using: CommandLine|contains, Image|endswith.
- Sigma f869743c-89d1-5642-a897-2fcc60fd7999: File dropped to user-accessible path: C:\Users\Public\Downloads\urlhaus_30_payload.bin
  ATT&CK: T1105
  Why: File selector chosen for windows telemetry from observed file path evidence using: TargetFilename|contains.
- Sigma 5a58eb61-cfd5-5782-803a-54d887d37989: DNS lookup observed: mdftw8lo.btyek.website
  ATT&CK: T1071.004
  Why: Network selector chosen for windows telemetry from observed DNS/domain evidence using: QueryName|contains.
- Sigma 4715f890-3e2d-5bd4-8f71-ecf3fc7ccb29: HTTP connection observed: https://mdftw8lo.btyek.website/?ublib=bf723810-216b-4253-949d-cd83a30499d4
  ATT&CK: T1071.001
  Why: Network selector chosen for windows telemetry from observed network evidence using: DestinationHostname|contains.
- Wazuh 100830: d44c2b12-b533-5511-b862-70b69b81ae54
  Why: Process creation converted using Sysmon parent rule 61603 and win.eventdata image and commandLine fields when available.
- Wazuh 109346: f869743c-89d1-5642-a897-2fcc60fd7999
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 109451: 5a58eb61-cfd5-5782-803a-54d887d37989
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 114363: 4715f890-3e2d-5bd4-8f71-ecf3fc7ccb29
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