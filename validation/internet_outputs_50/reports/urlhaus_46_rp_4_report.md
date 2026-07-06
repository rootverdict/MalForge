# Malware Behavior Detection Report

## Sample Overview
- Sandbox: cuckoo
- Sample name: urlhaus_46_rp_4
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
- domain: cdn.jsdelivr.net
- url: https://cdn.jsdelivr.net/gh/recavrylog/roandatech@1cc983d/rp_4
- file_path: C:\Users\Public\Downloads\urlhaus_46_rp_4

## ATT&CK Mappings
- T1059
- T1071.001
- T1071.004
- T1105

## Generated Sigma Rules
- 7e4dad60-e4d5-5ef1-937c-f44feb9a6e4f
- bfa0c2e0-8da0-5b51-a38d-afb7f2e0d29e
- c0936992-e835-5039-836b-06b9b6f8849d
- 375080b9-11fb-5a7b-a2f8-11811c9eb758

## Generated Wazuh Rules
- 116389
- 116668
- 101483
- 112301

## Rule Generation Rationale
- Sigma 7e4dad60-e4d5-5ef1-937c-f44feb9a6e4f: Process created: urlhaus_46_rp_4 (urlhaus_46_rp_4 --urlhaus-validation)
  ATT&CK: T1059
  Why: Process selector chosen for windows telemetry from executable and command line evidence using: CommandLine|contains, Image|endswith.
- Sigma bfa0c2e0-8da0-5b51-a38d-afb7f2e0d29e: File dropped to user-accessible path: C:\Users\Public\Downloads\urlhaus_46_rp_4
  ATT&CK: T1105
  Why: File selector chosen for windows telemetry from observed file path evidence using: TargetFilename|contains.
- Sigma c0936992-e835-5039-836b-06b9b6f8849d: DNS lookup observed: cdn.jsdelivr.net
  ATT&CK: T1071.004
  Why: Network selector chosen for windows telemetry from observed DNS/domain evidence using: QueryName|contains.
- Sigma 375080b9-11fb-5a7b-a2f8-11811c9eb758: HTTP connection observed: https://cdn.jsdelivr.net/gh/recavrylog/roandatech@1cc983d/rp_4
  ATT&CK: T1071.001
  Why: Network selector chosen for windows telemetry from observed network evidence using: DestinationHostname|contains.
- Wazuh 116389: 7e4dad60-e4d5-5ef1-937c-f44feb9a6e4f
  Why: Process creation converted using Sysmon parent rule 61603 and win.eventdata image and commandLine fields when available.
- Wazuh 116668: bfa0c2e0-8da0-5b51-a38d-afb7f2e0d29e
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 101483: c0936992-e835-5039-836b-06b9b6f8849d
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 112301: 375080b9-11fb-5a7b-a2f8-11811c9eb758
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