# Malware Behavior Detection Report

## Sample Overview
- Sandbox: cuckoo
- Sample name: urlhaus_41_i
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
- url: http://222.141.47.94:48327/i
- file_path: C:\Users\Public\Downloads\urlhaus_41_i

## ATT&CK Mappings
- T1059
- T1071
- T1071.001
- T1105
- T1571

## Generated Sigma Rules
- 7dca569e-c6df-54eb-acb3-7179cbeeb873
- acd5db0c-6115-5036-b348-8f204ce45313
- 6a683bce-b97f-5f02-be0e-0ba862e1f152
- 638cd98f-15e2-51ec-bf74-51ae7882582c

## Generated Wazuh Rules
- 107795
- 102373
- 108909
- 110583

## Rule Generation Rationale
- Sigma 7dca569e-c6df-54eb-acb3-7179cbeeb873: Process created: urlhaus_41_i (urlhaus_41_i --urlhaus-validation)
  ATT&CK: T1059
  Why: Process selector chosen for windows telemetry from executable and command line evidence using: CommandLine|contains, Image|endswith.
- Sigma acd5db0c-6115-5036-b348-8f204ce45313: File dropped to user-accessible path: C:\Users\Public\Downloads\urlhaus_41_i
  ATT&CK: T1105
  Why: File selector chosen for windows telemetry from observed file path evidence using: TargetFilename|contains.
- Sigma 6a683bce-b97f-5f02-be0e-0ba862e1f152: IP connection observed: 222.141.47.94
  ATT&CK: T1071
  Why: Network selector chosen for windows telemetry from observed IP evidence using: DestinationIp.
- Sigma 638cd98f-15e2-51ec-bf74-51ae7882582c: HTTP connection observed: http://222.141.47.94:48327/i
  ATT&CK: T1071.001, T1571
  Why: Network selector chosen for windows telemetry from observed IP evidence using: DestinationIp.
- Wazuh 107795: 7dca569e-c6df-54eb-acb3-7179cbeeb873
  Why: Process creation converted using Sysmon parent rule 61603 and win.eventdata image and commandLine fields when available.
- Wazuh 102373: acd5db0c-6115-5036-b348-8f204ce45313
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 108909: 6a683bce-b97f-5f02-be0e-0ba862e1f152
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 110583: 638cd98f-15e2-51ec-bf74-51ae7882582c
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