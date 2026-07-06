# Malware Behavior Detection Report

## Sample Overview
- Sandbox: cuckoo
- Sample name: urlhaus_10_Zoom 21.vbs
- MD5: n/a
- SHA256: n/a
- Generated at: 2026-07-01T10:00:17+00:00

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
- domain: jim-s.com
- url: https://jim-s.com/ab/Zoom_meeting/Meeting%20Invite%20HTML/downloads/windows/aboki/Zoom%2021.vbs
- file_path: C:\Users\Public\Downloads\urlhaus_10_Zoom 21.vbs

## ATT&CK Mappings
- T1059
- T1071.001
- T1071.004
- T1105

## Generated Sigma Rules
- fb2fe7c7-ea4e-574a-8511-0f63df1de2db
- 842564b1-22df-570a-b09f-9d4618f51894
- 57fe2415-fdc0-5175-8760-e956414af378
- bcc9197f-ad2a-59a2-8a49-ff364f01b187

## Generated Wazuh Rules
- 113787
- 103363
- 119856
- 114844

## Rule Generation Rationale
- Sigma fb2fe7c7-ea4e-574a-8511-0f63df1de2db: Process created: urlhaus_10_Zoom 21.vbs (urlhaus_10_Zoom 21.vbs --urlhaus-validation)
  ATT&CK: T1059
  Why: Process selector chosen for windows telemetry from executable and command line evidence using: CommandLine|contains, Image|endswith.
- Sigma 842564b1-22df-570a-b09f-9d4618f51894: File dropped to user-accessible path: C:\Users\Public\Downloads\urlhaus_10_Zoom 21.vbs
  ATT&CK: T1105
  Why: File selector chosen for windows telemetry from observed file path evidence using: TargetFilename|contains.
- Sigma 57fe2415-fdc0-5175-8760-e956414af378: DNS lookup observed: jim-s.com
  ATT&CK: T1071.004
  Why: Network selector chosen for windows telemetry from observed DNS/domain evidence using: QueryName|contains.
- Sigma bcc9197f-ad2a-59a2-8a49-ff364f01b187: HTTP connection observed: https://jim-s.com/ab/Zoom_meeting/Meeting%20Invite%20HTML/downloads/windows/aboki/Zoom%2021.vbs
  ATT&CK: T1071.001
  Why: Network selector chosen for windows telemetry from observed network evidence using: DestinationHostname|contains.
- Wazuh 113787: fb2fe7c7-ea4e-574a-8511-0f63df1de2db
  Why: Process creation converted using Sysmon parent rule 61603 and win.eventdata image and commandLine fields when available.
- Wazuh 103363: 842564b1-22df-570a-b09f-9d4618f51894
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 119856: 57fe2415-fdc0-5175-8760-e956414af378
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 114844: bcc9197f-ad2a-59a2-8a49-ff364f01b187
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