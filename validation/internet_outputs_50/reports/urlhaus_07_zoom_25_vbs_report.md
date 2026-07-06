# Malware Behavior Detection Report

## Sample Overview
- Sandbox: cuckoo
- Sample name: urlhaus_07_Zoom 25.vbs
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
- url: https://jim-s.com/ab/Zoom_meeting/Meeting%20Invite%20HTML/downloads/windows/aboki/Zoom%2025.vbs
- file_path: C:\Users\Public\Downloads\urlhaus_07_Zoom 25.vbs

## ATT&CK Mappings
- T1059
- T1071.001
- T1071.004
- T1105

## Generated Sigma Rules
- d98e6865-f21f-5cf0-8d4c-e3365901f44b
- 1f7426c8-d7bf-52cc-bd5a-2d645340538a
- 57fe2415-fdc0-5175-8760-e956414af378
- 4e46eac6-18e0-5e12-b260-5ed3bd82f744

## Generated Wazuh Rules
- 102307
- 116257
- 119856
- 103859

## Rule Generation Rationale
- Sigma d98e6865-f21f-5cf0-8d4c-e3365901f44b: Process created: urlhaus_07_Zoom 25.vbs (urlhaus_07_Zoom 25.vbs --urlhaus-validation)
  ATT&CK: T1059
  Why: Process selector chosen for windows telemetry from executable and command line evidence using: CommandLine|contains, Image|endswith.
- Sigma 1f7426c8-d7bf-52cc-bd5a-2d645340538a: File dropped to user-accessible path: C:\Users\Public\Downloads\urlhaus_07_Zoom 25.vbs
  ATT&CK: T1105
  Why: File selector chosen for windows telemetry from observed file path evidence using: TargetFilename|contains.
- Sigma 57fe2415-fdc0-5175-8760-e956414af378: DNS lookup observed: jim-s.com
  ATT&CK: T1071.004
  Why: Network selector chosen for windows telemetry from observed DNS/domain evidence using: QueryName|contains.
- Sigma 4e46eac6-18e0-5e12-b260-5ed3bd82f744: HTTP connection observed: https://jim-s.com/ab/Zoom_meeting/Meeting%20Invite%20HTML/downloads/windows/aboki/Zoom%2025.vbs
  ATT&CK: T1071.001
  Why: Network selector chosen for windows telemetry from observed network evidence using: DestinationHostname|contains.
- Wazuh 102307: d98e6865-f21f-5cf0-8d4c-e3365901f44b
  Why: Process creation converted using Sysmon parent rule 61603 and win.eventdata image and commandLine fields when available.
- Wazuh 116257: 1f7426c8-d7bf-52cc-bd5a-2d645340538a
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 119856: 57fe2415-fdc0-5175-8760-e956414af378
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 103859: 4e46eac6-18e0-5e12-b260-5ed3bd82f744
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