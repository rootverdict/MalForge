# Malware Behavior Detection Report

## Sample Overview
- Sandbox: cuckoo
- Sample name: urlhaus_18_Zoom 17.vbs
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
- domain: jim-s.com
- url: https://jim-s.com/ab/Zoom_meeting/Meeting%20Invite%20HTML/downloads/windows/aboki/Zoom%2017.vbs
- file_path: C:\Users\Public\Downloads\urlhaus_18_Zoom 17.vbs

## ATT&CK Mappings
- T1059
- T1071.001
- T1071.004
- T1105

## Generated Sigma Rules
- 28256687-d88d-50de-bb1f-c9eb2abc5653
- c1f4f5e0-6817-5be8-9bb3-475d8b9df186
- 57fe2415-fdc0-5175-8760-e956414af378
- d669d9ae-827d-55aa-be7d-93db2f5c351f

## Generated Wazuh Rules
- 115551
- 119775
- 119856
- 117516

## Rule Generation Rationale
- Sigma 28256687-d88d-50de-bb1f-c9eb2abc5653: Process created: urlhaus_18_Zoom 17.vbs (urlhaus_18_Zoom 17.vbs --urlhaus-validation)
  ATT&CK: T1059
  Why: Process selector chosen for windows telemetry from executable and command line evidence using: CommandLine|contains, Image|endswith.
- Sigma c1f4f5e0-6817-5be8-9bb3-475d8b9df186: File dropped to user-accessible path: C:\Users\Public\Downloads\urlhaus_18_Zoom 17.vbs
  ATT&CK: T1105
  Why: File selector chosen for windows telemetry from observed file path evidence using: TargetFilename|contains.
- Sigma 57fe2415-fdc0-5175-8760-e956414af378: DNS lookup observed: jim-s.com
  ATT&CK: T1071.004
  Why: Network selector chosen for windows telemetry from observed DNS/domain evidence using: QueryName|contains.
- Sigma d669d9ae-827d-55aa-be7d-93db2f5c351f: HTTP connection observed: https://jim-s.com/ab/Zoom_meeting/Meeting%20Invite%20HTML/downloads/windows/aboki/Zoom%2017.vbs
  ATT&CK: T1071.001
  Why: Network selector chosen for windows telemetry from observed network evidence using: DestinationHostname|contains.
- Wazuh 115551: 28256687-d88d-50de-bb1f-c9eb2abc5653
  Why: Process creation converted using Sysmon parent rule 61603 and win.eventdata image and commandLine fields when available.
- Wazuh 119775: c1f4f5e0-6817-5be8-9bb3-475d8b9df186
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 119856: 57fe2415-fdc0-5175-8760-e956414af378
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 117516: d669d9ae-827d-55aa-be7d-93db2f5c351f
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