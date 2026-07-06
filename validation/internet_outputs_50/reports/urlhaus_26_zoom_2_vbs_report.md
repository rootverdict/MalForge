# Malware Behavior Detection Report

## Sample Overview
- Sandbox: cuckoo
- Sample name: urlhaus_26_Zoom 2.vbs
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
- url: https://jim-s.com/ab/Zoom_meeting/Meeting%20Invite%20HTML/downloads/windows/aboki/Zoom%202.vbs
- file_path: C:\Users\Public\Downloads\urlhaus_26_Zoom 2.vbs

## ATT&CK Mappings
- T1059
- T1071.001
- T1071.004
- T1105

## Generated Sigma Rules
- e058c454-7c1d-58e5-b6c4-88b6725595e3
- 87bf2722-b5eb-5bc0-8b02-89a242188dc6
- 57fe2415-fdc0-5175-8760-e956414af378
- aac72cc2-5105-5855-8ed2-3f7bd6433761

## Generated Wazuh Rules
- 102628
- 109987
- 119856
- 111608

## Rule Generation Rationale
- Sigma e058c454-7c1d-58e5-b6c4-88b6725595e3: Process created: urlhaus_26_Zoom 2.vbs (urlhaus_26_Zoom 2.vbs --urlhaus-validation)
  ATT&CK: T1059
  Why: Process selector chosen for windows telemetry from executable and command line evidence using: CommandLine|contains, Image|endswith.
- Sigma 87bf2722-b5eb-5bc0-8b02-89a242188dc6: File dropped to user-accessible path: C:\Users\Public\Downloads\urlhaus_26_Zoom 2.vbs
  ATT&CK: T1105
  Why: File selector chosen for windows telemetry from observed file path evidence using: TargetFilename|contains.
- Sigma 57fe2415-fdc0-5175-8760-e956414af378: DNS lookup observed: jim-s.com
  ATT&CK: T1071.004
  Why: Network selector chosen for windows telemetry from observed DNS/domain evidence using: QueryName|contains.
- Sigma aac72cc2-5105-5855-8ed2-3f7bd6433761: HTTP connection observed: https://jim-s.com/ab/Zoom_meeting/Meeting%20Invite%20HTML/downloads/windows/aboki/Zoom%202.vbs
  ATT&CK: T1071.001
  Why: Network selector chosen for windows telemetry from observed network evidence using: DestinationHostname|contains.
- Wazuh 102628: e058c454-7c1d-58e5-b6c4-88b6725595e3
  Why: Process creation converted using Sysmon parent rule 61603 and win.eventdata image and commandLine fields when available.
- Wazuh 109987: 87bf2722-b5eb-5bc0-8b02-89a242188dc6
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 119856: 57fe2415-fdc0-5175-8760-e956414af378
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 111608: aac72cc2-5105-5855-8ed2-3f7bd6433761
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