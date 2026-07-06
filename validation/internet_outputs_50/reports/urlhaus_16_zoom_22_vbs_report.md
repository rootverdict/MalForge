# Malware Behavior Detection Report

## Sample Overview
- Sandbox: cuckoo
- Sample name: urlhaus_16_Zoom 22.vbs
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
- url: https://jim-s.com/ab/Zoom_meeting/Meeting%20Invite%20HTML/downloads/windows/aboki/Zoom%2022.vbs
- file_path: C:\Users\Public\Downloads\urlhaus_16_Zoom 22.vbs

## ATT&CK Mappings
- T1059
- T1071.001
- T1071.004
- T1105

## Generated Sigma Rules
- 208c436c-383a-54c0-b6f3-59202e4ab7a6
- 9816758e-9c16-5379-87a8-5365de1d947c
- 57fe2415-fdc0-5175-8760-e956414af378
- bd2e393c-1fe3-522a-ae5e-9f238b2064eb

## Generated Wazuh Rules
- 111307
- 105900
- 119856
- 113745

## Rule Generation Rationale
- Sigma 208c436c-383a-54c0-b6f3-59202e4ab7a6: Process created: urlhaus_16_Zoom 22.vbs (urlhaus_16_Zoom 22.vbs --urlhaus-validation)
  ATT&CK: T1059
  Why: Process selector chosen for windows telemetry from executable and command line evidence using: CommandLine|contains, Image|endswith.
- Sigma 9816758e-9c16-5379-87a8-5365de1d947c: File dropped to user-accessible path: C:\Users\Public\Downloads\urlhaus_16_Zoom 22.vbs
  ATT&CK: T1105
  Why: File selector chosen for windows telemetry from observed file path evidence using: TargetFilename|contains.
- Sigma 57fe2415-fdc0-5175-8760-e956414af378: DNS lookup observed: jim-s.com
  ATT&CK: T1071.004
  Why: Network selector chosen for windows telemetry from observed DNS/domain evidence using: QueryName|contains.
- Sigma bd2e393c-1fe3-522a-ae5e-9f238b2064eb: HTTP connection observed: https://jim-s.com/ab/Zoom_meeting/Meeting%20Invite%20HTML/downloads/windows/aboki/Zoom%2022.vbs
  ATT&CK: T1071.001
  Why: Network selector chosen for windows telemetry from observed network evidence using: DestinationHostname|contains.
- Wazuh 111307: 208c436c-383a-54c0-b6f3-59202e4ab7a6
  Why: Process creation converted using Sysmon parent rule 61603 and win.eventdata image and commandLine fields when available.
- Wazuh 105900: 9816758e-9c16-5379-87a8-5365de1d947c
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 119856: 57fe2415-fdc0-5175-8760-e956414af378
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 113745: bd2e393c-1fe3-522a-ae5e-9f238b2064eb
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