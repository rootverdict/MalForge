# Malware Behavior Detection Report

## Sample Overview
- Sandbox: cuckoo
- Sample name: urlhaus_09_Zoom 18.vbs
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
- url: https://jim-s.com/ab/Zoom_meeting/Meeting%20Invite%20HTML/downloads/windows/aboki/Zoom%2018.vbs
- file_path: C:\Users\Public\Downloads\urlhaus_09_Zoom 18.vbs

## ATT&CK Mappings
- T1059
- T1071.001
- T1071.004
- T1105

## Generated Sigma Rules
- b76c15e4-889e-55ed-9476-bfe6a0f6dbce
- 4527773b-e83e-5a58-804d-66e4ebbca18f
- 57fe2415-fdc0-5175-8760-e956414af378
- 0e3f7715-3d56-5f25-8cfd-e31df173d43e

## Generated Wazuh Rules
- 116166
- 110282
- 119856
- 112871

## Rule Generation Rationale
- Sigma b76c15e4-889e-55ed-9476-bfe6a0f6dbce: Process created: urlhaus_09_Zoom 18.vbs (urlhaus_09_Zoom 18.vbs --urlhaus-validation)
  ATT&CK: T1059
  Why: Process selector chosen for windows telemetry from executable and command line evidence using: CommandLine|contains, Image|endswith.
- Sigma 4527773b-e83e-5a58-804d-66e4ebbca18f: File dropped to user-accessible path: C:\Users\Public\Downloads\urlhaus_09_Zoom 18.vbs
  ATT&CK: T1105
  Why: File selector chosen for windows telemetry from observed file path evidence using: TargetFilename|contains.
- Sigma 57fe2415-fdc0-5175-8760-e956414af378: DNS lookup observed: jim-s.com
  ATT&CK: T1071.004
  Why: Network selector chosen for windows telemetry from observed DNS/domain evidence using: QueryName|contains.
- Sigma 0e3f7715-3d56-5f25-8cfd-e31df173d43e: HTTP connection observed: https://jim-s.com/ab/Zoom_meeting/Meeting%20Invite%20HTML/downloads/windows/aboki/Zoom%2018.vbs
  ATT&CK: T1071.001
  Why: Network selector chosen for windows telemetry from observed network evidence using: DestinationHostname|contains.
- Wazuh 116166: b76c15e4-889e-55ed-9476-bfe6a0f6dbce
  Why: Process creation converted using Sysmon parent rule 61603 and win.eventdata image and commandLine fields when available.
- Wazuh 110282: 4527773b-e83e-5a58-804d-66e4ebbca18f
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 119856: 57fe2415-fdc0-5175-8760-e956414af378
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 112871: 0e3f7715-3d56-5f25-8cfd-e31df173d43e
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