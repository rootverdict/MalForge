# Malware Behavior Detection Report

## Sample Overview
- Sandbox: cuckoo
- Sample name: urlhaus_11_Zoom 24.vbs
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
- url: https://jim-s.com/ab/Zoom_meeting/Meeting%20Invite%20HTML/downloads/windows/aboki/Zoom%2024.vbs
- file_path: C:\Users\Public\Downloads\urlhaus_11_Zoom 24.vbs

## ATT&CK Mappings
- T1059
- T1071.001
- T1071.004
- T1105

## Generated Sigma Rules
- 8185a073-8c6a-5bbc-b1cf-8fe0526dd8a0
- 88c1a622-1692-54ec-aca3-3c8377db8772
- 57fe2415-fdc0-5175-8760-e956414af378
- 0b986a35-fc18-52bd-a88f-c46cd0032fab

## Generated Wazuh Rules
- 101701
- 101826
- 119856
- 100294

## Rule Generation Rationale
- Sigma 8185a073-8c6a-5bbc-b1cf-8fe0526dd8a0: Process created: urlhaus_11_Zoom 24.vbs (urlhaus_11_Zoom 24.vbs --urlhaus-validation)
  ATT&CK: T1059
  Why: Process selector chosen for windows telemetry from executable and command line evidence using: CommandLine|contains, Image|endswith.
- Sigma 88c1a622-1692-54ec-aca3-3c8377db8772: File dropped to user-accessible path: C:\Users\Public\Downloads\urlhaus_11_Zoom 24.vbs
  ATT&CK: T1105
  Why: File selector chosen for windows telemetry from observed file path evidence using: TargetFilename|contains.
- Sigma 57fe2415-fdc0-5175-8760-e956414af378: DNS lookup observed: jim-s.com
  ATT&CK: T1071.004
  Why: Network selector chosen for windows telemetry from observed DNS/domain evidence using: QueryName|contains.
- Sigma 0b986a35-fc18-52bd-a88f-c46cd0032fab: HTTP connection observed: https://jim-s.com/ab/Zoom_meeting/Meeting%20Invite%20HTML/downloads/windows/aboki/Zoom%2024.vbs
  ATT&CK: T1071.001
  Why: Network selector chosen for windows telemetry from observed network evidence using: DestinationHostname|contains.
- Wazuh 101701: 8185a073-8c6a-5bbc-b1cf-8fe0526dd8a0
  Why: Process creation converted using Sysmon parent rule 61603 and win.eventdata image and commandLine fields when available.
- Wazuh 101826: 88c1a622-1692-54ec-aca3-3c8377db8772
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 119856: 57fe2415-fdc0-5175-8760-e956414af378
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 100294: 0b986a35-fc18-52bd-a88f-c46cd0032fab
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