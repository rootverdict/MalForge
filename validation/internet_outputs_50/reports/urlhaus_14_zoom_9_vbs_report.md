# Malware Behavior Detection Report

## Sample Overview
- Sandbox: cuckoo
- Sample name: urlhaus_14_Zoom 9.vbs
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
- url: https://jim-s.com/ab/Zoom_meeting/Meeting%20Invite%20HTML/downloads/windows/aboki/Zoom%209.vbs
- file_path: C:\Users\Public\Downloads\urlhaus_14_Zoom 9.vbs

## ATT&CK Mappings
- T1059
- T1071.001
- T1071.004
- T1105

## Generated Sigma Rules
- f8cdece4-4dab-5795-b5b8-8156638f0563
- 2c5e4d3f-f0d8-52bc-8971-7500d6d0f951
- 57fe2415-fdc0-5175-8760-e956414af378
- 170390bc-bc71-5f6f-a95b-7169c86d4443

## Generated Wazuh Rules
- 111459
- 102320
- 119856
- 116462

## Rule Generation Rationale
- Sigma f8cdece4-4dab-5795-b5b8-8156638f0563: Process created: urlhaus_14_Zoom 9.vbs (urlhaus_14_Zoom 9.vbs --urlhaus-validation)
  ATT&CK: T1059
  Why: Process selector chosen for windows telemetry from executable and command line evidence using: CommandLine|contains, Image|endswith.
- Sigma 2c5e4d3f-f0d8-52bc-8971-7500d6d0f951: File dropped to user-accessible path: C:\Users\Public\Downloads\urlhaus_14_Zoom 9.vbs
  ATT&CK: T1105
  Why: File selector chosen for windows telemetry from observed file path evidence using: TargetFilename|contains.
- Sigma 57fe2415-fdc0-5175-8760-e956414af378: DNS lookup observed: jim-s.com
  ATT&CK: T1071.004
  Why: Network selector chosen for windows telemetry from observed DNS/domain evidence using: QueryName|contains.
- Sigma 170390bc-bc71-5f6f-a95b-7169c86d4443: HTTP connection observed: https://jim-s.com/ab/Zoom_meeting/Meeting%20Invite%20HTML/downloads/windows/aboki/Zoom%209.vbs
  ATT&CK: T1071.001
  Why: Network selector chosen for windows telemetry from observed network evidence using: DestinationHostname|contains.
- Wazuh 111459: f8cdece4-4dab-5795-b5b8-8156638f0563
  Why: Process creation converted using Sysmon parent rule 61603 and win.eventdata image and commandLine fields when available.
- Wazuh 102320: 2c5e4d3f-f0d8-52bc-8971-7500d6d0f951
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 119856: 57fe2415-fdc0-5175-8760-e956414af378
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 116462: 170390bc-bc71-5f6f-a95b-7169c86d4443
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