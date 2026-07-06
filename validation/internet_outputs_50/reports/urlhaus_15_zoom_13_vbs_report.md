# Malware Behavior Detection Report

## Sample Overview
- Sandbox: cuckoo
- Sample name: urlhaus_15_Zoom 13.vbs
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
- url: https://jim-s.com/ab/Zoom_meeting/Meeting%20Invite%20HTML/downloads/windows/aboki/Zoom%2013.vbs
- file_path: C:\Users\Public\Downloads\urlhaus_15_Zoom 13.vbs

## ATT&CK Mappings
- T1059
- T1071.001
- T1071.004
- T1105

## Generated Sigma Rules
- ed4001ba-ebd6-5a2e-815d-e8f92f8ecabb
- a95eecfc-7252-58b4-bc08-cd36104b1def
- 57fe2415-fdc0-5175-8760-e956414af378
- ffec8cc1-056b-5c83-866b-f796bf4423a4

## Generated Wazuh Rules
- 101076
- 107684
- 119856
- 119623

## Rule Generation Rationale
- Sigma ed4001ba-ebd6-5a2e-815d-e8f92f8ecabb: Process created: urlhaus_15_Zoom 13.vbs (urlhaus_15_Zoom 13.vbs --urlhaus-validation)
  ATT&CK: T1059
  Why: Process selector chosen for windows telemetry from executable and command line evidence using: CommandLine|contains, Image|endswith.
- Sigma a95eecfc-7252-58b4-bc08-cd36104b1def: File dropped to user-accessible path: C:\Users\Public\Downloads\urlhaus_15_Zoom 13.vbs
  ATT&CK: T1105
  Why: File selector chosen for windows telemetry from observed file path evidence using: TargetFilename|contains.
- Sigma 57fe2415-fdc0-5175-8760-e956414af378: DNS lookup observed: jim-s.com
  ATT&CK: T1071.004
  Why: Network selector chosen for windows telemetry from observed DNS/domain evidence using: QueryName|contains.
- Sigma ffec8cc1-056b-5c83-866b-f796bf4423a4: HTTP connection observed: https://jim-s.com/ab/Zoom_meeting/Meeting%20Invite%20HTML/downloads/windows/aboki/Zoom%2013.vbs
  ATT&CK: T1071.001
  Why: Network selector chosen for windows telemetry from observed network evidence using: DestinationHostname|contains.
- Wazuh 101076: ed4001ba-ebd6-5a2e-815d-e8f92f8ecabb
  Why: Process creation converted using Sysmon parent rule 61603 and win.eventdata image and commandLine fields when available.
- Wazuh 107684: a95eecfc-7252-58b4-bc08-cd36104b1def
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 119856: 57fe2415-fdc0-5175-8760-e956414af378
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 119623: ffec8cc1-056b-5c83-866b-f796bf4423a4
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