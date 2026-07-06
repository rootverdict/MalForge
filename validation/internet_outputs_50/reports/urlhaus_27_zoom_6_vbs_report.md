# Malware Behavior Detection Report

## Sample Overview
- Sandbox: cuckoo
- Sample name: urlhaus_27_Zoom 6.vbs
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
- url: https://jim-s.com/ab/Zoom_meeting/Meeting%20Invite%20HTML/downloads/windows/aboki/Zoom%206.vbs
- file_path: C:\Users\Public\Downloads\urlhaus_27_Zoom 6.vbs

## ATT&CK Mappings
- T1059
- T1071.001
- T1071.004
- T1105

## Generated Sigma Rules
- 5e9773c2-fe4f-5697-bdc9-7e2c864ca4fc
- 465057e2-563b-5c5b-aef4-1d689d8dd5d0
- 57fe2415-fdc0-5175-8760-e956414af378
- 7317c6c5-2285-5046-9acb-09d1fd93b2b2

## Generated Wazuh Rules
- 110026
- 112701
- 119856
- 110725

## Rule Generation Rationale
- Sigma 5e9773c2-fe4f-5697-bdc9-7e2c864ca4fc: Process created: urlhaus_27_Zoom 6.vbs (urlhaus_27_Zoom 6.vbs --urlhaus-validation)
  ATT&CK: T1059
  Why: Process selector chosen for windows telemetry from executable and command line evidence using: CommandLine|contains, Image|endswith.
- Sigma 465057e2-563b-5c5b-aef4-1d689d8dd5d0: File dropped to user-accessible path: C:\Users\Public\Downloads\urlhaus_27_Zoom 6.vbs
  ATT&CK: T1105
  Why: File selector chosen for windows telemetry from observed file path evidence using: TargetFilename|contains.
- Sigma 57fe2415-fdc0-5175-8760-e956414af378: DNS lookup observed: jim-s.com
  ATT&CK: T1071.004
  Why: Network selector chosen for windows telemetry from observed DNS/domain evidence using: QueryName|contains.
- Sigma 7317c6c5-2285-5046-9acb-09d1fd93b2b2: HTTP connection observed: https://jim-s.com/ab/Zoom_meeting/Meeting%20Invite%20HTML/downloads/windows/aboki/Zoom%206.vbs
  ATT&CK: T1071.001
  Why: Network selector chosen for windows telemetry from observed network evidence using: DestinationHostname|contains.
- Wazuh 110026: 5e9773c2-fe4f-5697-bdc9-7e2c864ca4fc
  Why: Process creation converted using Sysmon parent rule 61603 and win.eventdata image and commandLine fields when available.
- Wazuh 112701: 465057e2-563b-5c5b-aef4-1d689d8dd5d0
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 119856: 57fe2415-fdc0-5175-8760-e956414af378
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 110725: 7317c6c5-2285-5046-9acb-09d1fd93b2b2
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