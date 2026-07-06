# Malware Behavior Detection Report

## Sample Overview
- Sandbox: cuckoo
- Sample name: urlhaus_05_Zoom 10.vbs
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
- url: https://jim-s.com/ab/Zoom_meeting/Meeting%20Invite%20HTML/downloads/windows/aboki/Zoom%2010.vbs
- file_path: C:\Users\Public\Downloads\urlhaus_05_Zoom 10.vbs

## ATT&CK Mappings
- T1059
- T1071.001
- T1071.004
- T1105

## Generated Sigma Rules
- b2bdd86f-7c96-5130-9cae-2acb70629f3d
- 4b848b42-ef56-5802-b3fd-bd3cc2d4e006
- 57fe2415-fdc0-5175-8760-e956414af378
- 9f8509a4-4dd5-5e4e-a649-7a24447d44d2

## Generated Wazuh Rules
- 108712
- 103768
- 119856
- 116934

## Rule Generation Rationale
- Sigma b2bdd86f-7c96-5130-9cae-2acb70629f3d: Process created: urlhaus_05_Zoom 10.vbs (urlhaus_05_Zoom 10.vbs --urlhaus-validation)
  ATT&CK: T1059
  Why: Process selector chosen for windows telemetry from executable and command line evidence using: CommandLine|contains, Image|endswith.
- Sigma 4b848b42-ef56-5802-b3fd-bd3cc2d4e006: File dropped to user-accessible path: C:\Users\Public\Downloads\urlhaus_05_Zoom 10.vbs
  ATT&CK: T1105
  Why: File selector chosen for windows telemetry from observed file path evidence using: TargetFilename|contains.
- Sigma 57fe2415-fdc0-5175-8760-e956414af378: DNS lookup observed: jim-s.com
  ATT&CK: T1071.004
  Why: Network selector chosen for windows telemetry from observed DNS/domain evidence using: QueryName|contains.
- Sigma 9f8509a4-4dd5-5e4e-a649-7a24447d44d2: HTTP connection observed: https://jim-s.com/ab/Zoom_meeting/Meeting%20Invite%20HTML/downloads/windows/aboki/Zoom%2010.vbs
  ATT&CK: T1071.001
  Why: Network selector chosen for windows telemetry from observed network evidence using: DestinationHostname|contains.
- Wazuh 108712: b2bdd86f-7c96-5130-9cae-2acb70629f3d
  Why: Process creation converted using Sysmon parent rule 61603 and win.eventdata image and commandLine fields when available.
- Wazuh 103768: 4b848b42-ef56-5802-b3fd-bd3cc2d4e006
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 119856: 57fe2415-fdc0-5175-8760-e956414af378
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 116934: 9f8509a4-4dd5-5e4e-a649-7a24447d44d2
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