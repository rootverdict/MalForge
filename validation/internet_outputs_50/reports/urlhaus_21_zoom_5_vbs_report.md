# Malware Behavior Detection Report

## Sample Overview
- Sandbox: cuckoo
- Sample name: urlhaus_21_Zoom 5.vbs
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
- url: https://jim-s.com/ab/Zoom_meeting/Meeting%20Invite%20HTML/downloads/windows/aboki/Zoom%205.vbs
- file_path: C:\Users\Public\Downloads\urlhaus_21_Zoom 5.vbs

## ATT&CK Mappings
- T1059
- T1071.001
- T1071.004
- T1105

## Generated Sigma Rules
- a3caf520-39e9-5baa-95e8-119a889abc83
- 4c120d65-049c-55b0-a746-6e066f01d1ff
- 57fe2415-fdc0-5175-8760-e956414af378
- 7f68787d-b3d9-5b26-8d77-2b7c907dbca1

## Generated Wazuh Rules
- 118164
- 112048
- 119856
- 117562

## Rule Generation Rationale
- Sigma a3caf520-39e9-5baa-95e8-119a889abc83: Process created: urlhaus_21_Zoom 5.vbs (urlhaus_21_Zoom 5.vbs --urlhaus-validation)
  ATT&CK: T1059
  Why: Process selector chosen for windows telemetry from executable and command line evidence using: CommandLine|contains, Image|endswith.
- Sigma 4c120d65-049c-55b0-a746-6e066f01d1ff: File dropped to user-accessible path: C:\Users\Public\Downloads\urlhaus_21_Zoom 5.vbs
  ATT&CK: T1105
  Why: File selector chosen for windows telemetry from observed file path evidence using: TargetFilename|contains.
- Sigma 57fe2415-fdc0-5175-8760-e956414af378: DNS lookup observed: jim-s.com
  ATT&CK: T1071.004
  Why: Network selector chosen for windows telemetry from observed DNS/domain evidence using: QueryName|contains.
- Sigma 7f68787d-b3d9-5b26-8d77-2b7c907dbca1: HTTP connection observed: https://jim-s.com/ab/Zoom_meeting/Meeting%20Invite%20HTML/downloads/windows/aboki/Zoom%205.vbs
  ATT&CK: T1071.001
  Why: Network selector chosen for windows telemetry from observed network evidence using: DestinationHostname|contains.
- Wazuh 118164: a3caf520-39e9-5baa-95e8-119a889abc83
  Why: Process creation converted using Sysmon parent rule 61603 and win.eventdata image and commandLine fields when available.
- Wazuh 112048: 4c120d65-049c-55b0-a746-6e066f01d1ff
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 119856: 57fe2415-fdc0-5175-8760-e956414af378
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 117562: 7f68787d-b3d9-5b26-8d77-2b7c907dbca1
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