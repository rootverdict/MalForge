# Malware Behavior Detection Report

## Sample Overview
- Sandbox: cuckoo
- Sample name: urlhaus_20_Zoom 8.vbs
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
- url: https://jim-s.com/ab/Zoom_meeting/Meeting%20Invite%20HTML/downloads/windows/aboki/Zoom%208.vbs
- file_path: C:\Users\Public\Downloads\urlhaus_20_Zoom 8.vbs

## ATT&CK Mappings
- T1059
- T1071.001
- T1071.004
- T1105

## Generated Sigma Rules
- bf06eb26-602f-5648-84ce-4ec688149872
- 8b4ab4ad-8629-5c96-8429-d209fb307d55
- 57fe2415-fdc0-5175-8760-e956414af378
- 847c7529-b593-5c09-91e7-72294e567c1d

## Generated Wazuh Rules
- 109041
- 115290
- 119856
- 118473

## Rule Generation Rationale
- Sigma bf06eb26-602f-5648-84ce-4ec688149872: Process created: urlhaus_20_Zoom 8.vbs (urlhaus_20_Zoom 8.vbs --urlhaus-validation)
  ATT&CK: T1059
  Why: Process selector chosen for windows telemetry from executable and command line evidence using: CommandLine|contains, Image|endswith.
- Sigma 8b4ab4ad-8629-5c96-8429-d209fb307d55: File dropped to user-accessible path: C:\Users\Public\Downloads\urlhaus_20_Zoom 8.vbs
  ATT&CK: T1105
  Why: File selector chosen for windows telemetry from observed file path evidence using: TargetFilename|contains.
- Sigma 57fe2415-fdc0-5175-8760-e956414af378: DNS lookup observed: jim-s.com
  ATT&CK: T1071.004
  Why: Network selector chosen for windows telemetry from observed DNS/domain evidence using: QueryName|contains.
- Sigma 847c7529-b593-5c09-91e7-72294e567c1d: HTTP connection observed: https://jim-s.com/ab/Zoom_meeting/Meeting%20Invite%20HTML/downloads/windows/aboki/Zoom%208.vbs
  ATT&CK: T1071.001
  Why: Network selector chosen for windows telemetry from observed network evidence using: DestinationHostname|contains.
- Wazuh 109041: bf06eb26-602f-5648-84ce-4ec688149872
  Why: Process creation converted using Sysmon parent rule 61603 and win.eventdata image and commandLine fields when available.
- Wazuh 115290: 8b4ab4ad-8629-5c96-8429-d209fb307d55
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 119856: 57fe2415-fdc0-5175-8760-e956414af378
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 118473: 847c7529-b593-5c09-91e7-72294e567c1d
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