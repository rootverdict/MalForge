# Malware Behavior Detection Report

## Sample Overview
- Sandbox: cuckoo
- Sample name: urlhaus_19_Zoom 3.vbs
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
- url: https://jim-s.com/ab/Zoom_meeting/Meeting%20Invite%20HTML/downloads/windows/aboki/Zoom%203.vbs
- file_path: C:\Users\Public\Downloads\urlhaus_19_Zoom 3.vbs

## ATT&CK Mappings
- T1059
- T1071.001
- T1071.004
- T1105

## Generated Sigma Rules
- 0fb8e2f6-e8d1-5972-8b54-f18b60fa3341
- 4904f62e-7415-5a9f-bb48-0d84256d33bc
- 57fe2415-fdc0-5175-8760-e956414af378
- c3880714-9346-5baa-85bc-ce968135caf4

## Generated Wazuh Rules
- 113338
- 118099
- 119856
- 115251

## Rule Generation Rationale
- Sigma 0fb8e2f6-e8d1-5972-8b54-f18b60fa3341: Process created: urlhaus_19_Zoom 3.vbs (urlhaus_19_Zoom 3.vbs --urlhaus-validation)
  ATT&CK: T1059
  Why: Process selector chosen for windows telemetry from executable and command line evidence using: CommandLine|contains, Image|endswith.
- Sigma 4904f62e-7415-5a9f-bb48-0d84256d33bc: File dropped to user-accessible path: C:\Users\Public\Downloads\urlhaus_19_Zoom 3.vbs
  ATT&CK: T1105
  Why: File selector chosen for windows telemetry from observed file path evidence using: TargetFilename|contains.
- Sigma 57fe2415-fdc0-5175-8760-e956414af378: DNS lookup observed: jim-s.com
  ATT&CK: T1071.004
  Why: Network selector chosen for windows telemetry from observed DNS/domain evidence using: QueryName|contains.
- Sigma c3880714-9346-5baa-85bc-ce968135caf4: HTTP connection observed: https://jim-s.com/ab/Zoom_meeting/Meeting%20Invite%20HTML/downloads/windows/aboki/Zoom%203.vbs
  ATT&CK: T1071.001
  Why: Network selector chosen for windows telemetry from observed network evidence using: DestinationHostname|contains.
- Wazuh 113338: 0fb8e2f6-e8d1-5972-8b54-f18b60fa3341
  Why: Process creation converted using Sysmon parent rule 61603 and win.eventdata image and commandLine fields when available.
- Wazuh 118099: 4904f62e-7415-5a9f-bb48-0d84256d33bc
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 119856: 57fe2415-fdc0-5175-8760-e956414af378
  Why: Non-process Windows rule converted using decoded JSON Wazuh field matching.
- Wazuh 115251: c3880714-9346-5baa-85bc-ce968135caf4
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