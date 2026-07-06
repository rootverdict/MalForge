# Malware Behavior Detection Report

## Sample Overview
- Sandbox: cuckoo
- Sample name: urlhaus_48_bin.sh
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
- file_path: 1
- ipv4: 1
- url: 1

### IOC Values
- ipv4: 14.0.131.161
- url: http://14.0.131.161:38465/bin.sh
- file_path: /tmp/urlhaus_48_bin.sh

## ATT&CK Mappings
- T1059
- T1071
- T1071.001
- T1105
- T1571

## Generated Sigma Rules
- 4a04e69b-8784-5fea-a85d-683f62c6e297
- acf2a0c9-7e18-55f8-bd0b-c151494603b6
- d558818c-7fce-5224-92b7-459169d882f2
- 67d8766c-d550-53bb-b137-da847c707736

## Generated Wazuh Rules
- 100065
- 111568
- 105063
- 102558

## Rule Generation Rationale
- Sigma 4a04e69b-8784-5fea-a85d-683f62c6e297: Process created: urlhaus_48_bin.sh (urlhaus_48_bin.sh --urlhaus-validation)
  ATT&CK: T1059
  Why: Process selector chosen for linux_or_iot telemetry from executable and command line evidence using: cmdline|contains, exe|endswith.
- Sigma acf2a0c9-7e18-55f8-bd0b-c151494603b6: File dropped to user-accessible path: /tmp/urlhaus_48_bin.sh
  ATT&CK: T1105
  Why: File selector chosen for linux_or_iot telemetry from observed file path evidence using: file.path|contains.
- Sigma d558818c-7fce-5224-92b7-459169d882f2: IP connection observed: 14.0.131.161
  ATT&CK: T1071
  Why: Network selector chosen for linux_or_iot telemetry from observed IP evidence using: destination.ip.
- Sigma 67d8766c-d550-53bb-b137-da847c707736: HTTP connection observed: http://14.0.131.161:38465/bin.sh
  ATT&CK: T1071.001, T1571
  Why: Network selector chosen for linux_or_iot telemetry from observed IP evidence using: destination.ip, url|contains.
- Wazuh 100065: 4a04e69b-8784-5fea-a85d-683f62c6e297
  Why: Rule converted using Linux/generic JSON field matching; no Windows Sysmon parent or win.eventdata fields are used.
- Wazuh 111568: acf2a0c9-7e18-55f8-bd0b-c151494603b6
  Why: Rule converted using Linux/generic JSON field matching; no Windows Sysmon parent or win.eventdata fields are used.
- Wazuh 105063: d558818c-7fce-5224-92b7-459169d882f2
  Why: Rule converted using Linux/generic JSON field matching; no Windows Sysmon parent or win.eventdata fields are used.
- Wazuh 102558: 67d8766c-d550-53bb-b137-da847c707736
  Why: Rule converted using Linux/generic JSON field matching; no Windows Sysmon parent or win.eventdata fields are used.

## Validation Warnings
- No validation warnings.

## Risk Scoring
- Average risk score: 62.75
- Average ATT&CK confidence: 0.74

## Review Status
- unreviewed

## Output Artifact List
- Navigator techniques: 5
- Sigma rule count: 4
- Wazuh rule count: 4