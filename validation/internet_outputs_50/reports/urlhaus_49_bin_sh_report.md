# Malware Behavior Detection Report

## Sample Overview
- Sandbox: cuckoo
- Sample name: urlhaus_49_bin.sh
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
- ipv4: 39.71.205.224
- url: http://39.71.205.224:59523/bin.sh
- file_path: /tmp/urlhaus_49_bin.sh

## ATT&CK Mappings
- T1059
- T1071
- T1071.001
- T1105
- T1571

## Generated Sigma Rules
- 7dc90987-e630-53cf-bc4b-26753e707a24
- d02e58e6-dce5-5518-bfa6-785d4a643b92
- 83b2d35a-fa2e-51b9-acc8-564a2332bf93
- d137061f-ca7c-587f-9a81-36218e34dd26

## Generated Wazuh Rules
- 113546
- 105241
- 105495
- 109871

## Rule Generation Rationale
- Sigma 7dc90987-e630-53cf-bc4b-26753e707a24: Process created: urlhaus_49_bin.sh (urlhaus_49_bin.sh --urlhaus-validation)
  ATT&CK: T1059
  Why: Process selector chosen for linux_or_iot telemetry from executable and command line evidence using: cmdline|contains, exe|endswith.
- Sigma d02e58e6-dce5-5518-bfa6-785d4a643b92: File dropped to user-accessible path: /tmp/urlhaus_49_bin.sh
  ATT&CK: T1105
  Why: File selector chosen for linux_or_iot telemetry from observed file path evidence using: file.path|contains.
- Sigma 83b2d35a-fa2e-51b9-acc8-564a2332bf93: IP connection observed: 39.71.205.224
  ATT&CK: T1071
  Why: Network selector chosen for linux_or_iot telemetry from observed IP evidence using: destination.ip.
- Sigma d137061f-ca7c-587f-9a81-36218e34dd26: HTTP connection observed: http://39.71.205.224:59523/bin.sh
  ATT&CK: T1071.001, T1571
  Why: Network selector chosen for linux_or_iot telemetry from observed IP evidence using: destination.ip, url|contains.
- Wazuh 113546: 7dc90987-e630-53cf-bc4b-26753e707a24
  Why: Rule converted using Linux/generic JSON field matching; no Windows Sysmon parent or win.eventdata fields are used.
- Wazuh 105241: d02e58e6-dce5-5518-bfa6-785d4a643b92
  Why: Rule converted using Linux/generic JSON field matching; no Windows Sysmon parent or win.eventdata fields are used.
- Wazuh 105495: 83b2d35a-fa2e-51b9-acc8-564a2332bf93
  Why: Rule converted using Linux/generic JSON field matching; no Windows Sysmon parent or win.eventdata fields are used.
- Wazuh 109871: d137061f-ca7c-587f-9a81-36218e34dd26
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