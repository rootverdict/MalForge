# Malware Behavior Detection Report

## Sample Overview
- Sandbox: cuckoo
- Sample name: urlhaus_42_i
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
- url: http://39.71.205.224:59523/i
- file_path: /tmp/urlhaus_42_i

## ATT&CK Mappings
- T1059
- T1071
- T1071.001
- T1105
- T1571

## Generated Sigma Rules
- c85f84fa-4f76-5ad4-999e-64ec32553d31
- 59c964ad-4eaf-5355-941f-f2e881215321
- 83b2d35a-fa2e-51b9-acc8-564a2332bf93
- a89e76a8-0dc7-5e91-932e-2b3ecfc8b12e

## Generated Wazuh Rules
- 107853
- 116206
- 105495
- 112387

## Rule Generation Rationale
- Sigma c85f84fa-4f76-5ad4-999e-64ec32553d31: Process created: urlhaus_42_i (urlhaus_42_i --urlhaus-validation)
  ATT&CK: T1059
  Why: Process selector chosen for linux_or_iot telemetry from executable and command line evidence using: cmdline|contains, exe|endswith.
- Sigma 59c964ad-4eaf-5355-941f-f2e881215321: File dropped to user-accessible path: /tmp/urlhaus_42_i
  ATT&CK: T1105
  Why: File selector chosen for linux_or_iot telemetry from observed file path evidence using: file.path|contains.
- Sigma 83b2d35a-fa2e-51b9-acc8-564a2332bf93: IP connection observed: 39.71.205.224
  ATT&CK: T1071
  Why: Network selector chosen for linux_or_iot telemetry from observed IP evidence using: destination.ip.
- Sigma a89e76a8-0dc7-5e91-932e-2b3ecfc8b12e: HTTP connection observed: http://39.71.205.224:59523/i
  ATT&CK: T1071.001, T1571
  Why: Network selector chosen for linux_or_iot telemetry from observed IP evidence using: destination.ip, url|contains.
- Wazuh 107853: c85f84fa-4f76-5ad4-999e-64ec32553d31
  Why: Rule converted using Linux/generic JSON field matching; no Windows Sysmon parent or win.eventdata fields are used.
- Wazuh 116206: 59c964ad-4eaf-5355-941f-f2e881215321
  Why: Rule converted using Linux/generic JSON field matching; no Windows Sysmon parent or win.eventdata fields are used.
- Wazuh 105495: 83b2d35a-fa2e-51b9-acc8-564a2332bf93
  Why: Rule converted using Linux/generic JSON field matching; no Windows Sysmon parent or win.eventdata fields are used.
- Wazuh 112387: a89e76a8-0dc7-5e91-932e-2b3ecfc8b12e
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