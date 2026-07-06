# Malware Behavior Detection Report

## Sample Overview
- Sandbox: cuckoo
- Sample name: urlhaus_43_i
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
- ipv4: 125.41.133.47
- url: http://125.41.133.47:43078/i
- file_path: /tmp/urlhaus_43_i

## ATT&CK Mappings
- T1059
- T1071
- T1071.001
- T1105
- T1571

## Generated Sigma Rules
- 37d2cdc8-e3bb-599c-91bf-c2d797969144
- db2c4941-05d1-5d43-a771-5a6bb79ea4a0
- 3ab520bb-0a3c-5a0c-995f-14ac219585cf
- 033d9e68-99fe-5526-a833-4b65a2cc5ea8

## Generated Wazuh Rules
- 117687
- 108368
- 106557
- 112886

## Rule Generation Rationale
- Sigma 37d2cdc8-e3bb-599c-91bf-c2d797969144: Process created: urlhaus_43_i (urlhaus_43_i --urlhaus-validation)
  ATT&CK: T1059
  Why: Process selector chosen for non_windows telemetry from executable and command line evidence using: cmdline|contains, exe|endswith.
- Sigma db2c4941-05d1-5d43-a771-5a6bb79ea4a0: File dropped to user-accessible path: /tmp/urlhaus_43_i
  ATT&CK: T1105
  Why: File selector chosen for non_windows telemetry from observed file path evidence using: file.path|contains.
- Sigma 3ab520bb-0a3c-5a0c-995f-14ac219585cf: IP connection observed: 125.41.133.47
  ATT&CK: T1071
  Why: Network selector chosen for non_windows telemetry from observed IP evidence using: destination.ip.
- Sigma 033d9e68-99fe-5526-a833-4b65a2cc5ea8: HTTP connection observed: http://125.41.133.47:43078/i
  ATT&CK: T1071.001, T1571
  Why: Network selector chosen for non_windows telemetry from observed IP evidence using: destination.ip, url|contains.
- Wazuh 117687: 37d2cdc8-e3bb-599c-91bf-c2d797969144
  Why: Rule converted using Linux/generic JSON field matching; no Windows Sysmon parent or win.eventdata fields are used.
- Wazuh 108368: db2c4941-05d1-5d43-a771-5a6bb79ea4a0
  Why: Rule converted using Linux/generic JSON field matching; no Windows Sysmon parent or win.eventdata fields are used.
- Wazuh 106557: 3ab520bb-0a3c-5a0c-995f-14ac219585cf
  Why: Rule converted using Linux/generic JSON field matching; no Windows Sysmon parent or win.eventdata fields are used.
- Wazuh 112886: 033d9e68-99fe-5526-a833-4b65a2cc5ea8
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