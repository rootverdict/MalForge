# Malware Behavior Detection Report

## Sample Overview
- Sandbox: cuckoo
- Sample name: urlhaus_50_bin.sh
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
- ipv4: 112.239.101.142
- url: http://112.239.101.142:35487/bin.sh
- file_path: /tmp/urlhaus_50_bin.sh

## ATT&CK Mappings
- T1059
- T1071
- T1071.001
- T1105
- T1571

## Generated Sigma Rules
- 39fb1fac-8e46-568c-9d2e-72e906fa70bb
- 7d6e0e1b-4c54-5a3f-bdb2-18d780503660
- df2c2ca9-55b3-5d93-a526-76b17abc030c
- f21f478c-f419-5def-9826-834d23979034

## Generated Wazuh Rules
- 108219
- 108160
- 106669
- 118186

## Rule Generation Rationale
- Sigma 39fb1fac-8e46-568c-9d2e-72e906fa70bb: Process created: urlhaus_50_bin.sh (urlhaus_50_bin.sh --urlhaus-validation)
  ATT&CK: T1059
  Why: Process selector chosen for non_windows telemetry from executable and command line evidence using: cmdline|contains, exe|endswith.
- Sigma 7d6e0e1b-4c54-5a3f-bdb2-18d780503660: File dropped to user-accessible path: /tmp/urlhaus_50_bin.sh
  ATT&CK: T1105
  Why: File selector chosen for non_windows telemetry from observed file path evidence using: file.path|contains.
- Sigma df2c2ca9-55b3-5d93-a526-76b17abc030c: IP connection observed: 112.239.101.142
  ATT&CK: T1071
  Why: Network selector chosen for non_windows telemetry from observed IP evidence using: destination.ip.
- Sigma f21f478c-f419-5def-9826-834d23979034: HTTP connection observed: http://112.239.101.142:35487/bin.sh
  ATT&CK: T1071.001, T1571
  Why: Network selector chosen for non_windows telemetry from observed IP evidence using: destination.ip, url|contains.
- Wazuh 108219: 39fb1fac-8e46-568c-9d2e-72e906fa70bb
  Why: Rule converted using Linux/generic JSON field matching; no Windows Sysmon parent or win.eventdata fields are used.
- Wazuh 108160: 7d6e0e1b-4c54-5a3f-bdb2-18d780503660
  Why: Rule converted using Linux/generic JSON field matching; no Windows Sysmon parent or win.eventdata fields are used.
- Wazuh 106669: df2c2ca9-55b3-5d93-a526-76b17abc030c
  Why: Rule converted using Linux/generic JSON field matching; no Windows Sysmon parent or win.eventdata fields are used.
- Wazuh 118186: f21f478c-f419-5def-9826-834d23979034
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