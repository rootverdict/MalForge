# Internet-Derived 50 Report Validation Summary

- Source: URLhaus recent CSV feed
- Source URL: https://urlhaus.abuse.ch/downloads/csv_recent/
- Safety scope: public CSV metadata only; no malware binaries, no detonation, no live sample execution.
- Input reports generated: 50
- Successful CLI runs: 50
- Failed CLI runs: 0
- Unique summary outputs: 50
- Markdown reports: 50
- Sigma files: 200
- Wazuh XML files: 50
- IOC JSON files: 50
- Navigator layers: 50
- Test event files: 50
- Aggregate behaviors: 203
- Aggregate IOCs: 156
- Aggregate Sigma rules: 200
- Aggregate Wazuh rules: 200
- Validation warnings: 0
- Unique ATT&CK techniques: 6

## Validation Notes
- Platform-aware generation verified on URLhaus Mozi elf/mips report: Linux/generic rules were emitted instead of Windows/Sysmon rules.
- Raw IP values in domain-like source fields are classified as IP/network C2 evidence, not DNS/domain evidence or Remote Services lateral movement.
- HTTP URL evidence from Cuckoo-style network.http entries is preserved and mapped to web-protocol behavior; non-standard ports also receive T1571.
- Missing MD5/SHA1/SHA256 values are reported as source-data limitations when URL-only metadata lacks payload hashes.

## Honest Claim

The tool was validated against 50 externally sourced URLhaus-derived report inputs and successfully generated behaviors, IOCs, ATT&CK mappings, Sigma rules, Wazuh rules, test events, Navigator layers, and Markdown/JSON reports. This does not prove compatibility with every possible sandbox/vendor schema.
