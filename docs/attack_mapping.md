# ATT&CK Mapping

## Strategy

The current ATT&CK 19.1 layer is local and rule-based. It maps extracted `Behavior` descriptions and categories to predefined techniques in `core/constants.py`.

## Category Mapping

### Process

- Generic process creation -> `T1059`
- PowerShell -> `T1059.001`
- Windows Command Shell / `cmd.exe` -> `T1059.003`
- `mshta.exe` -> `T1218.005`
- `regsvr32.exe` -> `T1218.010`
- `rundll32.exe` -> `T1218.011`

### Registry

- Generic registry modification -> `T1112`
- Registry run key / startup key -> `T1547.001`

### File

- File creation / dropped executable path -> `T1105`

### Network

- DNS lookup -> `T1071.004`
- HTTP / web connection -> `T1071.001`
- FTP connection -> `T1071.002`
- SMB connection -> `T1021.002`
- Generic IP/TCP connection -> no ATT&CK technique without application-protocol or remote-service evidence
- Explicit remote-service connection (for example RDP, SSH, or WinRM evidence) -> `T1021`
- Non-standard port -> `T1571`, added alongside the HTTP, FTP, SMB, TCP, or IP
  mapping rather than replacing it, so one behavior can carry both

### Persistence

- Scheduled task -> `T1053.005`
- Windows service -> `T1543.003`
- Startup / run-key style persistence -> `T1547.001`

### Sandbox Signature

`extractor/signature_extractor.py` assigns techniques directly on the behavior,
before the mapper runs, by matching the sandbox signature name:

- `inject`, `injection`, or `process_hollow` -> `T1055` (severity `high`)
- `drop`, `file`, or `payload` -> `T1105`
- `api`, `network`, `contact`, `dns`, or `http` -> `T1071.001`
- `service`, `task`, `startup`, `runkey`, or `run_key` -> `T1547.001`

A signature matching none of these produces no behavior.

### Defined But Not Emitted

`COMMON_ATTACK_MAPPINGS` also defines `T1036` (Masquerading) and `T1070.004`
(File Deletion). Nothing currently produces either one; they are reserved for
future file-extraction rules.

## Tactics

Techniques use ATT&CK v19 tactic names. `Stealth` (TA0005) and `Defense
Impairment` (TA0112) replaced `Defense Evasion`, so Navigator layers need a
v19-aware Navigator build.

## Confidence Logic

- `high`
  Explicit description or process marker, for example PowerShell, command shell, scheduled task, service, DNS, or HTTP
- `medium`
  Strong category-level behavior where exact sub-technique is less explicit
- `low`
  Weak fallback or inferred mapping when only generic activity is present

## Examples

- `Suspicious PowerShell execution`
  Maps to `T1059.001` with high confidence
- `Suspicious command shell execution`
  Maps to `T1059.003` with high confidence
- `Scheduled task persistence observed`
  Maps to `T1053.005` with high confidence
- `Service-based persistence observed`
  Maps to `T1543.003` with high confidence
- `DNS lookup observed: api.example.test`
  Maps to `T1071.004` with high confidence
- `HTTP connection observed: http://example.test/health`
  Maps to `T1071.001` with high confidence
- `Registry run key modified: HKCU\...\Run`
  Maps to `T1547.001` with high confidence
- `File dropped to user-accessible path: C:\Temp\stage.bin`
  Maps to `T1105` with medium confidence
