# ATT&CK Mapping

## Strategy

The current ATT&CK layer is local and rule-based. It maps extracted `Behavior` descriptions and categories to predefined techniques in `core/constants.py`.

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
- IP / remote service style connection -> `T1021`

### Persistence

- Scheduled task -> `T1053.005`
- Windows service -> `T1543.003`
- Startup / run-key style persistence -> `T1547.001`

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
