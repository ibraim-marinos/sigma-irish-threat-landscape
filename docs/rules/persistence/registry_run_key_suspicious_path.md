# Registry Run Key Persistence from Suspicious Path

## Rule Status

Experimental - validated with Sigma CLI 3.1.0.

## Threat Scenario

Windows Registry `Run` and `RunOnce` keys can automatically execute programs when a user signs in.

An attacker may create or modify one of these values so that malware executes again after the endpoint restarts or the user begins a new session. This provides persistence without requiring the attacker to launch the malware manually again.

A Registry Run entry becomes more suspicious when it references an executable, script, or DLL stored in a user-writable location such as:

- `AppData`
- `Temp`
- `Downloads`
- `Users\Public`

Attackers commonly use these locations because a standard user can often write files there without administrator privileges.

## Detection Hypothesis

If a Windows Registry Run or RunOnce value is set to execute content from a user-writable directory, the activity should be investigated as possible persistence.

## Required Telemetry

Windows Registry value-set events.

```yaml
logsource:
  category: registry_set
  product: windows
```

Suitable telemetry includes:

- Sysmon Event ID 13.
- Windows Security Event ID 4657 when Registry auditing is configured.
- EDR Registry-modification telemetry.

## Detection Logic Explanation

The rule uses two required selections.

### Run Key Selection

```yaml
selection_run_key:
  TargetObject|contains:
    - '\Software\Microsoft\Windows\CurrentVersion\Run\'
    - '\Software\Microsoft\Windows\CurrentVersion\RunOnce\'
    - '\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run\'
    - '\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce\'
```

This selection identifies values created or modified under common Windows autostart Registry locations.

It covers:

- Standard `Run` values.
- One-time `RunOnce` values.
- Registry locations used by 32-bit applications on 64-bit Windows systems.

Applications referenced by these values may execute when a user signs in.

### Suspicious Path Selection

```yaml
selection_suspicious_path:
  Details|contains:
    - '\AppData\'
    - '\Temp\'
    - '\Downloads\'
    - '\Users\Public\'
    - '%APPDATA%'
    - '%TEMP%'
```

This examines the data written into the Registry value.

The selection looks for content stored in locations commonly writable by standard users. Environment-variable versions such as `%APPDATA%` and `%TEMP%` are included because Registry values may reference paths without using their complete absolute location.

### Final Condition

```yaml
condition: selection_run_key and selection_suspicious_path
```

The rule only matches when:

1. A `Run` or `RunOnce` Registry value is set.
2. The value references a selected user-writable location.

This is more precise than alerting on every modification to a Run key.

## Relevant Event Fields

The following fields should be retained for investigation:

- `TargetObject`: Registry key and value that were modified.
- `Details`: Data written into the Registry value.
- `Image`: Process responsible for the modification.
- `User`: Account that performed the change.
- `Computer`: Affected endpoint.
- `ProcessId`: Operating-system identifier of the responsible process.
- `ProcessGuid`: Unique process identifier when supplied by Sysmon.

## MITRE ATT&CK Mapping

- **T1547.001 — Registry Run Keys / Startup Folder:** An attacker may add a Registry Run entry to execute a program when a user signs in.

## False Positives

Potential legitimate activity includes:

- Applications installed within a user's `AppData` directory.
- Software configured to start automatically when the user signs in.
- Approved software installation or update processes.
- Enterprise logon scripts and administrative automation.
- Collaboration, communication, or synchronisation applications using per-user installation paths.
- Authorised security testing.

A Run key referencing `AppData` is suspicious but does not independently prove malicious activity.

## Investigation Notes

When the rule triggers, the analyst should:

1. Identify the affected endpoint and user.
2. Review the complete `TargetObject` and Registry value name.
3. Examine the command or path recorded in `Details`.
4. Determine which process created or modified the value.
5. Check whether the responsible process is expected and digitally signed.
6. Locate the referenced executable, script, or DLL.
7. Calculate and investigate the referenced file's hashes.
8. Review the file's creation and modification timestamps.
9. Check whether the file was downloaded from the internet.
10. Review related process, PowerShell, command-shell, and network activity.
11. Determine whether the referenced file executed after a user logon.
12. Search other endpoints for the same Registry value, path, filename, or hash.
13. Remove the persistence mechanism and isolate the endpoint if malicious activity is confirmed.

Particularly suspicious indicators include:

- Random or misleading Registry value names.
- Executables with random filenames.
- Unsigned files.
- Recently created files.
- Files stored inside temporary directories.
- Registry modifications performed by Office applications or scripting engines.
- Commands containing encoded or obfuscated content.

## Tuning Recommendations

Organisations may tune the rule by:

- Allowlisting verified application names and digital publishers.
- Allowlisting approved per-user software installation paths.
- Excluding known software-deployment processes.
- Increasing severity when the referenced file is unsigned.
- Increasing severity when the modifying process is a scripting engine or Office application.
- Correlating the event with file creation, network connection, or process execution.
- Comparing Registry values against an approved autostart baseline.
- Enriching referenced file hashes with threat intelligence.

Avoid excluding the entire `AppData` directory because attackers frequently use it to store malicious files.

## Severity Rationale

The rule uses:

```yaml
level: medium
```

Legitimate per-user applications frequently configure automatic startup from `AppData`. Therefore, this detection should generate an investigation alert but should not automatically classify the endpoint as compromised.

The severity may be raised when supporting evidence confirms malicious behaviour.

## Validation Results

The rule was validated using:

```text
Sigma CLI version 3.1.0
```

Validation command:

```powershell
sigma check rules\persistence\registry_run_key_suspicious_path.yml
```

Result:

```text
Found 0 errors, 0 condition errors and 0 issues.
No rule errors found.
No condition errors found.
No validation issues found.
```

Validation date: 25 July 2026.

## Limitations

- The rule requires Registry value-set telemetry.
- It does not confirm that the referenced file executed successfully.
- Legitimate applications may use the same Registry locations and file paths.
- Attackers may use other persistence mechanisms not covered by this rule.
- Registry data may use alternative environment variables or obfuscated paths.
- The rule does not independently determine whether the referenced file is malicious.
- File, process, logon, and network telemetry are needed to confirm the complete activity.

## References

- [MITRE ATT&CK T1547.001 — Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [Microsoft Sysinternals — Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)