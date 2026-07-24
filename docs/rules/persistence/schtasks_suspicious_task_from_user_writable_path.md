# Scheduled Task Creation from User-Writable Path

## Rule Status

Experimental - validated with Sigma CLI 3.1.0.

## Threat Scenario

Windows Task Scheduler allows programs and commands to execute automatically based on configured triggers.

An attacker may use `schtasks.exe` to create a scheduled task that executes malware when Windows starts, when a user signs in, at a specific time, or repeatedly.

This provides persistence or recurring execution without requiring the attacker to launch the malware manually again.

A scheduled task is more suspicious when its action references content stored in a user-writable location such as:

- `AppData`
- `Temp`
- `Downloads`
- `Users\Public`

Example suspicious command:

```text
schtasks.exe /create /tn "Windows Update" /tr "C:\Users\Public\update.exe" /sc onlogon
```

The attacker may use a legitimate-looking task name, such as `Windows Update`, to make the activity appear normal.

## Detection Hypothesis

If `schtasks.exe` creates a scheduled task that executes content from a user-writable directory, the activity should be investigated as possible persistence or recurring malicious execution.

## Required Telemetry

Windows process-creation events containing the complete command line.

```yaml
logsource:
  category: process_creation
  product: windows
```

Suitable telemetry includes:

- Sysmon Event ID 1.
- Windows Security Event ID 4688 with command-line auditing enabled.
- EDR process-creation telemetry.

## Detection Logic Explanation

The rule uses three required selections.

### Process Selection

```yaml
selection_image:
  - Image|endswith: '\schtasks.exe'
  - OriginalFileName: schtasks.exe
```

This confirms that the executed process is the Windows `schtasks.exe` utility.

Checking both `Image` and `OriginalFileName` improves coverage when:

- The executable runs from its standard Windows location.
- The executable path uses different capitalisation.
- A copied or renamed executable retains its original filename metadata.

### Task-Creation Selection

```yaml
selection_create:
  CommandLine|contains: '/create'
```

The `/create` option indicates that `schtasks.exe` is creating a new scheduled task.

This prevents the rule from alerting on commands that only query, display, run, modify, or delete existing tasks.

Important command components include:

- `/tn`: Specifies the task name.
- `/tr`: Specifies the program or command executed by the task.
- `/sc`: Specifies the schedule or trigger.
- `/create`: Creates the task.

### Suspicious Path Selection

```yaml
selection_suspicious_path:
  CommandLine|contains:
    - '\AppData\'
    - '\Temp\'
    - '\Downloads\'
    - '\Users\Public\'
    - '%APPDATA%'
    - '%TEMP%'
```

This examines the scheduled task command for references to user-writable directories.

Environment-variable versions are included because an attacker may use `%APPDATA%` or `%TEMP%` instead of an absolute path.

### Final Condition

```yaml
condition: selection_image and selection_create and selection_suspicious_path
```

The rule only matches when all three behaviours are present:

1. `schtasks.exe` executes.
2. The command creates a task.
3. The task references a selected user-writable location.

This combined logic is more precise than alerting on every use of `schtasks.exe`.

## Relevant Event Fields

The following fields should be retained for investigation:

- `Image`: Executable path.
- `CommandLine`: Complete scheduled-task command.
- `ParentImage`: Process that launched `schtasks.exe`.
- `ParentCommandLine`: Command line of the parent process.
- `User`: Account that created the task.
- `Computer`: Affected endpoint.
- `ProcessId`: Operating-system process identifier.
- `ProcessGuid`: Unique process identifier when supplied by Sysmon.
- `Hashes`: Cryptographic hashes of the executable.

## MITRE ATT&CK Mapping

- **T1053.005 — Scheduled Task/Job: Scheduled Task:** An attacker may create a Windows scheduled task for persistence, recurring execution, or execution under another account context.

## False Positives

Potential legitimate activity includes:

- Approved software installers creating update tasks.
- Per-user applications installed within `AppData`.
- Enterprise software-deployment systems.
- Administrative maintenance and automation.
- Backup, synchronisation, monitoring, or security software.
- Authorised penetration testing.

The presence of a user-writable path is suspicious but does not independently prove malicious activity.

## Investigation Notes

When the rule triggers, the analyst should:

1. Identify the endpoint and user that created the task.
2. Review the complete command line.
3. Extract the task name supplied through `/tn`.
4. Extract the command or executable supplied through `/tr`.
5. Identify the trigger or schedule supplied through `/sc`.
6. Determine what process launched `schtasks.exe`.
7. Locate the file referenced by the task.
8. Check whether the file is digitally signed.
9. Calculate and investigate the file's hashes.
10. Review the file's creation and modification timestamps.
11. Determine whether the file was downloaded from the internet.
12. Review Windows Task Scheduler logs and task-creation events.
13. Check whether the task executed successfully.
14. Search other endpoints for the same task name, path, filename, hash, or command.
15. Disable the task and isolate the endpoint if malicious activity is confirmed.

Particularly suspicious indicators include:

- Task names imitating Windows or security components.
- Random or misleading task names.
- Tasks executing unsigned files.
- Tasks launching PowerShell, command shells, or script interpreters.
- Tasks running from temporary directories.
- Very frequent execution schedules.
- Tasks configured to run as `SYSTEM`.
- Tasks created shortly after a suspicious download or Office document execution.

## Tuning Recommendations

Organisations may tune the rule by:

- Allowlisting verified task names and software publishers.
- Allowlisting approved deployment and update processes.
- Excluding known management servers and administrator accounts.
- Increasing severity when the task runs as `SYSTEM`.
- Increasing severity for very frequent schedules.
- Increasing severity when the parent is an Office application or scripting engine.
- Correlating the alert with task-creation Event ID 4698.
- Correlating the alert with file creation and subsequent process execution.
- Comparing new tasks against an approved scheduled-task baseline.
- Enriching referenced file hashes with threat intelligence.

Avoid excluding all scheduled tasks referencing `AppData`, because attackers may deliberately place malicious files there.

## Severity Rationale

The rule uses:

```yaml
level: medium
```

Legitimate per-user applications and software installers may create scheduled tasks referencing `AppData`. Therefore, the detection should create an investigation alert but should not automatically classify the endpoint as compromised.

The severity may be raised when additional evidence confirms malicious behaviour.

## Validation Results

The rule was validated using:

```text
Sigma CLI version 3.1.0
```

Validation command:

```powershell
sigma check rules\persistence\schtasks_suspicious_task_from_user_writable_path.yml
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

- The rule requires process-creation telemetry with the complete command line.
- It only detects scheduled tasks created through `schtasks.exe`.
- Tasks created through PowerShell, WMI, COM interfaces, APIs, or the graphical interface may not match.
- It does not confirm that the scheduled task executed successfully.
- Legitimate applications may create tasks using the same paths.
- Alternative environment variables or obfuscated paths may avoid the selected strings.
- Additional task, file, process, logon, and network telemetry is required to confirm malicious activity.

## References

- [Microsoft — Schtasks Create](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-create)
- [MITRE ATT&CK T1053.005 — Scheduled Task/Job: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)