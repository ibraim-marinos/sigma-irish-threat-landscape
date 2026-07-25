# Rundll32 Comsvcs LSASS Memory Dump

## Rule Status

Experimental - validated with Sigma CLI 3.1.0.

## Threat Scenario

After compromising a Windows system and obtaining sufficient privileges, an attacker may attempt to extract credential material stored in the memory of the Local Security Authority Subsystem Service (`lsass.exe`).

Windows stores credential-related material in LSASS after users authenticate. Depending on the system configuration and available privileges, this material may include password hashes, Kerberos tickets, or other authentication information.

An attacker may abuse the legitimate Windows binary `rundll32.exe` together with the `MiniDump` functionality exported by `comsvcs.dll` to create a memory dump. The resulting dump file can then be analysed with credential-access tools.

Stolen credentials or hashes may allow the attacker to impersonate users, access privileged accounts, reuse authentication material, and move laterally to additional systems.

## Detection Hypothesis

If Windows process-creation telemetry records `rundll32.exe` executing `comsvcs.dll` with the `MiniDump` function, the activity should be investigated as potential LSASS credential dumping.

The complete combination is more meaningful than detecting `rundll32.exe` by itself because Rundll32 is a legitimate and commonly used Windows binary.

## Required Telemetry

Windows process-creation events containing full command-line information.

Suitable telemetry sources include:

- Sysmon Event ID 1 — Process creation.
- Windows Security Event ID 4688 — A new process has been created.
- Endpoint detection and response process telemetry.

```yaml
logsource:
  category: process_creation
  product: windows
```

Command-line auditing must be enabled so that the arguments supplied to `rundll32.exe` are available to the detection rule.

## Detection Logic Explanation

The rule contains three required selections.

### Process Selection

```yaml
selection_image:
  - Image|endswith: '\rundll32.exe'
  - OriginalFileName: RUNDLL32.EXE
```

This selection identifies Rundll32 through either its executable path or its original filename.

Using `OriginalFileName` provides additional resilience when an attacker copies or renames the executable while preserving its file metadata.

### Comsvcs Library Selection

```yaml
selection_library:
  CommandLine|contains: 'comsvcs.dll'
```

This selection requires the command line to reference `comsvcs.dll`.

The DLL is a legitimate Windows component, but its exported functionality can be abused to create a process-memory dump.

### MiniDump Function Selection

```yaml
selection_minidump:
  CommandLine|contains: 'MiniDump'
```

This selection requires the command line to invoke the `MiniDump` function.

The combination of `comsvcs.dll` and `MiniDump` is substantially more suspicious than ordinary Rundll32 execution.

### Final Condition

```yaml
condition: selection_image and selection_library and selection_minidump
```

All three selections must be true in the same process-creation event.

The rule therefore requires:

```text
rundll32.exe
AND comsvcs.dll
AND MiniDump
```

This combined condition reduces false positives and focuses the alert on a known credential-dumping pattern.

## Relevant Event Fields

| Field | Investigation Value |
|---|---|
| `Image` | Confirms the executed binary and its location |
| `CommandLine` | Shows the DLL, exported function, process identifier, and dump destination |
| `ParentImage` | Identifies the process that launched Rundll32 |
| `ParentCommandLine` | Provides additional execution context |
| `User` | Identifies the account responsible for execution |
| `Computer` | Identifies the affected endpoint |
| `ProcessId` | Identifies the Rundll32 process |
| `ProcessGuid` | Supports correlation with related Sysmon activity |
| `Hashes` | Supports verification of renamed or modified binaries |

## MITRE ATT&CK Mapping

- **Tactic:** Credential Access
- **Technique:** T1003 — OS Credential Dumping
- **Sub-technique:** T1003.001 — LSASS Memory

MITRE ATT&CK documents that credential material stored in LSASS memory may be harvested and used for lateral movement or alternate authentication.

MITRE also documents `rundll32.exe`, `comsvcs.dll`, and `MiniDump` as a method for creating an LSASS process-memory dump.

## False Positives

Potential legitimate activity may include:

- Approved digital-forensics investigations.
- Incident-response memory collection.
- Authorised penetration testing.
- Security-product testing.
- Troubleshooting performed by privileged administrators.

The complete command pattern should be rare in ordinary enterprise activity.

Before closing the alert as benign, the analyst should verify that the execution corresponds to an approved security or administrative activity.

## Investigation Notes

When this rule triggers, the analyst should:

1. Identify the user and endpoint associated with the event.
2. Confirm whether the account had administrative or SYSTEM privileges.
3. Review the complete Rundll32 command line.
4. Identify the parent process and determine why it launched Rundll32.
5. Determine the process identifier supplied to `MiniDump`.
6. Verify whether the target process was `lsass.exe`.
7. Identify the path and filename of the generated dump.
8. Search for file-creation telemetry around the same timestamp.
9. Determine whether the dump was compressed, renamed, copied, uploaded, or deleted.
10. Search for Mimikatz, credential-extraction tools, archive utilities, or suspicious PowerShell activity.
11. Review subsequent Windows logons and network authentication.
12. Determine whether the account accessed additional endpoints.
13. Check whether the event was part of approved forensic or penetration-testing activity.
14. Isolate the endpoint and reset exposed credentials if malicious activity is confirmed.

## Tuning Recommendations

Organisations may tune this rule by:

- Allowlisting approved forensic tools and incident-response workflows.
- Restricting exceptions to specific administrative systems and authorised accounts.
- Correlating the event with file creation in temporary or user-writable directories.
- Correlating with Sysmon Event ID 10 access to `lsass.exe`.
- Increasing priority when the parent process is PowerShell, Command Prompt, an Office application, or an unexpected executable.
- Increasing priority when the same account subsequently authenticates to additional systems.

Broad exclusions for `rundll32.exe` or `comsvcs.dll` should be avoided because they could suppress genuine credential-dumping activity.

## Severity Rationale

The rule uses a `high` severity because successful LSASS memory dumping may expose reusable authentication material.

Credential theft can enable privilege escalation, account compromise, lateral movement, and broader domain intrusion.

Although legitimate forensic activity can produce this pattern, the complete combination should be uncommon and requires prompt investigation.

## Validation Results

The rule was validated with Sigma CLI 3.1.0.

Validation command:

```powershell
sigma check rules\credential_access\rundll32_comsvcs_lsass_memory_dump.yml
```

Validation result:

```text
Found 0 errors, 0 condition errors and 0 issues.
No rule errors found.
No condition errors found.
No validation issues found.
```

The validation confirms that:

- The YAML syntax is valid.
- The detection selections are recognised.
- The condition references valid selections.
- The MITRE ATT&CK technique tag is accepted.
- No Sigma validation issues were identified.

## Limitations

- The rule detects a specific command-line method involving Rundll32 and `comsvcs.dll`.
- It does not detect every possible LSASS dumping technique.
- Attackers may use ProcDump, Task Manager, direct API calls, custom malware, or renamed tools.
- Process-creation telemetry alone does not confirm that the target process was LSASS.
- Missing or truncated command-line data may prevent detection.
- Case-sensitive backends may require additional normalisation.
- Legitimate forensic activity may generate the same command pattern.

This rule should be combined with process-access, file-creation, authentication, and endpoint-security telemetry.

## References

- https://attack.mitre.org/techniques/T1003/001/
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing