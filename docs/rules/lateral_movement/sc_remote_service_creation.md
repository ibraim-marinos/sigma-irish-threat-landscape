# SC.exe Remote Service Creation

## Rule Status

Experimental - validated with Sigma CLI 3.1.0.

## Threat Scenario

After obtaining administrative credentials, an attacker may use the legitimate Windows Service Controller utility `sc.exe` to create a service on another Windows system.

The attacker can configure the remote service to execute a malicious program, script, or command. Starting that service can provide code execution on the remote endpoint and allow the attacker to move laterally through the network.

The activity may form part of the following chain:

```text
Stolen administrative credentials → Remote service creation → Payload execution → Lateral movement
```

A conceptual command may resemble:

```text
sc.exe \\REMOTE-HOST create UpdateService binPath= "C:\Temp\payload.exe"
```

Remote service creation normally requires sufficient administrative permissions on the destination system.

## Detection Hypothesis

If `sc.exe` is used with a remote computer path, the `create` command, and a configured `binPath=`, the activity should be investigated as possible remote service execution or lateral movement.

The behaviour may be legitimate when performed by system administrators or deployment tools. The user, source endpoint, destination endpoint, service name, and configured binary must therefore be reviewed.

## Required Telemetry

Windows process-creation events containing the executable name, complete command line, parent process, user, and source endpoint.

```yaml
logsource:
  category: process_creation
  product: windows
```

Suitable telemetry sources include:

- Sysmon Event ID 1.
- Windows Security Event ID 4688 with command-line auditing enabled.
- Compatible EDR process-creation telemetry.
- Windows System Event ID 7045 as supporting evidence of service installation.

## Detection Logic Explanation

The rule uses four selections that must occur in the same process-creation event.

### SC Executable Selection

```yaml
selection_image:
  - Image|endswith: '\sc.exe'
  - OriginalFileName: sc.exe
```

This selection identifies the legitimate Windows Service Controller utility.

Two methods are used:

- `Image|endswith` checks the executable path.
- `OriginalFileName` checks the filename stored in executable metadata.

### Remote Target Selection

```yaml
selection_remote:
  CommandLine|contains: '\\'
```

This selection identifies the remote-computer syntax used by SC commands, such as:

```text
\\REMOTE-HOST
```

The presence of a remote target differentiates this behaviour from local service creation.

### Service Creation Selection

```yaml
selection_create:
  CommandLine|contains: 'create'
```

This selection identifies the SC command used to create a new Windows service.

### Binary Path Selection

```yaml
selection_binpath:
  CommandLine|contains: 'binPath='
```

This selection identifies the executable, script, or command configured to run when the service starts.

### Detection Condition

```yaml
condition: selection_image and selection_remote and selection_create and selection_binpath
```

All four selections must match. This reduces noise compared with detecting every execution of `sc.exe`.

## Relevant Event Fields

- `Image`: path of the executed `sc.exe` binary.
- `OriginalFileName`: original executable filename.
- `CommandLine`: remote host, service name, operation, and binary path.
- `ParentImage`: process that started SC.
- `ParentCommandLine`: parent-process command line.
- `User`: account creating the service.
- `Computer`: source endpoint where SC was executed.
- `ProcessId`: process identifier.
- `ProcessGuid`: unique process identifier used for correlation.
- `Hashes`: executable hashes.

## MITRE ATT&CK Mapping

### T1569.002 - System Services: Service Execution

Attackers may abuse the Windows Service Control Manager and utilities such as `sc.exe` to create or modify services that execute malicious content.

When the service is created on another system, this technique can provide remote execution and support lateral movement.

## False Positives

Possible legitimate causes include:

- Approved remote software deployment.
- System administration.
- Enterprise configuration management.
- Monitoring or backup-agent installation.
- Software installation and updates.
- Incident-response activity.
- Authorised penetration testing.
- Server provisioning and maintenance.

The analyst should verify the source account, destination system, service name, binary path, file signature, and associated change-management record.

## Investigation Notes

1. Identify the account that executed `sc.exe`.
2. Determine whether the account has authorised administrative responsibilities.
3. Identify the source endpoint where SC was executed.
4. Extract the remote destination from the command line.
5. Identify the service name created on the destination system.
6. Review the complete value assigned to `binPath=`.
7. Determine whether the binary path references:
   - A temporary directory.
   - A user-writable directory.
   - An administrative share.
   - A script interpreter.
   - An unsigned executable.
   - A suspicious command.
8. Check the signature and hash of the configured binary.
9. Review Windows System Event ID 7045 on the destination system.
10. Determine whether the new service was started.
11. Review service-related registry changes.
12. Search for file transfers to the remote endpoint before service creation.
13. Review SMB, RPC, and remote-authentication activity.
14. Determine whether the same account targeted additional endpoints.
15. Search for credential-theft or privilege-escalation activity on the source endpoint.
16. Confirm whether an approved deployment or change-management record exists.
17. Isolate affected endpoints if unauthorised remote execution is confirmed.

## Tuning Recommendations

- Identify management servers and deployment accounts that legitimately create remote services.
- Maintain narrow allowlists based on verified source system, account, service name, and binary path.
- Avoid excluding all administrator activity because compromised administrator accounts can perform lateral movement.
- Increase severity when the destination is a server, domain controller, or other critical asset.
- Increase severity when `binPath=` references a temporary or user-writable directory.
- Correlate with Event ID 7045 on the destination endpoint.
- Correlate with SMB file transfer, remote authentication, or service-start activity.
- Review allowlist entries regularly.

## Severity Rationale

The rule uses a `high` severity because it detects the combination of a remote target, service creation, and configured executable path.

This combination can provide privileged remote code execution and enable movement between systems. Legitimate administration remains possible, so the alert requires contextual investigation.

## Validation Results

The rule was validated on 26 July 2026 using Sigma CLI 3.1.0.

Command used:

```powershell
sigma check rules\lateral_movement\sc_remote_service_creation.yml
```

Result:

```text
Found 0 errors, 0 condition errors and 0 issues.
No rule errors found.
No condition errors found.
No validation issues found.
```

## Limitations

- The rule detects only remote service creation performed through `sc.exe`.
- Attackers may use PsExec, PowerShell, WMI, APIs, or other remote-execution methods.
- Renamed or modified copies of SC may evade filename-based detection.
- An attacker may modify an existing service instead of creating a new one.
- The rule does not confirm that the service was successfully created or started.
- Command-line telemetry must be enabled and collected.
- The rule cannot determine by itself whether the activity was authorised.
- Validation confirms Sigma syntax and structure, not detection performance in every SIEM or production environment.

## References

- https://attack.mitre.org/techniques/T1569/002/
- https://attack.mitre.org/detectionstrategies/DET0421/
- https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-create
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon