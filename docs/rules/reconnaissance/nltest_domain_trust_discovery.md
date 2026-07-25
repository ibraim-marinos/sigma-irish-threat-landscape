# NLTest Domain Trust Discovery

## Rule Status

Experimental - validated with Sigma CLI 3.1.0.

## Threat Scenario

After compromising a Windows endpoint or domain account, an attacker may perform reconnaissance to understand the Active Directory environment.

The legitimate Windows utility `nltest.exe` can display trust relationships between domains. An attacker may abuse this information to identify additional domains, domain controllers, privileged environments, or potential paths for lateral movement.

The activity may form part of the following chain:

```text
Compromised endpoint → NLTest reconnaissance → Domain trust discovery → Lateral movement preparation
```

A trust relationship does not automatically provide access. However, it helps the attacker identify where additional accounts, credentials, and permissions may be useful.

## Detection Hypothesis

If `nltest.exe` is executed with command-line parameters used to enumerate domain trust relationships, the activity should be investigated as possible Active Directory reconnaissance.

This behaviour may be legitimate when performed by domain administrators or support teams. The user, endpoint, command line, parent process, and surrounding activity must therefore be reviewed.

## Required Telemetry

Windows process-creation events containing the executable name, complete command line, parent process, user, and endpoint.

```yaml
logsource:
  category: process_creation
  product: windows
```

Suitable telemetry sources include:

- Sysmon Event ID 1.
- Windows Security Event ID 4688 with command-line auditing enabled.
- Compatible EDR process-creation telemetry.

## Detection Logic Explanation

The rule uses two selections that must occur in the same process-creation event.

### NLTest Executable Selection

```yaml
selection_image:
  - Image|endswith: '\nltest.exe'
  - OriginalFileName: nltest.exe
```

This selection identifies the legitimate Microsoft `nltest.exe` utility.

Two identification methods are used:

- `Image|endswith` checks the executable path.
- `OriginalFileName` checks the filename stored in the executable metadata.

Using both methods provides better resilience if the executable is started from an unexpected directory.

### Domain Trust Parameter Selection

```yaml
selection_trust:
  CommandLine|contains:
    - '/domain_trusts'
    - '/all_trusts'
    - '/trusted_domains'
```

This selection identifies command-line parameters associated with domain-trust enumeration:

- `/domain_trusts`: lists domain trust relationships.
- `/all_trusts`: expands the trust information returned.
- `/trusted_domains`: requests information about trusted domains.

### Detection Condition

```yaml
condition: selection_image and selection_trust
```

Both selections must match. The rule does not alert on every use of NLTest; it focuses on NLTest executions associated with domain-trust discovery.

## Relevant Event Fields

- `Image`: path of the executed `nltest.exe` binary.
- `OriginalFileName`: original executable filename.
- `CommandLine`: command and discovery parameters.
- `ParentImage`: process that started NLTest.
- `ParentCommandLine`: parent-process command line.
- `User`: account performing the discovery.
- `Computer`: endpoint where NLTest was executed.
- `ProcessId`: process identifier.
- `ProcessGuid`: unique process identifier used for correlation.
- `Hashes`: executable hashes.

## MITRE ATT&CK Mapping

### T1482 - Domain Trust Discovery

Attackers may enumerate trust relationships between Active Directory domains to understand the environment and identify possible routes for additional discovery, credential abuse, privilege escalation, or lateral movement.

Domain trust discovery usually supports a later attack stage rather than providing access by itself.

## False Positives

Possible legitimate causes include:

- Domain administrators troubleshooting Active Directory trusts.
- IT support teams diagnosing authentication problems.
- Approved domain migrations or consolidations.
- Active Directory health checks.
- Identity-management operations.
- Enterprise monitoring or inventory automation.
- Authorised penetration testing and security assessments.

The analyst should verify whether the user, device, timing, parent process, and command are expected before closing the alert.

## Investigation Notes

1. Identify the account that executed NLTest.
2. Determine whether the account belongs to:
   - A domain administrator.
   - An authorised support engineer.
   - A service account.
   - A standard user.
3. Review the endpoint where the command was executed.
4. Determine whether NLTest is normally used on that endpoint.
5. Review the complete command line and requested trust information.
6. Examine `ParentImage` and `ParentCommandLine`.
7. Determine whether execution occurred through:
   - An interactive command prompt.
   - PowerShell.
   - A script.
   - Remote administration.
   - An endpoint-management tool.
8. Search for nearby discovery activity involving:
   - Users.
   - Groups.
   - Computers.
   - Domain controllers.
   - Network shares.
   - Privileged accounts.
9. Review authentication events following the discovery command.
10. Check for connections to additional hosts or domains.
11. Determine whether the source endpoint shows malware, credential theft, or persistence indicators.
12. Confirm whether the activity belongs to an approved administrative task or security assessment.
13. Escalate when the command originates from an unusual endpoint, account, or parent process.

## Tuning Recommendations

- Establish which administrator accounts and management systems legitimately use NLTest.
- Maintain narrow allowlists for verified administrative workflows.
- Avoid excluding all executions by administrators because compromised privileged accounts can also perform discovery.
- Increase severity when NLTest is executed by a standard user.
- Increase severity when the parent process is PowerShell, a script interpreter, an Office application, or a remote-execution utility.
- Correlate with other discovery commands occurring within a short period.
- Correlate with subsequent remote authentication or service creation.
- Review allowlist entries regularly.

## Severity Rationale

The rule uses a `medium` severity because domain-trust discovery is suspicious in many user contexts but also has legitimate Active Directory administration uses.

Severity should be increased when the activity is performed by an unexpected user, from a workstation that does not normally run administrative tools, or alongside other signs of compromise.

## Validation Results

The rule was validated on 26 July 2026 using Sigma CLI 3.1.0.

Command used:

```powershell
sigma check rules\reconnaissance\nltest_domain_trust_discovery.yml
```

Result:

```text
Found 0 errors, 0 condition errors and 0 issues.
No rule errors found.
No condition errors found.
No validation issues found.
```

## Limitations

- The rule detects only the specified NLTest command-line parameters.
- Attackers may perform domain-trust discovery through PowerShell, LDAP queries, Windows APIs, or other tools.
- Renamed or modified copies of NLTest may evade filename-based detection.
- Command-line telemetry must be enabled and collected.
- The rule cannot determine by itself whether the user is authorised.
- Trust discovery does not prove that lateral movement occurred.
- Validation confirms Sigma syntax and structure, not detection performance in every SIEM or production environment.

## References

- https://attack.mitre.org/techniques/T1482/
- https://attack.mitre.org/detectionstrategies/DET0007/
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731935%28v%3Dws.11%29
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon