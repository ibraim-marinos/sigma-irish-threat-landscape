# Regsvr32 Remote Scriptlet Execution

## Rule Status

Experimental - successfully validated with Sigma CLI.

## Threat Scenario

An attacker may abuse the legitimate Windows `regsvr32.exe` utility to retrieve and execute a remote COM scriptlet.

A commonly abused command pattern combines the `/i` parameter, a remote HTTP or HTTPS URL, and `scrobj.dll`. This technique can execute script content through a trusted Microsoft-signed binary without registering a normal COM object.

## Detection Hypothesis

If Windows process-creation telemetry records `regsvr32.exe` using the `/i` parameter with a remote URL and `scrobj.dll`, the activity should be investigated as possible signed binary proxy execution.

## Required Telemetry

Windows process-creation events containing the complete command line.

```yaml
logsource:
  category: process_creation
  product: windows
```

Relevant sources include:

- Sysmon Event ID 1.
- Windows Security Event ID 4688 with command-line auditing enabled.
- EDR process-creation telemetry.

## Detection Logic Explanation

The rule uses four required selections.

### Regsvr32 Process

```yaml
selection_image:
  - Image|endswith: '\regsvr32.exe'
  - OriginalFileName: REGSVR32.EXE
```

This identifies `regsvr32.exe` through its executed path or original filename.

### Install Parameter

```yaml
selection_install:
  CommandLine|contains: '/i:'
```

This identifies use of the `/i` parameter, which passes a command-line string to the DLL installation function.

### Remote URL

```yaml
selection_url:
  CommandLine|contains:
    - 'http://'
    - 'https://'
```

This identifies remote HTTP or HTTPS content in the command line.

### Scriptlet Component

```yaml
selection_scriptlet:
  CommandLine|contains: 'scrobj.dll'
```

This identifies the Windows scriptlet component commonly involved in remote COM scriptlet execution.

### Final Condition

```yaml
condition: selection_image and selection_install and selection_url and selection_scriptlet
```

All four selections must match, reducing false positives from legitimate local DLL registration.

## MITRE ATT&CK Mapping

- **T1218.010 - System Binary Proxy Execution: Regsvr32:** An attacker may abuse `regsvr32.exe` to execute malicious scriptlets or DLL content through a trusted Windows binary.

## False Positives

Potential legitimate activity includes:

- Approved legacy applications that load remote COM scriptlets.
- Authorised administrative automation.
- Internal testing by application-development or security teams.
- Approved software-deployment workflows.

Remote use of `scrobj.dll` should be uncommon and verified carefully before allowlisting.

## Investigation Notes

When the rule triggers, the analyst should:

1. Extract the complete command line and remote URL.
2. Review the domain, IP address, path, and scriptlet extension.
3. Determine whether the destination is known and approved.
4. Identify the user and endpoint where the command executed.
5. Review `ParentImage` and `ParentCommandLine`.
6. Determine whether an Office application, browser, email client, or script interpreter launched `regsvr32.exe`.
7. Review DNS queries and network connections associated with the process.
8. Search for scriptlet, DLL, or temporary files created near the execution time.
9. Identify child processes and subsequent command execution.
10. Search for the same URL or command line across other endpoints.
11. Isolate the endpoint and block malicious infrastructure if compromise is confirmed.

## Tuning Recommendations

- Allowlist only verified internal domains, applications, or automation.
- Avoid globally allowlisting `regsvr32.exe` or `scrobj.dll`.
- Increase severity when launched by Office, browser, email, or scripting processes.
- Increase severity when the URL uses an IP address, URL shortener, or unusual domain.
- Correlate with network connections, DNS queries, module loads, file creation, and child processes.
- Tune field mappings according to the target SIEM or EDR schema.

## Validation Results

The rule was validated on 24 July 2026 using Sigma CLI 3.1.0.

```powershell
sigma check rules\lolbins\regsvr32_remote_scriptlet_execution.yml
```

Validation result:

```text
Found 0 errors, 0 condition errors and 0 issues.
No rule errors found.
No condition errors found.
No validation issues found.
```

## Limitations

- The rule requires the suspicious indicators to be visible in the process command line.
- Obfuscated, encoded, or indirectly supplied parameters may evade detection.
- A renamed copy may not be detected when original-filename telemetry is unavailable.
- The rule does not confirm that remote content executed successfully.
- Legitimate legacy applications may produce alerts.
- Command-line collection must be enabled and correctly normalised.

## References

- https://attack.mitre.org/techniques/T1218/010/
- https://attack.mitre.org/detectionstrategies/DET0282/
- https://learn.microsoft.com/en-gb/windows-server/administration/windows-commands/regsvr32