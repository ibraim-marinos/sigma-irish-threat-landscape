# Rundll32 Suspicious Script Execution

## Rule Status

Experimental - successfully validated with Sigma CLI.

## Threat Scenario

An attacker may abuse the legitimate Windows `rundll32.exe` binary to execute JavaScript or VBScript through unusual command-line arguments.

Patterns involving `javascript:`, `vbscript:`, `mshtml`, or `RunHTMLApplication` can allow script execution through a trusted Microsoft-signed binary instead of launching a conventional script interpreter.

## Detection Hypothesis

If Windows process-creation telemetry records `rundll32.exe` with script-protocol and MSHTML execution indicators, the activity should be investigated as possible signed binary proxy execution.

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

The rule uses three required selections.

### Rundll32 Process

```yaml
selection_image:
  - Image|endswith: '\rundll32.exe'
  - OriginalFileName: RUNDLL32.EXE
```

This identifies `rundll32.exe` through its executed path or original filename.

### Script Protocol

```yaml
selection_protocol:
  CommandLine|contains:
    - 'javascript:'
    - 'vbscript:'
```

This identifies JavaScript or VBScript protocol handlers in the process command line.

### MSHTML Execution

```yaml
selection_mshtml:
  CommandLine|contains:
    - 'mshtml'
    - 'RunHTMLApplication'
```

This identifies MSHTML components or functions associated with HTML and script execution.

### Final Condition

```yaml
condition: selection_image and selection_protocol and selection_mshtml
```

All three selections must match. Normal `rundll32.exe` activity without script and MSHTML indicators will not trigger the rule.

## MITRE ATT&CK Mapping

- **T1218.011 - System Binary Proxy Execution: Rundll32:** An attacker may abuse `rundll32.exe` to execute malicious DLL or script content through a trusted Windows binary.

## False Positives

Potential legitimate activity includes:

- Approved legacy applications that use unusual Rundll32 command lines.
- Authorised administrative scripts.
- Application compatibility testing.
- Security-team simulations or detection testing.
- Internal troubleshooting involving MSHTML components.

Script-protocol execution through `rundll32.exe` should be uncommon and verified carefully before allowlisting.

## Investigation Notes

When the rule triggers, the analyst should:

1. Extract the complete `rundll32.exe` command line.
2. Identify the script protocol and MSHTML function used.
3. Determine whether the command contains a URL, encoded content, or obfuscated script.
4. Identify the user and endpoint where the process executed.
5. Review `ParentImage` and `ParentCommandLine`.
6. Determine whether an Office application, browser, email client, archive utility, or script interpreter launched the process.
7. Review DNS queries and network connections associated with `rundll32.exe`.
8. Search for files created, downloaded, or modified near the execution time.
9. Identify child processes and subsequent command execution.
10. Search for the same command line, URL, or indicators across other endpoints.
11. Isolate the endpoint and block malicious infrastructure if compromise is confirmed.

## Tuning Recommendations

- Avoid globally allowlisting `rundll32.exe`.
- Allowlist only verified applications and exact expected command-line patterns.
- Increase severity when launched by Office, browser, email, archive, or scripting processes.
- Increase severity when URLs, encoded content, temporary directories, or unusual domains are present.
- Correlate with network connections, DNS queries, file creation, module loads, and child processes.
- Tune field mappings according to the target SIEM or EDR schema.

## Validation Results

The rule was validated on 24 July 2026 using Sigma CLI 3.1.0.

```powershell
sigma check rules\lolbins\rundll32_suspicious_script_execution.yml
```

Validation result:

```text
Found 0 errors, 0 condition errors and 0 issues.
No rule errors found.
No condition errors found.
No validation issues found.
```

## Limitations

- The rule requires script and MSHTML indicators to be visible in the process command line.
- Obfuscated, encoded, or indirectly supplied arguments may evade detection.
- A renamed copy may not be detected when original-filename telemetry is unavailable.
- The rule does not confirm that script execution completed successfully.
- Legitimate legacy applications may generate alerts.
- Command-line collection must be enabled and correctly normalised.

## References

- https://attack.mitre.org/techniques/T1218/011/
- https://attack.mitre.org/detectionstrategies/DET0475/
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon