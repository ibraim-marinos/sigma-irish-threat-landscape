# MSHTA Remote URL Execution

## Rule Status

Experimental - successfully validated with Sigma CLI.

## Threat Scenario

An attacker may abuse the legitimate Windows `mshta.exe` binary to retrieve and execute a remote HTML Application, JavaScript, or VBScript payload.

Because `mshta.exe` is a Microsoft-signed Windows binary, its execution may appear less suspicious than an unknown executable. Loading content from an external URL can allow an attacker to execute malicious code while abusing a trusted system utility.

## Detection Hypothesis

If Windows process-creation telemetry records `mshta.exe` with an HTTP or HTTPS URL in its command line, the activity should be investigated as possible signed binary proxy execution.

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

The rule uses two required selections.

### MSHTA Process

```yaml
selection_image:
  - Image|endswith: '\mshta.exe'
  - OriginalFileName: MSHTA.EXE
```

This selection identifies `mshta.exe` by its executed path or original filename. The original filename provides additional resilience if the binary has been copied or renamed.

### Remote URL

```yaml
selection_url:
  CommandLine|contains:
    - 'http://'
    - 'https://'
```

This selection identifies an HTTP or HTTPS address within the process command line.

### Final Condition

```yaml
condition: selection_image and selection_url
```

The rule requires both the MSHTA process and a remote URL. Executing `mshta.exe` without a URL will not trigger the detection.

## MITRE ATT&CK Mapping

- **T1218.005 - System Binary Proxy Execution: Mshta:** An attacker may abuse `mshta.exe` to execute malicious HTA, JavaScript, or VBScript content through a trusted Windows binary.

## False Positives

Potential legitimate activity includes:

- Approved internal applications that use remote HTA content.
- Legacy business applications dependent on `mshta.exe`.
- Authorised administrative or troubleshooting activity.
- Internal deployment tools referencing an approved web server.

The destination domain and the reason for execution should be verified before creating an allowlist entry.

## Investigation Notes

When the rule triggers, the analyst should:

1. Extract the complete command line and remote URL.
2. Review the domain, IP address, path, and file extension.
3. Determine whether the destination is internal, approved, newly registered, or suspicious.
4. Identify the user and endpoint where the process executed.
5. Review `ParentImage` and `ParentCommandLine`.
6. Determine whether an Office application, browser, email client, archive utility, or script interpreter launched `mshta.exe`.
7. Review DNS queries and network connections associated with the process.
8. Search for files created or downloaded near the execution time.
9. Identify child processes launched by `mshta.exe`.
10. Review endpoint activity for persistence, credential access, or additional payload execution.
11. Isolate the endpoint and block malicious infrastructure if compromise is confirmed.

## Tuning Recommendations

- Allowlist approved internal domains only after verification.
- Avoid allowlisting `mshta.exe` globally.
- Increase severity when the parent process is an Office application, browser, email client, or script interpreter.
- Increase severity when the URL uses an IP address, URL shortener, unusual top-level domain, or encoded content.
- Correlate with Sysmon network, DNS, file-creation, and child-process events.
- Tune field mappings according to the target SIEM or EDR schema.

## Validation Results

The rule was validated on 24 July 2026 using Sigma CLI 3.1.0.

```powershell
sigma check rules\lolbins\mshta_remote_url_execution.yml
```

Validation result:

```text
Found 0 errors, 0 condition errors and 0 issues.
No rule errors found.
No condition errors found.
No validation issues found.
```

## Limitations

- The rule detects URLs visible in the process command line.
- Obfuscated or indirectly supplied URLs may avoid this detection.
- A copied or renamed binary may not be detected if original-filename telemetry is unavailable.
- Legitimate legacy applications may generate alerts.
- The rule does not confirm that remote content was downloaded or executed successfully.
- Command-line collection must be enabled and correctly normalised.

## References

- https://attack.mitre.org/techniques/T1218/005/
- https://attack.mitre.org/detectionstrategies/DET0506/
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon