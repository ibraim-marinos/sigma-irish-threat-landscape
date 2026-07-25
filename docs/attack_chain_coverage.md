# Attack Chain Coverage

## Purpose

This document explains how the 15 Sigma rules in the Sigma Rule Library - Irish Threat Landscape work together to detect activity across a multi-stage cyberattack.

The rules are not intended to represent a single malware family or one fixed intrusion sequence. Together, they provide behavioural coverage across Microsoft 365, Microsoft Entra ID, Windows endpoints, Active Directory, credential access, persistence, reconnaissance, and lateral movement.

The operational stages below provide an investigation narrative. Individual MITRE ATT&CK techniques may support more than one attack stage or tactic.

## Coverage Summary

| Operational Stage | Detection Focus | Relevant Rules | MITRE ATT&CK |
|---|---|---|---|
| Initial execution | Malicious document or phishing attachment causing Office to launch PowerShell | Office Application Spawning PowerShell | T1204.002, T1059.001 |
| Payload delivery | Remote content downloaded through PowerShell or Certutil | PowerShell Remote Payload Download; Certutil Remote File Download | T1059.001, T1105 |
| Signed binary abuse | Trusted Windows binaries used to execute scripts or remote content | MSHTA Remote URL Execution; Regsvr32 Remote Scriptlet Execution; Rundll32 Suspicious Script Execution | T1218.005, T1218.010, T1218.011 |
| Local persistence | Malware configured to execute automatically through Registry or scheduled tasks | Registry Run Key Persistence from Suspicious Path; Scheduled Task Creation from User-Writable Path | T1547.001, T1053.005 |
| Cloud persistence and access | OAuth consent or application permissions provide continued access | M365 OAuth Consent with High-Risk Permissions; M365 Service Principal High-Risk Application Permissions | T1671, T1550.001, T1098.003 |
| Credential access | LSASS memory dumped through Rundll32 and Comsvcs | Rundll32 Comsvcs LSASS Memory Dump | T1003.001 |
| Discovery | Active Directory domain trust relationships enumerated | NLTest Domain Trust Discovery | T1482 |
| Remote execution | A service is created on another Windows system | SC.exe Remote Service Creation | T1569.002 |
| Email collection | Compromised mailbox configured to forward messages | M365 Inbox Forwarding with Message Hiding; M365 Mailbox SMTP Forwarding with Local Delivery | T1114.003 |
| Activity concealment | Inbox rule actions hide forwarded or redirected email | M365 Inbox Forwarding with Message Hiding | T1564.008 |

## End-to-End Attack Scenario

### Stage 1 — Phishing and User Execution

An employee receives a malicious attachment or document and opens it.

The Office Application Spawning PowerShell rule detects an Office application such as Word, Excel, PowerPoint, or Outlook launching PowerShell.

This behaviour may indicate that document content, a macro, an add-in, or another Office-based mechanism initiated script execution.

Relevant rule:

- Office Application Spawning PowerShell
- MITRE ATT&CK T1204.002 and T1059.001

### Stage 2 — Payload Retrieval

PowerShell retrieves an additional script or malware payload from an HTTP or HTTPS location.

Alternatively, an attacker may use Certutil to retrieve a remote file while blending with trusted Windows activity.

Relevant rules:

- PowerShell Remote Payload Download
- Certutil Remote File Download
- MITRE ATT&CK T1059.001 and T1105

### Stage 3 — Trusted Binary Abuse

The attacker may use Microsoft-signed Windows binaries to execute remote or script-based content.

These binaries are legitimate, commonly present, and may be permitted by basic application controls.

Relevant rules:

- MSHTA Remote URL Execution
- Regsvr32 Remote Scriptlet Execution
- Rundll32 Suspicious Script Execution
- MITRE ATT&CK T1218.005, T1218.010, and T1218.011

### Stage 4 — Local Persistence

After executing a payload, the attacker attempts to maintain access across user logons or system restarts.

A Registry Run or RunOnce value may reference content stored in a user-writable directory. A scheduled task may also be created to execute content from AppData, Temp, Downloads, or Users Public.

Relevant rules:

- Registry Run Key Persistence from Suspicious Path
- Scheduled Task Creation from User-Writable Path
- MITRE ATT&CK T1547.001 and T1053.005

### Stage 5 — Cloud Persistence and Microsoft 365 Abuse

If a Microsoft 365 identity is compromised, an attacker may grant consent to a malicious application or assign broad Microsoft Graph permissions to a service principal.

OAuth tokens and application permissions may provide access that does not depend on repeatedly using the victim's password.

Relevant rules:

- M365 OAuth Consent with High-Risk Permissions
- M365 Service Principal High-Risk Application Permissions
- MITRE ATT&CK T1671, T1550.001, and T1098.003

### Stage 6 — Credential Access

The attacker attempts to obtain additional authentication material from the compromised Windows endpoint.

Rundll32 may invoke the MiniDump functionality in Comsvcs to create a process-memory dump associated with LSASS credential access.

Relevant rule:

- Rundll32 Comsvcs LSASS Memory Dump
- MITRE ATT&CK T1003.001

### Stage 7 — Domain Discovery

Using compromised access, the attacker investigates Active Directory trust relationships.

Understanding trusted domains may help identify additional environments, privileged accounts, and possible paths for expansion.

Relevant rule:

- NLTest Domain Trust Discovery
- MITRE ATT&CK T1482

### Stage 8 — Remote Execution and Lateral Movement

The attacker uses SC.exe to create a service on a remote Windows system and specifies the executable path for that service.

Remote service creation can provide execution on another endpoint when the attacker possesses suitable credentials and network access.

Relevant rule:

- SC.exe Remote Service Creation
- MITRE ATT&CK T1569.002

### Stage 9 — Email Collection and Concealment

After compromising a Microsoft 365 mailbox, the attacker creates forwarding behaviour to collect incoming messages.

The attacker may preserve local delivery so the victim continues receiving messages, or combine forwarding with actions that mark messages as read, move them, or delete them.

Relevant rules:

- M365 Inbox Forwarding with Message Hiding
- M365 Mailbox SMTP Forwarding with Local Delivery
- MITRE ATT&CK T1114.003 and T1564.008

## Complete Rule Inventory

| # | Rule | Category | MITRE ATT&CK |
|---|---|---|---|
| 1 | M365 Inbox Forwarding with Message Hiding | BEC / Phishing | T1114.003, T1564.008 |
| 2 | M365 Mailbox SMTP Forwarding with Local Delivery | BEC / Phishing | T1114.003 |
| 3 | M365 OAuth Consent with High-Risk Permissions | OAuth Abuse | T1671, T1550.001 |
| 4 | M365 Service Principal High-Risk Application Permissions | OAuth Abuse | T1671, T1098.003 |
| 5 | MSHTA Remote URL Execution | LOLBins | T1218.005 |
| 6 | Regsvr32 Remote Scriptlet Execution | LOLBins | T1218.010 |
| 7 | Rundll32 Suspicious Script Execution | LOLBins | T1218.011 |
| 8 | Certutil Remote File Download | LOLBins | T1105 |
| 9 | Registry Run Key Persistence from Suspicious Path | Persistence | T1547.001 |
| 10 | Scheduled Task Creation from User-Writable Path | Persistence | T1053.005 |
| 11 | Office Application Spawning PowerShell | Malware / Phishing | T1204.002, T1059.001 |
| 12 | NLTest Domain Trust Discovery | Reconnaissance | T1482 |
| 13 | SC.exe Remote Service Creation | Lateral Movement | T1569.002 |
| 14 | Rundll32 Comsvcs LSASS Memory Dump | Credential Access | T1003.001 |
| 15 | PowerShell Remote Payload Download | Malware Delivery | T1059.001, T1105 |

## Coverage Strengths

The rule set demonstrates several detection-engineering principles:

- Behavioural detection instead of dependence on fixed indicators of compromise.
- Coverage across cloud identity, email, Windows endpoints, and Active Directory.
- Detection of trusted-tool abuse and living-off-the-land activity.
- Correlation opportunities across process creation, Registry changes, Microsoft 365 auditing, and Microsoft Entra auditing.
- MITRE ATT&CK mapping for every rule.
- False-positive and investigation guidance for every detection.
- Detection coverage across multiple connected stages of an intrusion.
- Portable Sigma logic that can be converted for compatible SIEM platforms.

## Correlation Opportunities

Individual alerts become more meaningful when correlated.

Examples include:

- Office launches PowerShell, followed by a PowerShell remote download.
- PowerShell downloads a file, followed by Registry or scheduled-task persistence.
- LSASS dumping is followed by NLTest discovery and remote service creation.
- OAuth consent is followed by mailbox forwarding changes.
- Certutil downloads a file that is later executed through a trusted Windows binary.
- Remote service creation is followed by process activity on a second endpoint.

A SOC analyst should correlate events by user, endpoint, process tree, timestamp, destination, file hash, remote domain, and authentication activity.

## Known Coverage Gaps

The library does not provide complete coverage of every possible attack technique.

Current gaps include:

- Exploitation of public-facing applications.
- Password spraying and brute-force authentication.
- Privilege-escalation exploits.
- Direct command-and-control beacon detection.
- Data staging and archive creation.
- Network-based exfiltration.
- Linux and macOS endpoint behaviour.
- Container and operational-technology environments.
- Memory-only execution that does not create observable command-line events.

These limitations are intentional. The project focuses on 15 explainable, testable, and documented detections relevant to Microsoft-centric Irish and European enterprise environments.

## Analyst Use

The rules should not be deployed to production without tuning.

Before deployment, an organisation should:

1. Confirm that the required log sources are collected.
2. Map generic Sigma fields to the target SIEM schema.
3. Test the converted queries against representative data.
4. Establish baselines for legitimate administrative activity.
5. Define narrow environment-specific exceptions.
6. Correlate related alerts across endpoint, identity, email, and network telemetry.
7. Document response procedures and escalation thresholds.
8. Review detection performance and false positives continuously.

## Conclusion

The 15-rule library demonstrates an end-to-end detection-engineering approach rather than a collection of unrelated signatures.

The rules collectively cover initial execution, payload transfer, trusted binary abuse, persistence, cloud access, credential theft, discovery, remote execution, mailbox collection, and concealment.

This coverage provides a practical foundation for SOC monitoring while clearly documenting required telemetry, investigation context, false positives, MITRE ATT&CK mappings, and known limitations.