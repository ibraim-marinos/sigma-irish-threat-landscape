# Irish and European Cyber Threat Landscape

## Purpose

This document explains the threat context behind the Sigma Rule Library - Irish Threat Landscape.

The library contains 15 behavioural detection rules focused on Microsoft 365, Microsoft Entra ID, Windows endpoints, Active Directory, business email compromise, malicious script execution, persistence, credential access, reconnaissance, and lateral movement.

The objective is not to claim that every included technique is unique to Ireland. The objective is to prioritise behaviours that are relevant to Irish and European organisations operating Microsoft-centric enterprise environments.

## Scope and Methodology

The threat landscape was reviewed using publicly available guidance and reporting from:

- Ireland's National Cyber Security Centre.
- The European Union Agency for Cybersecurity.
- Europol.
- Microsoft security documentation.
- MITRE ATT&CK.

The project converts strategic threat information into practical detection hypotheses.

The resulting rules focus on observable attacker behaviour instead of fixed indicators such as individual IP addresses, domains, or file hashes.

This approach makes the detections more reusable across organisations and more resilient when threat actors change infrastructure.

## Irish Organisational Context

Irish organisations operate within a highly connected European digital economy and rely extensively on cloud services, email, remote administration, identity platforms, and Windows endpoints.

Microsoft 365 and Microsoft Entra ID are important detection areas because compromise of an identity or mailbox may expose:

- Business communications.
- Financial information.
- Customer and employee data.
- Cloud applications.
- Shared files.
- Internal contacts.
- Authentication tokens.
- Administrative permissions.

Ireland's National Cyber Security Centre publishes Microsoft 365 configuration guidance that includes protection against phishing, spoofing, and impersonation.

The NCSC also advises Irish small businesses to implement practical security measures such as multifactor authentication, software updates, backups, strong passwords, and protection of important business information.

This project complements preventive controls by demonstrating how suspicious behaviour could be detected and investigated after an attacker gains access.

## European Threat Context

The ENISA Threat Landscape 2025 analysed thousands of cybersecurity incidents affecting the European threat environment between July 2024 and June 2025.

The report highlights a diverse threat ecosystem involving cybercriminals, state-aligned actors, hacktivists, initial-access activity, exploitation, social engineering, malware, ransomware, data compromise, and disruption.

ENISA reporting continues to identify phishing and social engineering as important methods for obtaining access or delivering malicious content.

Europol reporting also describes stolen data and access as important commodities within the cybercrime economy. Compromised credentials, personal information, business data, and access to organisational systems may be traded or exploited for fraud and additional attacks.

These trends support detection coverage across identity, email, endpoint execution, credential theft, discovery, and lateral movement.

## Priority Threat Areas

### Business Email Compromise

Business email compromise may begin with phishing, stolen credentials, token theft, or compromised sessions.

After accessing a mailbox, an attacker may create rules that:

- Forward messages to another recipient.
- Redirect messages.
- Preserve local delivery to avoid alerting the victim.
- Mark messages as read.
- Move messages into another folder.
- Delete messages that could expose the compromise.

BEC can support invoice fraud, payment diversion, impersonation, intelligence gathering, and continued monitoring of business communications.

Relevant rules:

- M365 Inbox Forwarding with Message Hiding.
- M365 Mailbox SMTP Forwarding with Local Delivery.

MITRE ATT&CK coverage:

- T1114.003 — Email Forwarding Rule.
- T1564.008 — Email Hiding Rules.

### Microsoft 365 and OAuth Abuse

OAuth abuse can provide access without requiring the attacker to repeatedly submit the victim's password.

A malicious or compromised application may request permissions capable of:

- Reading email.
- Modifying email.
- Sending email.
- Maintaining delegated access.
- Accessing organisational files.
- Reading or modifying directory information.

Service principals with broad application permissions may provide persistent, non-interactive access to cloud resources.

Relevant rules:

- M365 OAuth Consent with High-Risk Permissions.
- M365 Service Principal High-Risk Application Permissions.

MITRE ATT&CK coverage:

- T1671 — Cloud Application Integration.
- T1550.001 — Application Access Token.
- T1098.003 — Additional Cloud Roles.

### Phishing-Delivered Malware

A malicious document or attachment may cause an Office application to launch PowerShell.

PowerShell can then retrieve another script or payload from a remote server.

This creates a practical detection sequence:

1. Office application starts PowerShell.
2. PowerShell contacts a remote URL.
3. Additional content is downloaded.
4. The content is executed or stored in a user-writable directory.
5. Persistence or lateral movement follows.

Relevant rules:

- Office Application Spawning PowerShell.
- PowerShell Remote Payload Download.

MITRE ATT&CK coverage:

- T1204.002 — Malicious File.
- T1059.001 — PowerShell.
- T1105 — Ingress Tool Transfer.

### Living-off-the-Land Binary Abuse

Attackers may abuse trusted Microsoft-signed binaries to execute scripts, retrieve content, or bypass basic application restrictions.

This technique is important because the binaries may already be present and trusted within the environment.

The project detects suspicious use of:

- `mshta.exe`
- `regsvr32.exe`
- `rundll32.exe`
- `certutil.exe`

Relevant rules:

- MSHTA Remote URL Execution.
- Regsvr32 Remote Scriptlet Execution.
- Rundll32 Suspicious Script Execution.
- Certutil Remote File Download.

MITRE ATT&CK coverage:

- T1218.005 — MSHTA.
- T1218.010 — Regsvr32.
- T1218.011 — Rundll32.
- T1105 — Ingress Tool Transfer.

### Persistence

After gaining access, an attacker may configure malware to restart automatically.

Registry Run and RunOnce keys can execute content when a user signs in. Scheduled tasks can execute content at logon, startup, a selected time, or a recurring interval.

User-writable locations are important investigation indicators because they can often be modified without deploying files into protected system directories.

Relevant rules:

- Registry Run Key Persistence from Suspicious Path.
- Scheduled Task Creation from User-Writable Path.

MITRE ATT&CK coverage:

- T1547.001 — Registry Run Keys / Startup Folder.
- T1053.005 — Scheduled Task.

### Credential Access

Windows LSASS memory may contain authentication material associated with logged-on users.

An attacker with sufficient privileges may attempt to create an LSASS memory dump and analyse it to recover credential material or reusable hashes.

The project detects a specific method involving Rundll32, `comsvcs.dll`, and the `MiniDump` function.

Relevant rule:

- Rundll32 Comsvcs LSASS Memory Dump.

MITRE ATT&CK coverage:

- T1003.001 — LSASS Memory.

### Active Directory Reconnaissance

After compromising an endpoint or identity, an attacker may investigate the Active Directory environment before expanding access.

Domain trust discovery can reveal relationships between domains and possible paths towards additional systems or accounts.

Relevant rule:

- NLTest Domain Trust Discovery.

MITRE ATT&CK coverage:

- T1482 — Domain Trust Discovery.

### Lateral Movement and Remote Execution

Compromised credentials may be used to create and start a service on another Windows system.

Remote service creation can provide execution on a second endpoint and help an attacker expand through the environment.

Relevant rule:

- SC.exe Remote Service Creation.

MITRE ATT&CK coverage:

- T1569.002 — Service Execution.

## Relevance to Ransomware and Commodity Malware

The rule library does not attempt to identify a malware family using fixed indicators.

Instead, it detects behaviours that may appear in ransomware, loaders, information stealers, remote-access tools, and other malware operations.

Examples include:

- Phishing-related execution.
- PowerShell payload retrieval.
- Trusted binary abuse.
- Registry persistence.
- Scheduled-task persistence.
- Credential dumping.
- Domain discovery.
- Remote service creation.

This behavioural approach is useful because malware families, including historically prominent threats such as Emotet and Qakbot, may change infrastructure, filenames, hashes, delivery mechanisms, and campaign details.

A rule that depends only on a known hash may become obsolete quickly. A behavioural rule can remain useful when the attacker preserves the same operational technique.

The project does not claim that a single alert proves the presence of a specific malware family.

## End-to-End Detection Narrative

The library supports the following representative investigation sequence:

| Stage | Observable Behaviour | Detection Coverage |
|---|---|---|
| Initial execution | Office application launches PowerShell | Office Application Spawning PowerShell |
| Payload transfer | PowerShell or Certutil retrieves remote content | PowerShell Remote Payload Download; Certutil Remote File Download |
| Execution | Trusted Windows binary executes remote or script content | MSHTA, Regsvr32, and Rundll32 rules |
| Persistence | Run key or scheduled task references a suspicious path | Registry and Scheduled Task rules |
| Cloud persistence | Application consent or service-principal permissions are granted | OAuth abuse rules |
| Credential access | LSASS memory is dumped through Comsvcs | Rundll32 Comsvcs LSASS Memory Dump |
| Discovery | Domain trusts are enumerated | NLTest Domain Trust Discovery |
| Remote execution | Service is created on another endpoint | SC.exe Remote Service Creation |
| Collection | Mailbox messages are forwarded | Microsoft 365 forwarding rules |
| Concealment | Mailbox rules hide relevant messages | Message Hiding rule |

The complete multi-stage analysis is available in `docs/attack_chain_coverage.md`.

## Detection Engineering Principles

The project applies the following principles:

### Behaviour over Static Indicators

Rules identify combinations of processes, operations, parameters, command-line content, or permissions.

### Multiple Conditions

Detections require several related indicators rather than alerting on a single common executable or keyword.

### Investigation Context

Each rule identifies useful fields and provides investigation questions.

### False-Positive Awareness

Administrative and business activity may resemble malicious behaviour. Each rule documents plausible legitimate explanations.

### MITRE ATT&CK Mapping

Every rule maps to one or more MITRE ATT&CK techniques.

### Portable Detection Logic

Sigma provides generic detection logic that can be converted for compatible SIEM platforms.

### Environment-Specific Tuning

Rules require field mapping, baselining, testing, and narrow exceptions before production deployment.

## Operational Considerations

A production deployment should verify that the required telemetry is available.

Important sources include:

- Microsoft 365 Unified Audit Log.
- Microsoft Entra ID audit logs.
- Windows process-creation events.
- Sysmon process, file, Registry, and network events.
- Windows Security events.
- PowerShell Script Block Logging.
- Endpoint detection and response telemetry.
- DNS, proxy, firewall, and network-security logs.

Organisations should correlate alerts using:

- User identity.
- Endpoint.
- Process tree.
- Timestamp.
- Remote destination.
- File path.
- File hash.
- Authentication activity.
- Cloud application.
- Mailbox.
- Administrative approval records.

## Limitations

This document provides a detection-engineering context, not a complete quantitative assessment of cyber incidents in Ireland.

The project does not claim:

- That every included technique is uniquely prevalent in Ireland.
- That one Sigma alert confirms malicious activity.
- That the rules cover every attack technique.
- That generic Sigma fields automatically match every SIEM schema.
- That validation with Sigma CLI replaces testing against production telemetry.
- That behavioural similarity proves attribution to a named threat actor or malware family.

The threat landscape and attacker techniques continue to evolve. References and mappings should be reviewed periodically.

## Conclusion

Irish and European organisations face a broad threat environment involving phishing, compromised identities, cloud abuse, malware, credential theft, ransomware, data compromise, and lateral movement.

The 15-rule library translates this threat context into documented and validated detection hypotheses for Microsoft-centric environments.

The project demonstrates how strategic threat information can be converted into practical SOC detections while maintaining clear MITRE ATT&CK mapping, investigation guidance, false-positive awareness, and deployment limitations.

## References

- Ireland NCSC Guidance: https://www.ncsc.gov.ie/guidance/
- Ireland NCSC Office 365 Secure Configuration Framework: https://www.ncsc.gov.ie/pdfs/NCSC_Office_365_Secure_Configuration_Framework.pdf
- Ireland NCSC Cyber Security for Small Business: https://www.ncsc.gov.ie/pdfs/NCSC-SME-Guidance-0225.pdf
- ENISA Threat Landscape 2025: https://www.enisa.europa.eu/topics/cyber-threats/threat-landscape
- ENISA Threat Landscape 2025 Report: https://www.enisa.europa.eu/sites/default/files/2026-01/ENISA%20Threat%20Landscape%202025_v1.2.pdf
- Europol Internet Organised Crime Threat Assessment: https://www.europol.europa.eu/publications-events/main-reports/iocta-report
- Europol IOCTA 2025: https://www.europol.europa.eu/cms/sites/default/files/documents/Steal-deal-repeat-IOCTA_2025.pdf
- MITRE ATT&CK: https://attack.mitre.org/
- Microsoft Sysmon: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon