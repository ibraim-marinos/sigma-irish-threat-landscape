# Sigma Rule Library - Irish Threat Landscape

A portfolio-focused library of original Sigma detection rules addressing security threats relevant to Irish and European organisations.

## Project Status

> All 15 planned Sigma detection rules have been completed and validated. Documentation review, testing, and v1.0 release preparation remain in progress.

## Overview

This project demonstrates practical detection engineering skills through the development, documentation, and validation of Sigma rules for common enterprise attack scenarios.

The library focuses on threats and techniques affecting Microsoft-centric environments, including business email compromise, Microsoft 365 abuse, malicious OAuth activity, living-off-the-land binaries, malware execution, credential access, persistence, reconnaissance, and lateral movement.

The project uses threat-informed detection hypotheses, Windows and Microsoft 365 telemetry, MITRE ATT&CK mapping, documented investigation guidance, and repeatable Sigma CLI validation.

## Project Objectives

- Develop 15 original Sigma detection rules.
- Follow the official Sigma rule structure and naming conventions.
- Map every detection to MITRE ATT&CK.
- Document detection logic, false positives, investigation guidance, tuning recommendations, and limitations.
- Validate every rule using Sigma CLI.
- Demonstrate coverage across multiple connected stages of an attack chain.
- Provide platform-independent detections that can be converted for compatible SIEM platforms.
- Address attack behaviours relevant to Irish and European organisations.

## Detection Categories

| Category | Detection Focus |
|---|---|
| BEC and phishing | Suspicious mailbox activity associated with business email compromise |
| Microsoft 365 abuse | Malicious or unusual activity within Microsoft 365 environments |
| OAuth abuse | Suspicious application consent and service-principal permission activity |
| LOLBins | Abuse of trusted Windows binaries for malicious execution and file transfer |
| Malware | Phishing-delivered execution and remote payload retrieval |
| Persistence | Techniques used to maintain access to compromised systems |
| Credential access | Attempts to obtain reusable authentication material |
| Reconnaissance | Host, account, domain, and network discovery activity |
| Lateral movement | Remote execution techniques used to expand access |

## Detection Rules

| # | Detection Rule | Category | MITRE ATT&CK | Status | Validation |
|---|---|---|---|---|---|
| 1 | [M365 Inbox Forwarding with Message Hiding](rules/bec_phishing/m365_inbox_forwarding_with_message_hiding.yml) | BEC / Phishing | T1114.003, T1564.008 | Experimental | Passed |
| 2 | [M365 Mailbox SMTP Forwarding with Local Delivery](rules/bec_phishing/m365_mailbox_smtp_forwarding_with_local_delivery.yml) | BEC / Phishing | T1114.003 | Experimental | Passed |
| 3 | [M365 OAuth Consent with High-Risk Permissions](rules/oauth_abuse/m365_oauth_consent_high_risk_permissions.yml) | OAuth Abuse | T1671, T1550.001 | Experimental | Passed |
| 4 | [M365 Service Principal High-Risk Application Permissions](rules/oauth_abuse/m365_service_principal_high_risk_app_permissions.yml) | OAuth Abuse | T1671, T1098.003 | Experimental | Passed |
| 5 | [MSHTA Remote URL Execution](rules/lolbins/mshta_remote_url_execution.yml) | LOLBins | T1218.005 | Experimental | Passed |
| 6 | [Regsvr32 Remote Scriptlet Execution](rules/lolbins/regsvr32_remote_scriptlet_execution.yml) | LOLBins | T1218.010 | Experimental | Passed |
| 7 | [Rundll32 Suspicious Script Execution](rules/lolbins/rundll32_suspicious_script_execution.yml) | LOLBins | T1218.011 | Experimental | Passed |
| 8 | [Certutil Remote File Download](rules/lolbins/certutil_remote_file_download.yml) | LOLBins | T1105 | Experimental | Passed |
| 9 | [Registry Run Key Persistence from Suspicious Path](rules/persistence/registry_run_key_suspicious_path.yml) | Persistence | T1547.001 | Experimental | Passed |
| 10 | [Scheduled Task Creation from User-Writable Path](rules/persistence/schtasks_suspicious_task_from_user_writable_path.yml) | Persistence | T1053.005 | Experimental | Passed |
| 11 | [Office Application Spawning PowerShell](rules/malware/office_application_spawns_powershell.yml) | Malware / Phishing | T1204.002, T1059.001 | Experimental | Passed |
| 12 | [NLTest Domain Trust Discovery](rules/reconnaissance/nltest_domain_trust_discovery.yml) | Reconnaissance | T1482 | Experimental | Passed |
| 13 | [SC.exe Remote Service Creation](rules/lateral_movement/sc_remote_service_creation.yml) | Lateral Movement | T1569.002 | Experimental | Passed |
| 14 | [Rundll32 Comsvcs LSASS Memory Dump](rules/credential_access/rundll32_comsvcs_lsass_memory_dump.yml) | Credential Access | T1003.001 | Experimental | Passed |
| 15 | [PowerShell Remote Payload Download](rules/malware/powershell_remote_payload_download.yml) | Malware Delivery | T1059.001, T1105 | Experimental | Passed |

## Project Documentation

Start with these project-level guides:

- [Irish and European Threat Landscape](docs/threat_landscape_ireland.md)
- [Sigma Usage and Validation Guide](docs/sigma_usage.md)
- [End-to-End Attack-Chain Coverage](docs/attack_chain_coverage.md)
- [Sigma Rule Structure Guide](docs/sigma_rule_structure.md)

Detailed rule logic, false-positive analysis, investigation guidance, tuning recommendations, validation results, and limitations are available in:

- [BEC and phishing documentation](docs/rules/bec_phishing/)
- [OAuth abuse documentation](docs/rules/oauth_abuse/)
- [LOLBins documentation](docs/rules/lolbins/)
- [Malware documentation](docs/rules/malware/)
- [Persistence documentation](docs/rules/persistence/)
- [Credential-access documentation](docs/rules/credential_access/)
- [Reconnaissance documentation](docs/rules/reconnaissance/)
- [Lateral-movement documentation](docs/rules/lateral_movement/)

## Attack Chain Coverage

The 15 rules collectively provide behavioural coverage across the following operational stages:

| Stage | Example Coverage |
|---|---|
| Initial execution | Office application spawning PowerShell |
| Payload delivery | PowerShell or Certutil retrieving remote content |
| Signed binary abuse | MSHTA, Regsvr32, and Rundll32 execution |
| Local persistence | Registry Run keys and scheduled tasks |
| Cloud persistence | OAuth consent and service-principal permissions |
| Credential access | LSASS memory dumping through Rundll32 and Comsvcs |
| Discovery | Active Directory domain-trust enumeration |
| Remote execution | Remote Windows service creation |
| Email collection | Microsoft 365 mailbox forwarding |
| Concealment | Inbox rule actions that hide forwarded messages |

See the complete [end-to-end attack-chain coverage review](docs/attack_chain_coverage.md) for the multi-stage attack narrative, correlation opportunities, strengths, and known coverage gaps.

## Repository Structure

```text
sigma-irish-threat-landscape/
|-- rules/
|   |-- bec_phishing/
|   |-- credential_access/
|   |-- lateral_movement/
|   |-- lolbins/
|   |-- m365_abuse/
|   |-- malware/
|   |-- oauth_abuse/
|   |-- persistence/
|   `-- reconnaissance/
|-- docs/
|   |-- rules/
|   |-- attack_chain_coverage.md
|   `-- sigma_rule_structure.md
|-- screenshots/
|   |-- day1/
|   |-- day2/
|   |-- day3/
|   |-- day4/
|   |-- day5/
|   |-- day6/
|   `-- day7/
|-- tests/
|-- README.md
|-- PROJECT_PROGRESS.md
|-- LICENSE
`-- .gitignore
```

## Validation

All 15 rules have been validated individually and together using Sigma CLI 3.1.0.

Complete-library validation command:

```powershell
sigma check rules
```

Complete-library validation result:

```text
Found 0 errors, 0 condition errors and 0 issues.
No rule errors found.
No condition errors found.
No validation issues found.
```

Validation confirms valid Sigma syntax, detection-condition structure, MITRE ATT&CK tags, and supported quality checks.

Production deployments still require environment-specific field mapping, testing, baselining, tuning, and exception management.

## Skills Demonstrated

- Detection engineering
- Sigma rule development
- Security log analysis
- Windows process analysis
- Microsoft 365 and Microsoft Entra monitoring
- Active Directory discovery detection
- Credential-access detection
- Lateral-movement detection
- Living-off-the-land binary analysis
- MITRE ATT&CK mapping
- Threat-informed detection development
- False-positive analysis
- Investigation planning
- Attack-chain correlation
- Rule testing and validation
- Technical documentation
- Git and GitHub version control

## Disclaimer

These rules are developed for educational, portfolio, and defensive security purposes.

They should be tested and tuned for the specific log sources, field mappings, SIEM platform, and operational environment before production deployment.

## Author

**Ibraim Arturo Marinos Lian**

Cybersecurity professional focused on SOC operations, threat detection, incident investigation, and security automation.

## License

This project is licensed under the MIT License.