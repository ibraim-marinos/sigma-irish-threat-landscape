# Sigma Rule Library – Irish Threat Landscape

A portfolio-focused library of original Sigma detection rules addressing security threats relevant to Irish and European organisations.

## Project Status

> Currently under active development. 10 of 15 planned Sigma detection rules have been completed and validated.

## Overview

This project demonstrates practical detection engineering skills through the development, documentation, and validation of Sigma rules for common enterprise attack scenarios.

The library focuses on threats and techniques affecting Microsoft-centric environments, including business email compromise, Microsoft 365 abuse, malicious OAuth activity, living-off-the-land binaries, persistence, reconnaissance, lateral movement, and malware behaviour.

## Project Objectives

- Develop 15 original Sigma detection rules.
- Follow the official Sigma rule structure and naming conventions.
- Map detections to MITRE ATT&CK techniques.
- Document detection logic, false positives, and investigation guidance.
- Validate rules using Sigma tooling.
- Demonstrate coverage across multiple stages of an attack chain.
- Provide platform-independent detections that can be converted for different SIEM platforms.

## Planned Detection Categories

| Category | Detection Focus |
|---|---|
| BEC and phishing | Suspicious email and account activity associated with business email compromise |
| Microsoft 365 abuse | Malicious or unusual activity within Microsoft 365 environments |
| OAuth abuse | Suspicious application consent and permission activity |
| LOLBins | Abuse of trusted Windows binaries for malicious execution |
| Persistence | Techniques used to maintain access to compromised systems |
| Reconnaissance | Host, account, and network discovery activity |
| Lateral movement | Techniques used to move between systems and accounts |
| Malware | Behaviour associated with threats such as Emotet and Qakbot |

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

Detailed detection logic, false-positive analysis, investigation guidance, tuning recommendations, and validation results are available in the [BEC and phishing documentation](docs/rules/bec_phishing/), [OAuth abuse documentation](docs/rules/oauth_abuse/), [LOLBins documentation](docs/rules/lolbins/), and [persistence documentation](docs/rules/persistence/).

## Repository Structure

```text
sigma-irish-threat-landscape/
├── rules/
├── docs/
├── screenshots/
├── tests/
├── README.md
├── PROJECT_PROGRESS.md
├── LICENSE
└── .gitignore
```

## Skills Demonstrated

- Detection engineering
- Sigma rule development
- Security log analysis
- MITRE ATT&CK mapping
- Threat-informed detection
- Rule testing and validation
- Technical documentation
- Git and GitHub version control

## Disclaimer

These rules are developed for educational, portfolio, and defensive security purposes. They should be tested and tuned for the specific log sources and environment before production deployment.

## Author

**Ibraim Arturo Marinos Lian**

Cybersecurity professional focused on SOC operations, threat detection, incident investigation, and security automation.

## License

This project is licensed under the MIT License.