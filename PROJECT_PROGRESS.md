# Project Progress - Sigma Rule Library

This document tracks the development of the Sigma Rule Library - Irish Threat Landscape from initial setup to the v1.0 release.

## Project Summary

- **Target:** 15 original Sigma detection rules
- **Rules completed:** 15 of 15
- **Development period:** 10 days
- **Current version:** Pre-release
- **Current phase:** Day 7 rule development and attack-chain coverage review completed

## Development Roadmap

| Day | Focus | Status |
|---|---|---|
| Day 1 | Repository setup, documentation, and Sigma fundamentals | Completed |
| Day 2 | BEC and phishing detection rules | Completed |
| Day 3 | Microsoft 365 and OAuth abuse detection rules | Completed |
| Day 4 | LOLBins detection rules | Completed |
| Day 5 | LOLBins and persistence detection rules | Completed |
| Day 6 | Irish/European threats, reconnaissance, and lateral movement | Completed |
| Day 7 | Complete 15 rules and perform attack-chain coverage review | Completed |
| Day 8 | Complete professional documentation | Not Started |
| Day 9 | Validate rules, capture screenshots, and polish repository | Not Started |
| Day 10 | Final review, v1.0 release, LinkedIn, CV, and interview preparation | Not Started |

## Day 1 - Repository Foundation

**Date:** 23 July 2026
**Status:** Completed

### Completed

- Created the public GitHub repository.
- Cloned the repository locally using Git.
- Configured VS Code Workspace Trust.
- Created the professional folder structure.
- Added rule categories for BEC, Microsoft 365, OAuth, LOLBins, persistence, reconnaissance, lateral movement, and malware.
- Added `.gitkeep` files to preserve empty directories.
- Configured `.gitignore`.
- Added the MIT License.
- Created the initial project README.
- Reviewed the official Sigma rule structure and specification.
- Documented the project rule structure and quality standards.
- Reviewed all staged files for formatting issues.
- Prepared the repository foundation for the initial Git commit.

## Day 2 - BEC and Phishing Detections

**Date:** 23 July 2026
**Status:** Completed

### Completed

- Researched BEC-related mailbox forwarding behaviour.
- Identified the required Microsoft 365 Exchange audit telemetry.
- Installed Sigma CLI 3.1.0 in an isolated virtual environment.
- Created and documented the M365 Inbox Forwarding with Message Hiding rule.
- Mapped the first rule to MITRE ATT&CK T1114.003 and T1564.008.
- Created and documented the M365 Mailbox SMTP Forwarding with Local Delivery rule.
- Mapped the second rule to MITRE ATT&CK T1114.003.
- Documented false positives, investigation guidance, tuning recommendations, and limitations for both rules.
- Validated both rules individually and as a rule set.
- Confirmed 0 errors, 0 condition errors, and 0 validation issues.
- Captured validation evidence for both rules.
- Updated the project README with rule progress and links.

## Day 3 - Microsoft 365 and OAuth Abuse Detections

**Date:** 24 July 2026
**Status:** Completed

### Completed

- Researched Microsoft Entra application-consent and service-principal permission events.
- Identified Microsoft Entra audit logs as the required telemetry.
- Created and documented the M365 OAuth Consent with High-Risk Permissions rule.
- Mapped the third rule to MITRE ATT&CK T1671 and T1550.001.
- Created and documented the M365 Service Principal High-Risk Application Permissions rule.
- Mapped the fourth rule to MITRE ATT&CK T1671 and T1098.003.
- Documented detection logic, false positives, investigation guidance, tuning recommendations, and limitations for both rules.
- Validated both rules individually and validated the complete four-rule library.
- Confirmed 0 errors, 0 condition errors, and 0 validation issues.
- Captured professional validation evidence for both rules.
- Updated the project README to show 4 of 15 completed rules.

## Day 4 - LOLBins Detections

**Date:** 24 July 2026
**Status:** Completed

### Completed

- Researched abuse of Microsoft-signed Windows binaries.
- Identified Windows process-creation telemetry as the required log source.
- Created and documented the MSHTA Remote URL Execution rule.
- Mapped the fifth rule to MITRE ATT&CK T1218.005.
- Created and documented the Regsvr32 Remote Scriptlet Execution rule.
- Mapped the sixth rule to MITRE ATT&CK T1218.010.
- Created and documented the Rundll32 Suspicious Script Execution rule.
- Mapped the seventh rule to MITRE ATT&CK T1218.011.
- Documented detection logic, false positives, investigation guidance, tuning recommendations, and limitations for all three rules.
- Validated each LOLBin rule individually and validated the complete seven-rule library.
- Confirmed 0 errors, 0 condition errors, and 0 validation issues.
- Captured professional validation evidence for all three rules.
- Updated the project README to show 7 of 15 completed rules.

## Day 5 - LOLBins and Persistence Detections

**Date:** 25 July 2026
**Status:** Completed

### Completed

- Researched Certutil abuse for remote file transfer.
- Created and documented the Certutil Remote File Download rule.
- Mapped the eighth rule to MITRE ATT&CK T1105.
- Researched Windows Registry Run and RunOnce persistence.
- Identified Registry value-set telemetry, including Sysmon Event ID 13.
- Created and documented the Registry Run Key Persistence from Suspicious Path rule.
- Mapped the ninth rule to MITRE ATT&CK T1547.001.
- Researched Windows scheduled-task persistence using `schtasks.exe`.
- Created and documented the Scheduled Task Creation from User-Writable Path rule.
- Mapped the tenth rule to MITRE ATT&CK T1053.005.
- Documented detection logic, false positives, investigation guidance, tuning recommendations, severity rationale, and limitations for all three rules.
- Validated each new rule individually.
- Validated the complete ten-rule library.
- Confirmed 0 errors, 0 condition errors, and 0 validation issues.
- Captured professional validation evidence for all three rules.
- Updated the project README to show 10 of 15 completed rules.
- Added links to the persistence documentation in the README.

## Day 6 - Irish and European Threat Detections

**Date:** 26 July 2026
**Status:** Completed

### Completed

- Researched phishing and malware execution patterns relevant to Irish and European organisations.
- Reviewed ENISA threat-landscape information supporting the importance of phishing-led initial access.
- Created and documented the Office Application Spawning PowerShell rule.
- Mapped the eleventh rule to MITRE ATT&CK T1204.002 and T1059.001.
- Researched Active Directory domain-trust discovery using `nltest.exe`.
- Created and documented the NLTest Domain Trust Discovery rule.
- Mapped the twelfth rule to MITRE ATT&CK T1482.
- Researched remote Windows service creation using `sc.exe`.
- Created and documented the SC.exe Remote Service Creation rule.
- Mapped the thirteenth rule to MITRE ATT&CK T1569.002.
- Documented detection logic, false positives, investigation guidance, tuning recommendations, severity rationale, and limitations for all three rules.
- Validated each new rule individually.
- Validated the complete thirteen-rule library.
- Confirmed 0 errors, 0 condition errors, and 0 validation issues.
- Captured professional validation evidence for all three rules.
- Updated the project README to show 13 of 15 completed rules.
- Added links to the malware, reconnaissance, and lateral-movement documentation.

## Day 7 - Library Completion and Attack-Chain Review

**Date:** 26 July 2026
**Status:** Completed

### Completed

- Identified credential access as a remaining attack-chain coverage gap.
- Created and documented the Rundll32 Comsvcs LSASS Memory Dump rule.
- Mapped the fourteenth rule to MITRE ATT&CK T1003.001.
- Identified remote payload delivery through PowerShell as a remaining coverage opportunity.
- Created and documented the PowerShell Remote Payload Download rule.
- Mapped the fifteenth rule to MITRE ATT&CK T1059.001 and T1105.
- Documented detection logic, false positives, investigation guidance, tuning recommendations, severity rationale, validation results, and limitations for both rules.
- Validated both new rules individually with Sigma CLI 3.1.0.
- Captured professional validation evidence for both rules.
- Confirmed that the repository contains exactly 15 Sigma YAML rules.
- Validated the complete fifteen-rule library.
- Confirmed 0 errors, 0 condition errors, and 0 validation issues.
- Reviewed titles, UUIDs, and severity levels across all 15 rules.
- Confirmed that all 15 UUIDs are unique.
- Reviewed MITRE ATT&CK mappings across the complete rule set.
- Created the end-to-end attack-chain coverage review.
- Documented correlation opportunities, coverage strengths, known gaps, and deployment considerations.
- Updated the project README to show 15 of 15 validated rules.
- Added the credential-access category and documentation links.
- Added a link to the attack-chain coverage review.

## Rule Development Progress

| # | Rule | Category | Status | MITRE ATT&CK |
|---|---|---|---|---|
| 1 | M365 Inbox Forwarding with Message Hiding | BEC / Phishing | Experimental - Validated | T1114.003, T1564.008 |
| 2 | M365 Mailbox SMTP Forwarding with Local Delivery | BEC / Phishing | Experimental - Validated | T1114.003 |
| 3 | M365 OAuth Consent with High-Risk Permissions | OAuth Abuse | Experimental - Validated | T1671, T1550.001 |
| 4 | M365 Service Principal High-Risk Application Permissions | OAuth Abuse | Experimental - Validated | T1671, T1098.003 |
| 5 | MSHTA Remote URL Execution | LOLBins | Experimental - Validated | T1218.005 |
| 6 | Regsvr32 Remote Scriptlet Execution | LOLBins | Experimental - Validated | T1218.010 |
| 7 | Rundll32 Suspicious Script Execution | LOLBins | Experimental - Validated | T1218.011 |
| 8 | Certutil Remote File Download | LOLBins | Experimental - Validated | T1105 |
| 9 | Registry Run Key Persistence from Suspicious Path | Persistence | Experimental - Validated | T1547.001 |
| 10 | Scheduled Task Creation from User-Writable Path | Persistence | Experimental - Validated | T1053.005 |
| 11 | Office Application Spawning PowerShell | Malware / Phishing | Experimental - Validated | T1204.002, T1059.001 |
| 12 | NLTest Domain Trust Discovery | Reconnaissance | Experimental - Validated | T1482 |
| 13 | SC.exe Remote Service Creation | Lateral Movement | Experimental - Validated | T1569.002 |
| 14 | Rundll32 Comsvcs LSASS Memory Dump | Credential Access | Experimental - Validated | T1003.001 |
| 15 | PowerShell Remote Payload Download | Malware Delivery | Experimental - Validated | T1059.001, T1105 |

## Validation Summary

| Date | Scope | Tool | Result |
|---|---|---|---|
| 23 July 2026 | Two BEC and phishing rules | Sigma CLI 3.1.0 | 0 errors, 0 condition errors, 0 issues |
| 24 July 2026 | Complete four-rule library | Sigma CLI 3.1.0 | 0 errors, 0 condition errors, 0 issues |
| 24 July 2026 | Complete seven-rule library | Sigma CLI 3.1.0 | 0 errors, 0 condition errors, 0 issues |
| 25 July 2026 | Complete ten-rule library | Sigma CLI 3.1.0 | 0 errors, 0 condition errors, 0 issues |
| 26 July 2026 | Complete thirteen-rule library | Sigma CLI 3.1.0 | 0 errors, 0 condition errors, 0 issues |
| 26 July 2026 | Complete fifteen-rule library | Sigma CLI 3.1.0 | 0 errors, 0 condition errors, 0 issues |

## Version History

| Version | Date | Description |
|---|---|---|
| Pre-release - Day 1 | 23 July 2026 | Repository foundation and initial documentation |
| Pre-release - Day 2 | 23 July 2026 | Two validated BEC and phishing detection rules |
| Pre-release - Day 3 | 24 July 2026 | Two validated OAuth abuse detection rules and four-rule library validation |
| Pre-release - Day 4 | 24 July 2026 | Three validated LOLBins detection rules and seven-rule library validation |
| Pre-release - Day 5 | 25 July 2026 | Three validated LOLBins and persistence rules and ten-rule library validation |
| Pre-release - Day 6 | 26 July 2026 | Three validated European threat, reconnaissance, and lateral-movement rules and thirteen-rule library validation |
| Pre-release - Day 7 | 26 July 2026 | Completed fifteen-rule library and end-to-end attack-chain coverage review |