# Project Progress - Sigma Rule Library

This document tracks the development of the Sigma Rule Library - Irish Threat Landscape from initial setup to the v1.0 release.

## Project Summary

- **Target:** 15 original Sigma detection rules
- **Rules completed:** 7 of 15
- **Development period:** 10 days
- **Current version:** Pre-release
- **Current phase:** Day 4 LOLBins detections completed

## Development Roadmap

| Day | Focus | Status |
|---|---|---|
| Day 1 | Repository setup, documentation, and Sigma fundamentals | Completed |
| Day 2 | BEC and phishing detection rules | Completed |
| Day 3 | Microsoft 365 and OAuth abuse detection rules | Completed |
| Day 4 | LOLBins detection rules | Completed |
| Day 5 | LOLBins and persistence detection rules | Not Started |
| Day 6 | Irish/European threats, reconnaissance, and lateral movement | Not Started |
| Day 7 | Complete 15 rules and perform attack-chain coverage review | Not Started |
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

## Rule Development Progress

| Rule | Category | Status | MITRE ATT&CK |
|---|---|---|---|
| M365 Inbox Forwarding with Message Hiding | BEC / Phishing | Experimental - Validated | T1114.003, T1564.008 |
| M365 Mailbox SMTP Forwarding with Local Delivery | BEC / Phishing | Experimental - Validated | T1114.003 |
| M365 OAuth Consent with High-Risk Permissions | OAuth Abuse | Experimental - Validated | T1671, T1550.001 |
| M365 Service Principal High-Risk Application Permissions | OAuth Abuse | Experimental - Validated | T1671, T1098.003 |
| MSHTA Remote URL Execution | LOLBins | Experimental - Validated | T1218.005 |
| Regsvr32 Remote Scriptlet Execution | LOLBins | Experimental - Validated | T1218.010 |
| Rundll32 Suspicious Script Execution | LOLBins | Experimental - Validated | T1218.011 |
| Rules 08-15 | To be developed | Not Started | To be mapped |

## Validation Summary

| Date | Scope | Tool | Result |
|---|---|---|---|
| 23 July 2026 | Two BEC and phishing rules | Sigma CLI 3.1.0 | 0 errors, 0 condition errors, 0 issues |
| 24 July 2026 | Complete four-rule library | Sigma CLI 3.1.0 | 0 errors, 0 condition errors, 0 issues |
| 24 July 2026 | Complete seven-rule library | Sigma CLI 3.1.0 | 0 errors, 0 condition errors, 0 issues |

## Version History

| Version | Date | Description |
|---|---|---|
| Pre-release - Day 1 | 23 July 2026 | Repository foundation and initial documentation |
| Pre-release - Day 2 | 23 July 2026 | Two validated BEC and phishing detection rules |
| Pre-release - Day 3 | 24 July 2026 | Two validated OAuth abuse detection rules and four-rule library validation |
| Pre-release - Day 4 | 24 July 2026 | Three validated LOLBins detection rules and seven-rule library validation |