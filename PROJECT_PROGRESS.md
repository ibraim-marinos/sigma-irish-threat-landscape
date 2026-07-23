# Project Progress - Sigma Rule Library

This document tracks the development of the Sigma Rule Library - Irish Threat Landscape from initial setup to the v1.0 release.

## Project Summary

- **Target:** 15 original Sigma detection rules
- **Rules completed:** 2 of 15
- **Development period:** 10 days
- **Current version:** Pre-release
- **Current phase:** Day 2 BEC and phishing detections completed

## Development Roadmap

| Day | Focus | Status |
|---|---|---|
| Day 1 | Repository setup, documentation, and Sigma fundamentals | Completed |
| Day 2 | BEC and phishing detection rules | Completed |
| Day 3 | Microsoft 365 and OAuth abuse detection rules | Not Started |
| Day 4 | LOLBins detection rules | Not Started |
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

## Rule Development Progress

| Rule | Category | Status | MITRE ATT&CK |
|---|---|---|---|
| M365 Inbox Forwarding with Message Hiding | BEC / Phishing | Experimental - Validated | T1114.003, T1564.008 |
| M365 Mailbox SMTP Forwarding with Local Delivery | BEC / Phishing | Experimental - Validated | T1114.003 |
| Rules 03-15 | To be developed | Not Started | To be mapped |

## Validation Summary

| Date | Scope | Tool | Result |
|---|---|---|---|
| 23 July 2026 | Two BEC and phishing rules | Sigma CLI 3.1.0 | 0 errors, 0 condition errors, 0 issues |

## Version History

| Version | Date | Description |
|---|---|---|
| Pre-release - Day 1 | 23 July 2026 | Repository foundation and initial documentation |
| Pre-release - Day 2 | 23 July 2026 | Two validated BEC and phishing detection rules |