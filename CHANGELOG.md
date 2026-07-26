# Changelog

All notable changes to the Sigma Rule Library - Irish Threat Landscape are documented in this file.

The project follows the principles of [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and uses [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-07-27

### Added

- Completed a library of 15 original Sigma detection rules.
- Added two Business Email Compromise and Exchange Online forwarding detections.
- Added two Microsoft Entra and OAuth application-permission abuse detections.
- Added four Windows LOLBin detections covering MSHTA, Regsvr32, Rundll32, and Certutil activity.
- Added two Windows persistence detections covering Registry Run keys and scheduled tasks.
- Added phishing-led Office-to-PowerShell execution detection.
- Added PowerShell remote-payload download detection.
- Added Active Directory domain-trust discovery detection.
- Added remote Windows service creation detection.
- Added Rundll32 and Comsvcs LSASS memory-dump detection.
- Added MITRE ATT&CK mappings, severity levels, false positives, and investigation fields to every rule.
- Added detailed analyst documentation for all 15 detections.
- Added an Irish and European threat-landscape analysis.
- Added an end-to-end attack-chain coverage review.
- Added a Sigma rule-structure guide.
- Added a Sigma CLI installation, validation, and conversion guide.
- Added professional validation screenshots for individual rules and the complete library.
- Added `tests/validate_repository.py` for repeatable repository-quality checks.
- Added GitHub Actions continuous validation for pushes and pull requests.
- Added validation, rule-count, and MIT licence badges to the README.
- Added project progress tracking across the complete ten-day development roadmap.

### Validation

- Validated all 15 rules individually and as a complete library with Sigma CLI 3.1.0.
- Confirmed 0 rule errors, 0 condition errors, and 0 validation issues.
- Confirmed exactly 15 Sigma YAML rules.
- Confirmed that all UUIDs and rule titles are unique.
- Confirmed required metadata and MITRE ATT&CK tags across the complete library.
- Confirmed corresponding analyst documentation for every rule.
- Confirmed that all internal Markdown links resolve correctly.
- Confirmed that the README links to all 15 rules.
- Confirmed that repository formatting and encoding checks pass.
- Confirmed GitHub Actions continuous validation completes successfully.

### Coverage

Version 1.0.0 provides behavioural detection coverage across:

- Business Email Compromise.
- Microsoft 365 and Exchange Online abuse.
- Microsoft Entra and OAuth abuse.
- Phishing-delivered malware execution.
- PowerShell execution and remote payload transfer.
- Windows LOLBin abuse.
- Windows persistence.
- Credential access.
- Active Directory reconnaissance.
- Remote service execution and lateral movement.
- Email collection and continued cloud-account access.

### Deployment Notice

The rules are platform-independent detection content and require environment-specific testing before production deployment.

Organisations should confirm:

- Required telemetry is collected.
- Sigma fields map correctly to the target SIEM.
- Processing pipelines and backends are appropriate.
- Administrative baselines and false positives are understood.
- Alert severity and investigation workflows match operational requirements.
- Detection performance is monitored and tuned over time.

## Development History

- Day 1: Repository foundation and Sigma fundamentals.
- Day 2: BEC and phishing detections.
- Day 3: Microsoft 365 and OAuth abuse detections.
- Day 4: Windows LOLBin detections.
- Day 5: Certutil and Windows persistence detections.
- Day 6: European threat, reconnaissance, and lateral-movement detections.
- Day 7: Library completion and attack-chain coverage review.
- Day 8: Professional threat-landscape and Sigma usage documentation.
- Day 9: Automated testing, continuous validation, and repository polish.
- Day 10: Final review and v1.0.0 release.