# Sigma Rule Library – Irish Threat Landscape

A portfolio-focused library of original Sigma detection rules addressing security threats relevant to Irish and European organisations.

## Project Status

> Currently under active development. The initial v1.0 release will contain 15 validated Sigma detection rules.

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