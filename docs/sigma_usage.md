# Sigma Usage and Validation Guide

## Purpose

This guide explains how to prepare the local environment, validate the rules in this repository, and convert Sigma rules into SIEM-specific queries.

The instructions use Windows PowerShell, Python, and Sigma CLI. They are intended to make the validation process reproducible for recruiters, detection engineers, SOC analysts, and other repository users.

## What Is Sigma?

Sigma is an open and platform-independent detection format for describing suspicious activity in log data.

A Sigma rule defines:

- The required log source.
- The event fields and values to detect.
- The Boolean condition that triggers the detection.
- Relevant MITRE ATT&CK techniques.
- Expected false positives.
- The proposed alert severity.

Sigma rules are written in YAML and can be converted into queries for supported SIEM platforms through compatible pySigma backends.

Sigma is not a SIEM and does not collect logs by itself. The organisation must already collect the required telemetry, such as Windows process-creation events, Sysmon events, Microsoft 365 audit logs, or Microsoft Entra audit logs.

## Prerequisites

The following components are required:

- Windows 10 or Windows 11.
- PowerShell.
- Git.
- Python 3.
- Internet access during installation.
- A local clone of this repository.

Confirm that Python is installed:

```powershell
py -0p
```

This displays the Python versions and installation paths available on the computer.

## Clone the Repository

Clone the repository from GitHub:

```powershell
git clone https://github.com/ibraim-marinos/sigma-irish-threat-landscape.git
```

Move into the repository:

```powershell
cd sigma-irish-threat-landscape
```

Confirm the repository status:

```powershell
git status
```

## Create a Python Virtual Environment

Create an isolated Python environment inside the repository:

```powershell
py -m venv .venv
```

Activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

When activation succeeds, the PowerShell prompt begins with:

```text
(.venv)
```

The virtual environment prevents the project dependencies from interfering with packages installed globally on the computer.

## Install Sigma CLI

Upgrade `pip` inside the virtual environment:

```powershell
python -m pip install --upgrade pip
```

Install Sigma CLI:

```powershell
python -m pip install sigma-cli
```

Confirm the installed package:

```powershell
python -m pip show sigma-cli
```

Confirm the Sigma CLI version:

```powershell
sigma version
```

This project was developed and validated with Sigma CLI 3.1.0.

The correct version command is `sigma version`, not `sigma --version`.

## Repository Rule Structure

Detection rules are stored below the `rules` directory and grouped by detection category:

```text
rules/
├── bec_phishing/
├── credential_access/
├── lateral_movement/
├── lolbins/
├── m365_abuse/
├── malware/
├── oauth_abuse/
├── persistence/
└── reconnaissance/
```

Each `.yml` file contains the machine-readable Sigma detection.

The corresponding analyst documentation is stored under:

```text
docs/rules/
```

The documentation explains the threat scenario, detection logic, telemetry requirements, MITRE ATT&CK mapping, false positives, investigation guidance, tuning recommendations, validation results, and limitations.

## Validate One Rule

Use `sigma check` followed by the rule path to validate an individual rule.

Example:

```powershell
sigma check rules\malware\powershell_remote_payload_download.yml
```

A successful result should include:

```text
Found 0 errors, 0 condition errors and 0 issues.
No rule errors found.
No condition errors found.
No validation issues found.
```

This confirms that Sigma CLI can parse the rule and that its syntax, condition structure, and supported quality checks pass validation.

## Validate a Rule Category

A complete category can be validated by providing its directory.

Example:

```powershell
sigma check rules\lolbins
```

This validates all Sigma rules stored in the `rules\lolbins` directory.

Other examples include:

```powershell
sigma check rules\persistence
sigma check rules\oauth_abuse
sigma check rules\malware
```

## Validate the Complete Rule Library

Validate all rules together:

```powershell
sigma check rules
```

The expected result for the completed library is:

```text
Found 0 errors, 0 condition errors and 0 issues.
No rule errors found.
No condition errors found.
No validation issues found.
```

Validating the entire directory also helps identify library-wide issues that might not be apparent when rules are checked individually.

## Count the Rules

Confirm the number of Sigma rule files:

```powershell
Get-ChildItem rules -Recurse -Filter *.yml | Measure-Object
```

The expected count is:

```text
Count : 15
```

## Review Rule Metadata

Display the title, unique identifier, and severity level from every rule:

```powershell
Select-String -Path rules\*\*.yml -Pattern "^(title|id|level):"
```

This helps confirm that every rule contains essential metadata.

## Check for Duplicate Rule IDs

Every Sigma rule should use a unique UUID.

Run:

```powershell
$ids = Select-String -Path rules\*\*.yml -Pattern "^id:" | ForEach-Object { $_.Line.Replace("id:", "").Trim() }; $ids | Group-Object | Where-Object { $_.Count -gt 1 }
```

If the command produces no output, no duplicate identifiers were found.

## Review MITRE ATT&CK Tags

Display the MITRE ATT&CK technique tags used throughout the library:

```powershell
Select-String -Path rules\*\*.yml -Pattern "attack\.t[0-9]"
```

This provides a quick inventory of the techniques represented by the detection library.

The complete multi-stage coverage analysis is available in:

```text
docs/attack_chain_coverage.md
```

## Check File Formatting

Before committing changes, check for trailing whitespace and other formatting problems:

```powershell
git diff --check
```

No output means that Git found no formatting errors in the unstaged changes.

After staging files, run:

```powershell
git diff --cached --check
```

No output means that the staged changes passed the same formatting check.

## Review Changes Before Committing

Display the current file status:

```powershell
git status --short
```

Review a summary of staged changes:

```powershell
git --no-pager diff --cached --stat
```

These commands help prevent accidental or unrelated files from being included in a commit.

## Sigma CLI Plugins

Sigma CLI uses plugins to provide backends, processing pipelines, and other conversion components.

List the available plugins:

```powershell
sigma plugin list
```

List the conversion targets currently installed:

```powershell
sigma list targets
```

If no target is available, the appropriate backend plugin must be installed before conversion.

For example, install the Splunk backend with:

```powershell
sigma plugin install splunk
```

After installation, confirm that the target is available:

```powershell
sigma list targets
```

Backend installation is optional when the objective is only to validate Sigma rules.

## Convert a Sigma Rule

The general conversion format is:

```powershell
sigma convert -t <target> <rule-path>
```

For example, after installing the Splunk backend:

```powershell
sigma convert -t splunk rules\malware\powershell_remote_payload_download.yml
```

Convert a complete directory:

```powershell
sigma convert -t splunk rules\lolbins
```

Available targets depend on the plugins installed in the active Python environment.

Use the following command for the current conversion options:

```powershell
sigma convert --help
```

## Processing Pipelines

A backend converts generic Sigma logic into the query language used by a SIEM. A processing pipeline can additionally map generic Sigma fields and log sources to the field names used by a particular environment.

List installed pipelines:

```powershell
sigma list pipelines
```

Pipelines are important because two organisations using the same SIEM may use different indexes, source types, field names, or data models.

A successfully converted query is therefore a starting point. It must still be reviewed and tested against the target environment.

## What Validation Confirms

Sigma CLI validation helps confirm:

- The YAML can be parsed.
- Required rule elements are present.
- Detection conditions reference valid selections.
- Supported field modifiers are used correctly.
- Rule identifiers and tags follow supported quality checks.
- The rule does not contain recognised validation issues.

## What Validation Does Not Confirm

A clean Sigma CLI result does not prove that:

- The required logs are being collected.
- The event fields match a specific SIEM implementation.
- The detection will identify every variation of the behaviour.
- The rule will produce an acceptable false-positive rate.
- The severity is appropriate for every organisation.
- The rule is ready for immediate production deployment.

Production readiness requires representative log samples, SIEM field mapping, controlled testing, analyst review, tuning, and ongoing performance monitoring.

## Required Telemetry

The rules in this repository depend on several log sources.

Windows-focused rules generally require:

- Windows process-creation auditing or equivalent EDR telemetry.
- Full command-line capture.
- Parent and child process relationships.
- Sysmon process-creation events where available.
- Sysmon Registry value-set events for Registry persistence detections.

Microsoft cloud rules generally require:

- Microsoft 365 Unified Audit Log data.
- Exchange Online administrative events.
- Microsoft Entra ID audit logs.
- Application-consent and service-principal activity.

A rule cannot detect activity when its required telemetry is absent or incomplete.

## Troubleshooting

### Sigma Command Is Not Recognised

Confirm that the virtual environment is active:

```powershell
.\.venv\Scripts\Activate.ps1
```

Then confirm the installation:

```powershell
python -m pip show sigma-cli
```

### PowerShell Blocks Virtual-Environment Activation

Check the current execution policy:

```powershell
Get-ExecutionPolicy
```

If organisational policy permits it, allow locally created scripts for the current user:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Security policy should not be changed on a managed corporate computer without authorisation.

### Sigma Reports a YAML Parsing Error

Review:

- Indentation.
- Colons.
- Quotation marks.
- List formatting.
- Field modifiers.
- Tabs accidentally inserted into YAML.

YAML should use spaces for indentation.

### Sigma Reports a Condition Error

Confirm that every selection referenced by `condition` exists under `detection`.

Example:

```yaml
condition: selection_image and selection_download and selection_url
```

All three selections must be defined within the same detection section.

### No Conversion Target Is Available

List installed targets:

```powershell
sigma list targets
```

Then list available plugins:

```powershell
sigma plugin list
```

Install the required backend and check the targets again.

### A Converted Query Uses Incorrect Fields

The generic fields in the Sigma rule may not match the organisation’s SIEM schema.

Review:

- Index and source-type selection.
- Windows event-field extraction.
- EDR field names.
- Microsoft 365 audit-field mapping.
- Backend processing pipelines.
- Organisation-specific aliases and data models.

## Recommended Validation Workflow

Use the following workflow whenever a rule is created or modified:

1. Save the YAML file.
2. Validate the individual rule with `sigma check`.
3. Review its detection logic and MITRE ATT&CK mapping.
4. Update the corresponding analyst documentation.
5. Run `git diff --check`.
6. Validate the complete `rules` directory.
7. Capture validation evidence when required.
8. Review `git status --short`.
9. Stage the intended files.
10. Run `git diff --cached --check`.
11. Review the staged change summary.
12. Commit and push the validated changes.

## Security and Production Considerations

These rules are designed for defensive security, education, and portfolio demonstration.

Before production deployment:

- Test each rule against representative telemetry.
- Confirm field mappings.
- Establish approved administrative baselines.
- Add environment-specific allowlists carefully.
- Measure alert volume.
- Review false positives.
- Define investigation and escalation procedures.
- Correlate detections with identity, endpoint, network, and threat-intelligence data.
- Maintain version control for tuning changes.
- Revalidate rules after modifications.

Broad exclusions should be avoided because they may create detection gaps that attackers can exploit.

## References

- [Sigma Detection Format documentation](https://sigmahq.io/docs/)
- [Sigma Getting Started guide](https://sigmahq.io/docs/guide/getting-started.html)
- [Sigma backends and plugins](https://sigmahq.io/docs/digging-deeper/backends)
- [SigmaHQ rule repository](https://github.com/SigmaHQ/sigma)
- [Sigma CLI repository](https://github.com/SigmaHQ/sigma-cli)
- [pySigma repository](https://github.com/SigmaHQ/pySigma)
- [MITRE ATT&CK](https://attack.mitre.org/)