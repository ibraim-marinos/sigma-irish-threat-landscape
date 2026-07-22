# Sigma Rule Structure Guide

This document defines the structure and quality requirements followed by every detection rule in this repository.

## What Is Sigma?

Sigma is a generic and open detection format used to describe suspicious log activity. A Sigma rule can be converted into queries for supported SIEM platforms through compatible tooling and backends.

## Standard Rule Structure

```yaml
title: Short Descriptive Rule Title
id: 00000000-0000-4000-8000-000000000000
status: experimental
description: Concise explanation of the suspicious activity.
references:
  - https://example.com/reference
author: Ibraim Arturo Marinos Lian
date: YYYY-MM-DD
modified: YYYY-MM-DD
tags:
  - attack.tactic
  - attack.t1234
logsource:
  category: example_category
  product: example_product
detection:
  selection:
    FieldName: ExampleValue
  condition: selection
falsepositives:
  - Legitimate administrative or business activity.
level: medium
```

This is a structural example only. It is not a functional detection rule.

## Field Requirements

### title

A short and specific description of the activity detected by the rule.

### id

A globally unique UUID version 4. Each original rule must have its own identifier.

### status

The maturity of the rule. New rules in this project begin as `experimental` and may move to `test` after validation.

Supported values include:

- `experimental`
- `test`
- `stable`
- `deprecated`
- `unsupported`

### description

A concise explanation of the suspicious behaviour and why it may be security-relevant.

### references

Authoritative sources supporting the detection logic, telemetry, or threat behaviour.

### author

The creator of the detection rule.

### date and modified

Dates use the ISO 8601 format:

```text
YYYY-MM-DD
```

The `modified` field is added or updated when significant rule logic or metadata changes.

### tags

Tags provide categorisation and MITRE ATT&CK mapping.

Example:

```yaml
tags:
  - attack.execution
  - attack.t1059.001
```

### logsource

Defines the telemetry required by the rule.

It may contain:

- `category`: the type of log activity.
- `product`: the operating system or product.
- `service`: a specific logging service.
- `definition`: additional logging requirements.

Example:

```yaml
logsource:
  category: process_creation
  product: windows
```

### detection

Contains the observable event fields and values used to identify the suspicious activity.

Example:

```yaml
detection:
  selection:
    Image|endswith: '\example.exe'
  condition: selection
```

### condition

Determines how selections and filters are evaluated.

Examples:

```yaml
condition: selection
condition: selection and not filter
condition: 1 of selection_*
```

### falsepositives

Documents legitimate scenarios that may trigger the rule. These notes help analysts investigate alerts but do not automatically suppress matches.

### level

Defines the severity of the detection:

- `informational`
- `low`
- `medium`
- `high`
- `critical`

## Repository Quality Standard

Every rule in this project must include:

- A unique UUID v4.
- A clear and specific title.
- An accurate log source.
- Understandable detection logic.
- MITRE ATT&CK tactic and technique tags.
- Known false positives.
- An appropriate severity level.
- Authoritative references where available.
- Separate investigation and tuning documentation.
- Successful validation before release.

## File-Naming Standard

Rule filenames must:

- Use lowercase letters.
- Use underscores instead of spaces.
- Avoid special characters.
- Use the `.yml` extension.
- Clearly describe the detection.

Example:

```text
win_suspicious_certutil_download.yml
```