# M365 Inbox Forwarding with Message Hiding

## Rule Status

Experimental - Sigma CLI validation passed.

## Threat Scenario

Following the compromise of a Microsoft 365 account, an attacker may create or modify an Exchange Online inbox rule to forward messages to another recipient.

The attacker may combine forwarding with actions that delete, mark as read, or move the original messages. This can provide continued access to email communications while reducing the likelihood that the victim notices the malicious activity.

## Detection Hypothesis

If Microsoft 365 records the creation or modification of an inbox rule that combines message forwarding or redirection with message-hiding behaviour, the activity should be investigated as potential post-compromise BEC activity.

## Required Telemetry

Microsoft 365 Unified Audit Log events for Exchange Online.

```yaml
logsource:
  product: m365
  service: exchange
```

## Relevant Event Fields

### Operation

Identifies the Exchange Online action performed:

- `New-InboxRule`
- `Set-InboxRule`

### Parameters

Identifies the configuration applied to the inbox rule.

Forwarding or redirection parameters:

- `ForwardTo`
- `ForwardAsAttachmentTo`
- `RedirectTo`

Message-hiding parameters:

- `DeleteMessage`
- `MarkAsRead`
- `MoveToFolder`

## Planned Detection Logic

```text
(New-InboxRule OR Set-InboxRule)
AND
(ForwardTo OR ForwardAsAttachmentTo OR RedirectTo)
AND
(DeleteMessage OR MarkAsRead OR MoveToFolder)
```

## MITRE ATT&CK Mapping

- **Tactic:** Collection
- **Technique:** T1114.003 - Email Forwarding Rule
- **Tactic:** Stealth
- **Technique:** T1564.008 - Email Hiding Rules

## Documentation Status

Complete - detection logic, false positives, investigation guidance, validation results, tuning recommendations, and limitations documented.

## Detection Logic Explanation

The rule requires three groups of indicators to occur within the same Microsoft 365 Exchange audit event.

### Operation Selection

The `Operation` field must indicate that an inbox rule was created or modified:

```text
New-InboxRule OR Set-InboxRule
```

### Forwarding Selection

The `Parameters` field must contain at least one forwarding or redirection action:

```text
ForwardTo OR ForwardAsAttachmentTo OR RedirectTo
```

### Message-Hiding Selection

The `Parameters` field must also contain at least one action capable of reducing the visibility of the original message:

```text
DeleteMessage OR MarkAsRead OR MoveToFolder
```

### Final Condition

```text
operation AND forwarding AND message hiding
```

Requiring all three selections makes the rule more specific than a generic alert for any newly created forwarding rule.

## False Positives

Possible legitimate scenarios include:

- A user combining forwarding with mailbox organisation actions.
- An administrator configuring rules during a mailbox migration.
- Helpdesk activity involving shared or delegated mailboxes.
- Approved business workflows that forward and archive messages.

All matches should be compared with approved change records and the normal behaviour of the affected user.

## Investigation Notes

When the rule generates an alert:

1. Identify the affected mailbox using `UserId` and `ObjectId`.
2. Review `Parameters` to determine the forwarding destination and hiding action.
3. Confirm whether the destination is internal, external, approved, or previously observed.
4. Review `ClientIP` and correlate it with Microsoft Entra ID sign-in logs.
5. Look for unusual locations, devices, user agents, failed MFA attempts, or unfamiliar sessions.
6. Review recent `New-InboxRule`, `Set-InboxRule`, and `Remove-InboxRule` events for the user.
7. Check whether mailbox forwarding is also configured at the mailbox level.
8. Confirm the activity with the user, mailbox owner, helpdesk, or change-management records.
9. If unauthorized, disable the rule, revoke active sessions, reset credentials, and investigate related account activity.

## Tuning Recommendations

- Allowlist documented forwarding destinations where appropriate.
- Exclude approved service accounts or administrative workflows only after verification.
- Correlate matches with unusual sign-ins or recent credential changes.
- Maintain visibility of allowlisted activity for periodic review.
- Avoid broad exclusions that could hide attacker-controlled forwarding rules.

## Validation Results

- **Validation date:** 2026-07-23
- **Tool:** Sigma CLI 3.1.0
- **Command:**

```powershell
sigma check rules\bec_phishing\m365_inbox_forwarding_with_message_hiding.yml
```

- **Result:** 0 errors, 0 condition errors, and 0 validation issues.

## Limitations

- The rule identifies forwarding and message-hiding parameters but does not independently prove that the destination is external or malicious.
- The `Parameters` field must be ingested in a searchable form by the target SIEM.
- Field mappings may require adjustment depending on the Microsoft 365 connector and SIEM platform.
- Legitimate business workflows may produce matching events and require environment-specific tuning.