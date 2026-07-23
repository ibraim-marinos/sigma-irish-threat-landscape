# M365 Mailbox SMTP Forwarding with Local Delivery

## Rule Status

Experimental - Sigma CLI validation passed.

## Threat Scenario

An attacker with sufficient access to Microsoft 365 Exchange Online may modify mailbox-level forwarding settings using the `Set-Mailbox` operation.

By configuring an SMTP forwarding address and retaining delivery to the original mailbox, the attacker may receive copies of incoming messages while the victim continues to receive email normally. This can reduce the likelihood that the forwarding activity is noticed.

## Detection Hypothesis

If Microsoft 365 records a `Set-Mailbox` operation that configures SMTP forwarding together with continued delivery to the original mailbox, the activity should be investigated as potential stealthy email collection.

## Required Telemetry

Microsoft 365 Unified Audit Log events for Exchange Online.

```yaml
logsource:
  product: m365
  service: exchange
```

## Relevant Event Fields

### Operation

The `Operation` field identifies the Exchange Online action:

- `Set-Mailbox`

### Parameters

The `Parameters` field contains the mailbox configuration:

- `ForwardingSmtpAddress`
- `DeliverToMailboxAndForward`

The forwarding destination value must be reviewed during investigation to determine whether it is internal, external, approved, or suspicious.

## Planned Detection Logic

```text
Set-Mailbox
AND
ForwardingSmtpAddress
AND
DeliverToMailboxAndForward
```

## MITRE ATT&CK Mapping

- **Tactic:** Collection
- **Technique:** T1114.003 - Email Forwarding Rule

## Documentation Status

Complete - detection logic, false positives, investigation guidance, validation results, tuning recommendations, and limitations documented.

## Detection Logic Explanation

The rule identifies a Microsoft 365 Exchange audit event where the mailbox configuration is modified using `Set-Mailbox`.

### Operation Selection

The `Operation` field must contain:

```text
Set-Mailbox
```

### Parameter Selection

The `Parameters` field must contain all of the following:

```text
ForwardingSmtpAddress
AND
DeliverToMailboxAndForward
AND
True
```

This combination indicates that SMTP forwarding was configured together with continued delivery to the original mailbox.

### Final Condition

```text
Set-Mailbox AND forwarding parameters
```

## False Positives

Possible legitimate scenarios include:

- Approved mailbox forwarding for business continuity.
- Delegated mailbox access or shared mailbox workflows.
- Employee onboarding, offboarding, or role transitions.
- Mailbox migration or consolidation activity.
- Administrator-configured forwarding supported by a valid change request.

## Investigation Notes

When the rule generates an alert:

1. Identify the initiating account using `UserId`.
2. Identify the affected mailbox using `ObjectId`.
3. Review `Parameters` and extract the value of `ForwardingSmtpAddress`.
4. Determine whether the forwarding destination is internal, external, approved, or newly observed.
5. Review `ClientIP` and correlate it with Microsoft Entra ID sign-in activity.
6. Confirm whether the initiating account had legitimate Exchange administrative privileges.
7. Check for an approved helpdesk ticket or change-management record.
8. Review recent mailbox permission, inbox rule, OAuth consent, and authentication changes.
9. Confirm the forwarding configuration directly using Exchange Online administrative tools.
10. If unauthorized, remove the forwarding configuration, revoke sessions, reset credentials, and investigate related accounts.

## Tuning Recommendations

- Maintain an allowlist of approved forwarding destinations.
- Correlate matches with privileged administrator activity.
- Exclude documented migration accounts only after confirming their expected behaviour.
- Monitor changes outside approved maintenance windows.
- Alert with higher priority when the destination is external or newly observed.
- Avoid excluding all administrator activity because compromised administrators can perform the same action.

## Validation Results

- **Validation date:** 2026-07-23
- **Tool:** Sigma CLI 3.1.0
- **Command:**

```powershell
sigma check rules\bec_phishing\m365_mailbox_smtp_forwarding_with_local_delivery.yml
```

- **Result:** 0 errors, 0 condition errors, and 0 validation issues.

## Limitations

- The rule does not independently determine whether the forwarding destination is external or malicious.
- The `Parameters` field must be ingested in a searchable form by the target SIEM.
- The string representation of the enabled value may differ between Microsoft 365 connectors.
- The presence of `True` should be tested against representative audit events before production deployment.
- Field mappings may require adjustment for the target SIEM or Microsoft 365 connector.
- Legitimate administrative workflows may trigger the rule and require environment-specific tuning.