# M365 OAuth Consent with High-Risk Permissions

## Rule Status

Experimental - successfully validated with Sigma CLI.

## Threat Scenario

After compromising a Microsoft 365 account, an attacker may persuade the victim or use the compromised account to grant consent to a malicious OAuth application.

The application may request sensitive Microsoft Graph permissions that allow it to read, modify, or send email and maintain access through OAuth tokens. This can provide continued access to organisational data without requiring repeated interactive sign-ins.

## Detection Hypothesis

If Microsoft Entra records a successful application-consent event involving high-risk email permissions or persistent delegated access, the activity should be investigated as possible malicious OAuth consent abuse.

## Required Telemetry

Microsoft Entra ID audit logs containing application-management and consent activity.

```yaml
logsource:
  product: azure
  service: auditlogs
```

## Relevant Audit Activity

- **Category:** `ApplicationManagement`
- **Activity:** `Consent to application`
- **Result:** `success`
- **Logged service:** Core Directory

## High-Risk Permissions

The detection focuses on the following permissions:

- `Mail.Read`
- `Mail.ReadWrite`
- `Mail.Send`
- `offline_access`

These permissions may allow an application to read email, modify mailbox data, send messages, or maintain delegated access through refresh tokens.

## Detection Logic Explanation

The rule uses two required selections.

### Application Consent Event

```yaml
selection_event:
  Category: ApplicationManagement
  ActivityDisplayName: Consent to application
  Result: success
```

This selection limits the detection to successful Microsoft Entra application-consent events.

### High-Risk Permissions

```yaml
selection_permissions:
  TargetResources|contains:
    - Mail.Read
    - Mail.ReadWrite
    - Mail.Send
    - offline_access
```

This selection searches the target-resource details for permissions associated with email access, email modification, message sending, or persistent delegated access.

### Final Condition

```yaml
condition: selection_event and selection_permissions
```

Both selections must match. A general application-management event without one of the specified permissions will not trigger the rule.

## MITRE ATT&CK Mapping

- **T1671 - Cloud Application Integration:** An attacker may use a malicious or compromised OAuth integration to establish persistent access to cloud data.
- **T1550.001 - Application Access Token:** OAuth access or refresh tokens may allow access without repeatedly supplying the user's credentials.

## False Positives

Potential legitimate activity includes:

- Approved business applications that require Microsoft 365 email access.
- Expected user consent during deployment of an authorised application.
- Administrator consent granted as part of an approved change.
- Security, backup, migration, archiving, or email-management applications.
- Legitimate applications requesting `offline_access` to maintain user sessions.

Every alert should be reviewed against the organisation's approved-application inventory and change-management records.

## Investigation Notes

When the rule triggers, the analyst should:

1. Identify the user or administrator who granted consent.
2. Record the application name, application ID, publisher, and tenant information.
3. Review every permission granted to the application.
4. Determine whether the application is approved by the organisation.
5. Check whether administrative consent was used.
6. Review the consenting user's recent sign-ins, IP addresses, devices, locations, and MFA results.
7. Search for recent phishing activity involving the affected user.
8. Determine whether the application subsequently accessed email, files, contacts, or other Microsoft 365 data.
9. Review whether other users granted consent to the same application.
10. Revoke the consent and associated tokens if the activity is confirmed as unauthorised.
11. Reset affected credentials and investigate the account for additional compromise.

## Tuning Recommendations

- Maintain an allowlist of approved application IDs rather than relying only on application names.
- Prioritise consent granted by privileged or high-value accounts.
- Increase severity when several sensitive permissions are granted together.
- Correlate consent events with unusual sign-ins, phishing reports, or newly registered applications.
- Consider requiring additional risk indicators when `offline_access` is the only matched permission.
- Tune field mappings according to how Microsoft Entra audit data is normalised by the target SIEM.

## Validation Results

The rule was validated on 24 July 2026 using Sigma CLI 3.1.0.

```powershell
sigma check rules\oauth_abuse\m365_oauth_consent_high_risk_permissions.yml
```

Validation result:

```text
Found 0 errors, 0 condition errors and 0 issues.
No rule errors found.
No condition errors found.
No validation issues found.
```

## Limitations

- The rule detects the granting of permissions, not the application's subsequent use of those permissions.
- Legitimate applications may request the same permissions and generate alerts.
- `offline_access` is commonly requested by legitimate applications and may require additional tuning.
- The structure of `TargetResources` may vary between log collectors and SIEM platforms.
- The rule depends on Microsoft Entra audit logs being enabled, collected, and correctly normalised.
- Historical consent granted before audit-log collection began will not be detected.

## References

- https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/app-perms-audit-logs
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-applications
- https://attack.mitre.org/techniques/T1671/
- https://attack.mitre.org/techniques/T1550/001/