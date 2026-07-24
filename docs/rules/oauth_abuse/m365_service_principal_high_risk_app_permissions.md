# M365 Service Principal High-Risk Application Permissions

## Rule Status

Experimental - successfully validated with Sigma CLI.

## Threat Scenario

An attacker with sufficient Microsoft Entra privileges may grant high-risk application permissions to a malicious or compromised service principal.

Unlike delegated permissions, application permissions can allow the service principal to access organisational data automatically without a signed-in user. This may provide persistent access to email, files, and directory information.

## Detection Hypothesis

If Microsoft Entra records a successful app-role assignment to a service principal involving high-risk Microsoft Graph permissions, the activity should be investigated as possible OAuth application abuse or cloud persistence.

## Required Telemetry

Microsoft Entra ID audit logs containing application-management and service-principal permission changes.

```yaml
logsource:
  product: azure
  service: auditlogs
```

## Relevant Audit Activity

- **Category:** `ApplicationManagement`
- **Activity:** `Add app role assignment to service principal`
- **Result:** `success`
- **Logged service:** Core Directory

## High-Risk Application Permissions

The detection focuses on the following permissions:

- `Mail.Read`
- `Mail.ReadWrite`
- `Mail.Send`
- `Files.ReadWrite.All`
- `Directory.ReadWrite.All`

These permissions may allow an application to access or modify email, files, and directory information without an interactive user session.

## Detection Logic Explanation

The rule uses two required selections.

### App-Role Assignment Event

```yaml
selection_event:
  Category: ApplicationManagement
  ActivityDisplayName: Add app role assignment to service principal
  Result: success
```

This selection limits the detection to successful Microsoft Entra app-role assignments involving service principals.

### High-Risk Permissions

```yaml
selection_permissions:
  TargetResources|contains:
    - Mail.Read
    - Mail.ReadWrite
    - Mail.Send
    - Files.ReadWrite.All
    - Directory.ReadWrite.All
```

This selection searches the target-resource details for application permissions that provide broad access to email, files, or directory information.

### Final Condition

```yaml
condition: selection_event and selection_permissions
```

Both selections must match. An unrelated application-management event or an app-role assignment without one of the specified permissions will not trigger the rule.

## MITRE ATT&CK Mapping

- **T1671 - Cloud Application Integration:** An attacker may use a malicious or compromised application integration to establish persistent access to cloud data.
- **T1098.003 - Additional Cloud Roles:** An attacker may assign additional cloud permissions to maintain or expand access.

## False Positives

Potential legitimate activity includes:

- Approved deployment of applications requiring Microsoft Graph permissions.
- Security monitoring or incident-response applications.
- Backup, migration, compliance, archiving, or automation services.
- Administrator changes performed through an approved change request.
- Permission updates required by a trusted application vendor.

Every alert should be compared with the approved-application inventory and change-management records.

## Investigation Notes

When the rule triggers, the analyst should:

1. Identify the user or administrator who assigned the permission.
2. Confirm whether the initiating account was authorised to make the change.
3. Record the service-principal name, object ID, application ID, and publisher.
4. Review all permissions assigned to the service principal.
5. Determine whether the application is approved by the organisation.
6. Verify whether an approved change request exists.
7. Review recent sign-ins and administrative activity from the initiating account.
8. Check whether new credentials, certificates, secrets, owners, or redirect URLs were added to the application.
9. Determine whether the service principal subsequently accessed email, files, or directory data.
10. Search for other users, applications, or service principals modified by the same initiating account.
11. Remove unauthorised permissions and revoke application credentials if malicious activity is confirmed.
12. Investigate the initiating account for possible compromise.

## Tuning Recommendations

- Maintain an allowlist of approved application IDs and service-principal object IDs.
- Prioritise changes performed by unexpected or newly privileged accounts.
- Increase severity when multiple high-risk permissions are granted together.
- Correlate the event with new application credentials, secrets, certificates, or owners.
- Correlate with unusual administrator sign-ins or changes performed outside approved maintenance windows.
- Tune field mappings according to how Microsoft Entra audit data is normalised by the target SIEM.

## Validation Results

The rule was validated on 24 July 2026 using Sigma CLI 3.1.0.

```powershell
sigma check rules\oauth_abuse\m365_service_principal_high_risk_app_permissions.yml
```

Validation result:

```text
Found 0 errors, 0 condition errors and 0 issues.
No rule errors found.
No condition errors found.
No validation issues found.
```

## Limitations

- The rule detects permission assignment, not subsequent use of the permissions.
- Legitimate enterprise applications may require the same high-risk permissions.
- The structure of `TargetResources` may vary between log collectors and SIEM platforms.
- Application roles may appear as identifiers instead of readable permission names in some environments.
- The rule depends on Microsoft Entra audit logs being collected and correctly normalised.
- Historical permissions assigned before audit-log collection began will not be detected.

## References

- https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/app-perms-audit-logs
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-applications
- https://attack.mitre.org/techniques/T1671/
- https://attack.mitre.org/techniques/T1098/003/