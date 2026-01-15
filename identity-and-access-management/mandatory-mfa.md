# Mandatory MFA

## Tier: 1 - High Priority
**MITRE ATT&CK:** [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)  
**Remediation SLA:** 24 hours  
**CVSS Range:** 9.0 - 10.0

---

## Risk Description

Multi-factor authentication (MFA) is the single most effective control against account compromise. Microsoft reports that MFA blocks 99.9% of automated attacks. Accounts without MFA are trivially compromised through credential stuffing, phishing, and password spraying.

### Business Impact
- **Colonial Pipeline (2021):** Single compromised VPN account without MFA led to $4.4M ransom
- **Twitter (2020):** Social engineering bypassed single-factor auth, compromised high-profile accounts
- **SolarWinds (2020):** Attackers leveraged accounts without proper MFA enforcement

### Attack Vectors Mitigated by MFA
| Attack Type | MFA Effectiveness |
|-------------|-------------------|
| Credential stuffing | 99.9% blocked |
| Password spraying | 99.9% blocked |
| Phishing (standard) | 99.9% blocked |
| Phishing (advanced) | 95%+ blocked with phishing-resistant MFA |
| Brute force | 100% blocked |

---

## MFA Methods - Security Hierarchy

| Method | Security Level | Phishing-Resistant | Recommendation |
|--------|---------------|-------------------|----------------|
| **FIDO2/WebAuthn** | Highest | Yes | Privileged accounts |
| **Hardware Tokens** | High | Yes | All admin access |
| **TOTP Authenticator** | Medium | No | Standard users |
| **Push Notification** | Medium | Partial | Standard users with number matching |
| **SMS/Voice** | Low | No | Avoid - deprecated by NIST |

---

## Detection Methods

### Tools
- **[PROWLER](https://prowler.cloud/):** MFA enforcement verification across cloud accounts
- **[Cloudsploit](https://cloudsploit.com/):** User authentication configuration analysis

### Detection Commands

**AWS - Users without MFA:**
```bash
# List users without MFA
aws iam generate-credential-report
aws iam get-credential-report --output text --query 'Content' | \
  base64 -d | awk -F, '$4=="true" && $8=="false" {print $1}'

# PROWLER check
prowler aws -c iam_user_mfa_enabled_console_access
```

**Azure AD - MFA Status:**
```powershell
# Get MFA status for all users
Get-MgUser -All | ForEach-Object {
    Get-MgUserAuthenticationMethod -UserId $_.Id
}
```

**GCP - Users without 2FA:**
```bash
gcloud identity groups memberships list --group-email=GROUP --format="table(preferredMemberKey.id)" | \
  xargs -I{} gcloud identity users describe {} --format="value(name,2svEnrolled)"
```

---

## Qualifying Criteria

A finding qualifies as Tier 1 MFA Failure if:

- [ ] Any user account lacks MFA enrollment
- [ ] Privileged accounts use SMS-based MFA only
- [ ] MFA can be bypassed via legacy authentication
- [ ] Conditional access policies don't require MFA
- [ ] Service accounts with interactive login lack MFA
- [ ] Emergency/break-glass accounts lack secure MFA recovery

---

## Remediation

### Immediate Actions (0-24 hours)
1. Enable MFA requirement for all privileged accounts
2. Block legacy authentication protocols
3. Audit recent logins for accounts without MFA

### MFA Rollout Strategy

**Phase 1: Privileged Accounts (Day 1-7)**
- All admin and root accounts
- All accounts with elevated permissions
- Require hardware tokens or FIDO2

**Phase 2: Remote Access (Day 7-14)**
- VPN users
- Remote desktop access
- Cloud console access

**Phase 3: All Users (Day 14-30)**
- Standard users
- Contractors and third parties
- Service accounts with interactive capability

### AWS MFA Enforcement
```json
// IAM Policy requiring MFA
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyAllExceptListedIfNoMFA",
      "Effect": "Deny",
      "NotAction": [
        "iam:CreateVirtualMFADevice",
        "iam:EnableMFADevice",
        "iam:GetUser",
        "iam:ListMFADevices",
        "iam:ListVirtualMFADevices",
        "iam:ResyncMFADevice",
        "sts:GetSessionToken"
      ],
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}
      }
    }
  ]
}
```

### Azure Conditional Access
```powershell
# Create Conditional Access Policy requiring MFA
$params = @{
    DisplayName = "Require MFA for all users"
    State = "enabled"
    Conditions = @{
        Users = @{
            IncludeUsers = @("All")
        }
        Applications = @{
            IncludeApplications = @("All")
        }
    }
    GrantControls = @{
        Operator = "OR"
        BuiltInControls = @("mfa")
    }
}
New-MgIdentityConditionalAccessPolicy -BodyParameter $params
```

### Block Legacy Authentication
```powershell
# Azure AD - Block legacy auth
$params = @{
    DisplayName = "Block legacy authentication"
    State = "enabled"
    Conditions = @{
        ClientAppTypes = @("exchangeActiveSync", "other")
    }
    GrantControls = @{
        Operator = "OR"
        BuiltInControls = @("block")
    }
}
```

---

## Phishing-Resistant MFA

For highest security (privileged accounts):

| Solution | Protocol | Implementation |
|----------|----------|----------------|
| YubiKey | FIDO2/WebAuthn | Hardware token enrollment |
| Windows Hello | FIDO2 | Biometric + TPM |
| Apple Passkeys | FIDO2 | Device-bound credentials |
| Google Titan | FIDO2 | Hardware token |

---

## Exception Handling

If MFA cannot be immediately enabled:

1. Document business justification
2. Implement compensating controls:
   - IP allowlisting
   - Device certificates
   - Enhanced monitoring
   - Short session timeouts
3. Set remediation deadline (maximum 30 days)
4. Require executive sign-off

---

## Monitoring Requirements

| Event | Action |
|-------|--------|
| MFA enrollment disabled | Alert security team |
| Legacy auth attempt | Log and block |
| MFA bypass attempt | Immediate investigation |
| Multiple MFA failures | Account lockout |
| Admin login without MFA | Critical alert |

---

## References

- [Microsoft: MFA Effectiveness](https://www.microsoft.com/security/blog/2019/08/20/one-simple-action-you-can-take-to-prevent-99-9-percent-of-account-attacks/)
- [NIST SP 800-63B: Authentication Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [CISA: More Than a Password](https://www.cisa.gov/mfa)

---

*For scanner details, see [Scanners and Frameworks](../scanners-and-frameworks.md)*
