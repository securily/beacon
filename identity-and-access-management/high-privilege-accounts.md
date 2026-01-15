# High-Privilege Accounts

## Tier: 1 - High Priority
**MITRE ATT&CK:** [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)  
**Remediation SLA:** 24 hours  
**CVSS Range:** 8.0 - 10.0

---

## Risk Description

High-privilege accounts (root, administrator, domain admin) are the ultimate target for attackers. A compromised privileged account provides complete control over systems, data, and network infrastructure. The principle of least privilege exists specifically to limit this blast radius.

### Business Impact
- Complete infrastructure compromise
- Mass data exfiltration capability
- Ransomware deployment with maximum impact
- Persistent access difficult to eradicate
- Regulatory violations (SOX, PCI DSS, HIPAA)

### Attack Chain
1. Initial access via phishing or exploited vulnerability
2. Credential harvesting (Mimikatz, keyloggers)
3. Privilege escalation to admin/root
4. Lateral movement using privileged credentials
5. Domain dominance and data exfiltration

---

## Privileged Account Categories

| Category | Examples | Risk Level |
|----------|----------|------------|
| **Infrastructure Admin** | Domain Admin, AWS root, GCP Owner | Critical |
| **Database Admin** | DBA, sa, postgres superuser | Critical |
| **Application Admin** | App superuser, CMS admin | High |
| **Service Accounts** | Automated processes with admin rights | High |
| **Emergency/Break-glass** | Rarely used recovery accounts | Critical |

---

## Detection Methods

### Tools
- **[PROWLER](https://prowler.cloud/):** IAM best practices and privileged account detection
- **[Cloudsploit](https://cloudsploit.com/):** Cloud privilege analysis

### Detection Queries

**AWS - Root Account Usage:**
```bash
aws iam generate-credential-report
aws iam get-credential-report --output text --query 'Content' | base64 -d | grep root
```

**AWS - Overprivileged IAM:**
```bash
prowler aws -c iam_administrator_access_with_mfa -c iam_root_access_key_exists
```

**Azure AD - Privileged Accounts:**
```powershell
Get-MgDirectoryRoleMember -DirectoryRoleId (Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'").Id
```

### Indicators of Risk
- Root/administrator accounts used for daily operations
- Service accounts with interactive login capability
- Privileged accounts without MFA
- Accounts unused for 90+ days with admin rights
- Shared credentials for privileged access

---

## Qualifying Criteria

A finding qualifies as Tier 1 High-Privilege Account issue if:

- [ ] Root account has active access keys
- [ ] Admin accounts lack MFA
- [ ] Service accounts have admin privileges unnecessarily
- [ ] Privileged accounts unused for 90+ days remain active
- [ ] Users have permanent admin privileges for infrequent tasks
- [ ] Shared admin credentials in use

---

## Remediation

### Immediate Actions (0-24 hours)
1. Enable MFA on ALL privileged accounts immediately
2. Remove access keys from root accounts
3. Disable unused privileged accounts
4. Audit recent privileged account activity for compromise

### Privileged Access Management (7-30 days)
1. Deploy PAM solution (CyberArk, HashiCorp Vault, AWS SSM)
2. Implement just-in-time (JIT) privilege elevation
3. Enforce privilege checkout with time limits
4. Implement session recording for privileged access

### AWS Root Account Lockdown
```bash
# Delete root access keys
aws iam delete-access-key --access-key-id AKIAEXAMPLE --user-name root

# Enable MFA (via console - cannot be done via CLI for root)

# Create organizational SCP to deny root usage
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Action": "*",
    "Resource": "*",
    "Condition": {
      "StringLike": {"aws:PrincipalArn": "arn:aws:iam::*:root"}
    }
  }]
}
```

### Least Privilege Implementation
```json
// Before: Overprivileged
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "*",
    "Resource": "*"
  }]
}

// After: Least privilege
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "s3:GetObject",
      "s3:PutObject"
    ],
    "Resource": "arn:aws:s3:::specific-bucket/*"
  }]
}
```

---

## Service Account Security

| Best Practice | Implementation |
|---------------|----------------|
| Unique accounts | One service account per application |
| No interactive login | Disable console access for service accounts |
| Key rotation | Automated rotation every 90 days |
| Audit logging | Log all service account actions |
| IP restrictions | Limit source IPs where possible |

---

## Monitoring Requirements

| Metric | Threshold | Action |
|--------|-----------|--------|
| Root account login | Any | Immediate alert and investigation |
| Admin role assumption | Unusual hours | Alert security team |
| New admin user creation | Any | Require approval verification |
| Failed admin login | 3+ attempts | Account lockout and alert |
| Service account interactive login | Any | Immediate investigation |

---

## References

- [NIST SP 800-53: AC-6 Least Privilege](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
- [Microsoft Securing Privileged Access](https://docs.microsoft.com/en-us/security/compass/privileged-access-strategy)

---

*For scanner details, see [Scanners and Frameworks](../scanners-and-frameworks.md)*
