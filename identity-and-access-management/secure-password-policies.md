# Secure Password and Access Key Policies

## Tier: 1 - High Priority
**MITRE ATT&CK:** [T1552 - Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)  
**Remediation SLA:** 48 hours  
**CVSS Range:** 7.0 - 9.0

---

## Risk Description

Weak password policies and unrotated access keys are primary attack vectors. Attackers maintain vast databases of breached credentials and use automated tools to test them against targets. Exposed API keys in code repositories are discovered and exploited within minutes.

### Business Impact
- Credential stuffing attacks succeed against 0.5-2% of attempts
- Average cost of credential-related breach: $4.5M
- Leaked API keys in GitHub repos exploited in <30 minutes
- Stale access keys persist after employee departure

### Attack Vectors
| Vector | Description | Prevalence |
|--------|-------------|------------|
| Credential stuffing | Automated testing of breached creds | High |
| Password spraying | Common passwords across many accounts | High |
| Exposed secrets | Keys in code repos, configs | Very High |
| Key persistence | Unrotated keys from former employees | Medium |

---

## Password Policy Requirements

### Minimum Standards (NIST SP 800-63B)

| Requirement | Standard | Rationale |
|-------------|----------|-----------|
| Minimum length | 14 characters | Exponentially harder to crack |
| Complexity | Not required* | Length > complexity |
| Blocklist | Check against breached passwords | Prevent known compromised |
| History | Prevent last 12 passwords | Prevent reuse |
| Expiration | Only on compromise* | Frequent rotation = weaker passwords |
| MFA | Required | Primary defense |

*NIST updated guidance - complexity requirements and forced rotation often reduce security

### Password Strength Comparison
```
8 chars, complex:    ~6 hours to crack (GPU)
12 chars, lowercase: ~2 years to crack
14 chars, mixed:     ~10,000+ years to crack
20 chars passphrase: Effectively uncrackable
```

---

## Access Key Requirements

### Key Rotation Schedule

| Key Type | Rotation Frequency | Enforcement |
|----------|-------------------|-------------|
| Root/Admin API keys | Never use / Delete | Automated |
| User access keys | 90 days maximum | Policy |
| Service account keys | 90-180 days | Automated |
| Application secrets | 90 days | Secrets manager |
| SSH keys | Annual + on termination | Manual |

---

## Detection Methods

### Tools
- **[Nessus](https://www.tenable.com/products/nessus):** Password policy auditing
- **[PROWLER](https://prowler.cloud/):** Access key rotation analysis

### Detection Commands

**AWS Access Key Age:**
```bash
# Find access keys older than 90 days
aws iam generate-credential-report
aws iam get-credential-report --output text --query 'Content' | \
  base64 -d | awk -F, 'NR>1 && $9!="N/A" { 
    days=int((systime()-mktime(gensub(/[-:T]/, " ", "g", $10)))/86400); 
    if(days>90) print $1, "key age:", days, "days" 
  }'

# PROWLER check
prowler aws -c iam_access_key_age_90_days -c iam_password_policy_minimum_length_14
```

**Check for exposed secrets:**
```bash
# GitHub secret scanning (if enabled)
gh secret-scanning list --repo OWNER/REPO

# Local scan with truffleHog
trufflehog git file://./repo --since-commit HEAD~100
```

### Password Policy Verification
```bash
# AWS password policy
aws iam get-account-password-policy

# Expected output for compliant policy:
# MinimumPasswordLength: 14
# RequireSymbols: false (NIST)
# RequireNumbers: false (NIST)
# RequireUppercaseCharacters: false (NIST)
# RequireLowercaseCharacters: false (NIST)
# MaxPasswordAge: 0 (no expiry unless compromised)
# PasswordReusePrevention: 12
```

---

## Qualifying Criteria

A finding qualifies as Tier 1 Password/Key Policy issue if:

**Passwords:**
- [ ] Minimum length below 14 characters
- [ ] No check against breached password lists
- [ ] Default passwords in use
- [ ] Passwords stored in plaintext
- [ ] No account lockout policy

**Access Keys:**
- [ ] Root account has active access keys
- [ ] Access keys older than 90 days
- [ ] API keys committed to source control
- [ ] Service account keys without rotation
- [ ] Shared access keys across users

---

## Remediation

### AWS Password Policy

```bash
# Set compliant password policy
aws iam update-account-password-policy \
  --minimum-password-length 14 \
  --no-require-symbols \
  --no-require-numbers \
  --no-require-uppercase-characters \
  --no-require-lowercase-characters \
  --allow-users-to-change-password \
  --max-password-age 0 \
  --password-reuse-prevention 12
```

### Automated Key Rotation

```python
# Lambda function for automatic key rotation
import boto3
from datetime import datetime, timezone

def lambda_handler(event, context):
    iam = boto3.client('iam')
    max_age_days = 90
    
    for user in iam.list_users()['Users']:
        for key in iam.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']:
            age = (datetime.now(timezone.utc) - key['CreateDate']).days
            
            if age > max_age_days:
                # Deactivate old key
                iam.update_access_key(
                    UserName=user['UserName'],
                    AccessKeyId=key['AccessKeyId'],
                    Status='Inactive'
                )
                # Notify user to create new key
                notify_user(user['UserName'], key['AccessKeyId'], age)
```

### Secrets Management Implementation

```hcl
# Terraform - AWS Secrets Manager with rotation
resource "aws_secretsmanager_secret" "db_password" {
  name = "prod/db/password"
  
  # Enable automatic rotation
  rotation_rules {
    automatically_after_days = 90
  }
}

resource "aws_secretsmanager_secret_rotation" "db_password" {
  secret_id           = aws_secretsmanager_secret.db_password.id
  rotation_lambda_arn = aws_lambda_function.rotate_secret.arn
}
```

### Git Secret Prevention

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.4.0
    hooks:
      - id: detect-secrets
        args: ['--baseline', '.secrets.baseline']
        
  - repo: https://github.com/trufflesecurity/trufflehog
    rev: v3.63.0
    hooks:
      - id: trufflehog
```

### GitHub Secret Scanning

```yaml
# .github/workflows/secret-scan.yml
name: Secret Scanning
on: [push, pull_request]

jobs:
  secrets:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: TruffleHog
        uses: trufflesecurity/trufflehog@main
        with:
          extra_args: --only-verified
```

---

## Breached Password Checking

### Implementation Options

| Method | Integration |
|--------|-------------|
| Have I Been Pwned API | Real-time check at password set |
| Internal blocklist | Offline list of known compromised |
| Azure AD Password Protection | Native AD integration |
| AWS Cognito | Custom Lambda trigger |

```python
# HIBP API check example
import hashlib
import requests

def is_password_breached(password):
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    
    response = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}')
    
    for line in response.text.splitlines():
        if line.split(':')[0] == suffix:
            return True  # Password found in breach database
    return False
```

---

## Monitoring Requirements

| Event | Alert Level | Response |
|-------|-------------|----------|
| New access key created | Info | Log and audit |
| Key older than 80 days | Warning | Notify user |
| Key older than 90 days | Critical | Force rotation |
| Multiple failed logins | High | Lockout + investigate |
| Password changed | Info | Confirm legitimacy |
| Secret detected in commit | Critical | Rotate immediately |

---

## References

- [NIST SP 800-63B Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)
- [AWS Secrets Manager Best Practices](https://docs.aws.amazon.com/secretsmanager/latest/userguide/best-practices.html)

---

*For scanner details, see [Scanners and Frameworks](../scanners-and-frameworks.md)*
