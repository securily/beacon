# Secure Credential Management

## Tier: 3 - Best Practices
**Beacon ID:** `BCN-T3-IAM-002`
**MITRE ATT&CK:** [T1552 - Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)
**Remediation SLA:** 90 days
**Escalation:** Quarterly planning review

---

## Risk Description

This finding covers credential **process maturity**, not credential exposure.
The credentials are within policy today; the finding is that keeping them that
way depends on human diligence.

Manual processes fail silently and eventually. Every long-lived privileged
credential finding at Tier 1 began life as a rotation someone was supposed to
perform and stopped performing — usually without anyone noticing, because
nothing breaks when a rotation is skipped. That is precisely what makes it
dangerous: the failure mode is invisible until an incident makes it visible.

Automating the lifecycle is therefore preventive work with clearly compounding
returns. It is Tier 3 because the current state is compliant; the investment is
against *future* Tier 1 and Tier 2 findings rather than a present exposure.

> **Escalate immediately, do not record here:** a privileged credential already
> past its rotation interval, or found in a repository, is
> [BCN-T1-IAM-003](secure-password-policies.md) with a 72-hour SLA. Recording it
> under this finding silently applies a 90-day clock to a 72-hour problem — one
> of the six documented classification failures in
> [CLASSIFICATION.md](../CLASSIFICATION.md).

### Why this compounds

| Manual practice | Eventual Tier 1 finding |
|-----------------|-------------------------|
| Calendar-reminder rotation | Unrotated privileged access key |
| Credentials shared over chat | Credential in an unrecallable location |
| Provisioning by ticket | Orphaned account after a leaver |
| Static keys in CI configuration | Key harvested from a build log |
| One shared account per team | Rotation impossible without coordinated change |

---

## Credential Hierarchy

Prefer the highest available option. Each step up removes a class of failure
rather than mitigating it.

| Approach | Rotation burden | Exposure window | Recommendation |
|----------|-----------------|-----------------|----------------|
| **Workload identity** (IRSA, GKE WI, Azure MI) | None — no stored secret | Minutes | Target state for all workloads |
| **OIDC federation** (CI to cloud) | None — no stored secret | Job duration | Target state for all pipelines |
| **Managed secret store with auto-rotation** | Automated | Rotation period | Where a secret must exist |
| **Managed secret store, manual rotation** | Manual | Rotation period | Interim |
| **Static credential in config** | Manual | Unbounded | Remediate |
| **Credential in source control** | — | Permanent | **Tier 1 — rotate now** |

The goal is not better rotation. It is **removing the credential entirely**,
which makes rotation moot.

---

## Detection Methods

### Tools
- **[PROWLER](https://prowler.cloud/):** Access key age and rotation posture
- **[TruffleHog](https://github.com/trufflesecurity/trufflehog) / [Gitleaks](https://github.com/gitleaks/gitleaks):** Secret scanning across full git history
- **[Nessus](https://www.tenable.com/products/nessus):** Credential management auditing

### Assessing lifecycle maturity

**The diagnostic question:** *how does rotation happen?* If the answer names a
person or a reminder rather than a system, the finding applies.

```bash
# AWS — key age distribution across all users
aws iam list-users --query 'Users[].UserName' --output text | tr '\t' '\n' | \
  while read -r u; do
    aws iam list-access-keys --user-name "$u" \
      --query "AccessKeyMetadata[].{User:UserName,Key:AccessKeyId,
                                    Created:CreateDate,Status:Status}" \
      --output text
  done | awk '{ cmd="date -d "$2" +%s 2>/dev/null || date -j -f %Y-%m-%dT%H:%M:%S+00:00 "$2" +%s";
                cmd | getline created; close(cmd);
                age=int((systime()-created)/86400);
                if (age > 90) print "STALE ("age"d): "$0 }'
```

```bash
# Secrets Manager — which secrets actually have automatic rotation
aws secretsmanager list-secrets \
  --query 'SecretList[].{Name:Name,
                         Rotation:RotationEnabled,
                         LastRotated:LastRotatedDate}' --output table
```

```bash
# Full history scan — deleted secrets persist in git objects
trufflehog git file://. --only-verified --json | jq -r '
  "\(.SourceMetadata.Data.Git.commit[0:8]) \(.DetectorName) \(.SourceMetadata.Data.Git.file)"'

gitleaks detect --source . --log-opts="--all" --report-format json
```

### Assessing distribution

Credentials delivered by hand cannot be rotated without coordination. Look for:

```bash
# Kubernetes — secrets mounted as static files vs sourced from a broker
kubectl get pods -A -o json | jq -r '
  .items[] | select(.spec.volumes[]?.secret != null)
  | "\(.metadata.namespace)/\(.metadata.name)"'

# CI — static credentials stored as repository secrets
gh api repos/:owner/:repo/actions/secrets --jq '.secrets[].name'
```

---

## Qualifying Criteria

A finding qualifies as **Tier 3 Secure Credential Management** if any apply,
**and** no credential is currently out of policy:

- [ ] Rotation is performed manually or driven by calendar reminder
- [ ] No automated alerting as credentials approach maximum age
- [ ] Provisioning and deprovisioning are ticket-driven rather than
      event-driven from the authoritative identity source
- [ ] Revocation depends on someone remembering, not on a leaver event
- [ ] Credentials distributed by hand (chat, email, shared documents)
- [ ] Static credentials used where workload identity or OIDC federation is
      available on the platform
- [ ] Secrets stored in CI configuration rather than retrieved from a broker
- [ ] No inventory mapping credentials to owners and purposes
- [ ] Shared credentials spanning multiple applications or people

---

## Remediation

### Phase 1 — Inventory and alerting (Days 1–30)

You cannot automate a population you have not enumerated. Build the inventory
first: credential, owner, purpose, consuming system, current rotation method.

**Alert before expiry**, so failures surface as warnings rather than outages:

```bash
aws cloudwatch put-metric-alarm \
  --alarm-name access-key-age-warning \
  --metric-name AccessKeyAge \
  --namespace Custom/IAM \
  --statistic Maximum \
  --period 86400 \
  --threshold 75 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 1 \
  --alarm-actions <sns-topic-arn>
```

### Phase 2 — Eliminate the credential (Days 30–60)

This is the highest-value step. Removing a stored secret removes rotation,
distribution, and leakage in one change.

**CI to cloud — replace static keys with OIDC federation:**

```yaml
# GitHub Actions — no stored AWS credentials at all
permissions:
  id-token: write
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::<acct>:role/github-deploy
          aws-region: us-east-1
          # no aws-access-key-id / aws-secret-access-key
```

```json
// Trust policy — scope to a specific repository and ref.
// Without the sub condition, any repository on GitHub can assume this role.
{
  "Effect": "Allow",
  "Principal": { "Federated": "arn:aws:iam::<acct>:oidc-provider/token.actions.githubusercontent.com" },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": {
      "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
      "token.actions.githubusercontent.com:sub": "repo:my-org/my-repo:ref:refs/heads/main"
    }
  }
}
```

**Workloads — use platform identity:**

```yaml
# EKS — IAM Roles for Service Accounts
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::<acct>:role/app-role
```

```yaml
# Azure — workload identity federation
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app
  annotations:
    azure.workload.identity/client-id: <client-id>
```

### Phase 3 — Automate what remains (Days 60–90)

For secrets that must exist — third-party API keys, database credentials for
systems without IAM integration — move them into a managed store with automatic
rotation.

```bash
aws secretsmanager rotate-secret \
  --secret-id prod/db/credentials \
  --rotation-lambda-arn arn:aws:lambda:us-east-1:<acct>:function:SecretsRotation \
  --rotation-rules AutomaticallyAfterDays=30
```

**Deliver secrets to workloads through the store, not through people:**

```yaml
# External Secrets Operator — application never sees a static credential
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: db-credentials
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secretsmanager
    kind: SecretStore
  target:
    name: db-credentials
  data:
    - secretKey: password
      remoteRef:
        key: prod/db/credentials
        property: password
```

**Automate provisioning and deprovisioning from the authoritative source**, so a
leaver event revokes access without a human step.

### Phase 4 — Prevent regression

```yaml
# Pre-commit — block the next occurrence rather than detecting it later
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks
```

Enable server-side push protection as well. Pre-commit hooks are advisory —
developers can bypass them, and the one time it matters, someone will.

---

## Verification

| Check | Evidence |
|-------|----------|
| Rotation is automatic for supported types | Secret store audit log showing unattended rotation |
| CI authenticates without stored credentials | Pipeline configuration with no cloud keys; successful federated run |
| Workloads use platform identity | Pod/function configuration showing identity binding |
| Leaver deprovisioning is automated | Simulated leaver event revokes access without manual action |
| No secrets in repository history | Full-history scan across all branches returns clean |
| Push protection active | Test push containing a synthetic secret is rejected |
| Every credential has an owner | Inventory export with owner and purpose populated |

---

## Exception Handling

Where a system genuinely cannot support automated rotation:

1. Record the system, the credential, and the technical constraint
2. Store the credential in the managed secret store regardless — centralized
   custody has value even without automated rotation
3. Apply the shortest practical manual rotation interval with a calendar owner
   **and** an automated age alert
4. Set a review date tied to the system's upgrade or decommissioning plan
5. Restrict the credential's privilege scope as a compensating control

---

## Monitoring Requirements

| Event | Action |
|-------|--------|
| Credential approaching maximum age | Warning to owner at 75% of interval |
| Automated rotation failed | Alert platform team; investigate before expiry |
| Secret retrieved from an unexpected principal | Investigate |
| New static credential created | Alert; verify federation was genuinely unavailable |
| Secret detected in a push | Block and alert |
| Credential with no owner tag | Weekly report |
| Access key created for a human user | Alert — humans should use federated sessions |

---

## References

- [NIST SP 800-63B — Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_CheatSheet.html)
- [AWS — IAM Roles for Service Accounts](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html)
- [GitHub — OIDC Hardening for Cloud Providers](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments)

---

## Related Findings

- [Secure Password Policies](secure-password-policies.md) — `BCN-T1-IAM-003`, Tier 1
- [High-Privilege Accounts](high-privilege-accounts.md) — `BCN-T1-IAM-002`, Tier 1
- [Regulatory IAM Compliance](regulatory-iam-compliance.md) — `BCN-T2-IAM-003`, Tier 2
- [RBAC](rbac.md) — `BCN-T3-IAM-001`, Tier 3

---

*For classification guidance, see [Classification Procedure](../CLASSIFICATION.md).
For scanner details, see [Scanners and Frameworks](../scanners-and-frameworks.md).*
