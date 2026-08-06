# Regulatory IAM Compliance

## Tier: 2 - Regulatory
**Beacon IDs:** `BCN-T2-IAM-001`, `BCN-T2-IAM-002`, `BCN-T2-IAM-003`
**MITRE ATT&CK:** [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)
**Remediation SLA:** 30 days
**Escalation:** Security manager review at 14 days

---

## Risk Description

Identity controls are the first thing an assessor tests, because they are
objectively verifiable from a configuration export. There is no interpretation
involved in reading a password policy or an access-review record — it either
meets the requirement or it does not, which is why IAM deficiencies are cited
more consistently than almost any other control area.

The consequence here is **regulatory, not immediate compromise**. Weak
authentication policy on the general user population does not put an attacker in
your network today; it puts a finding in your auditor's report and threatens the
certification your customers contract against. Missing MFA on *privileged*
accounts is a different matter entirely and belongs in Tier 1 — see
[Mandatory MFA](mandatory-mfa.md).

### Business Impact

| Outcome | Consequence |
|---------|-------------|
| Qualified SOC 2 opinion | Enterprise deals stall in procurement review |
| Failed PCI DSS assessment | Loss of card-processing capability; forensic audit costs |
| ISO 27001 non-conformity | Certification suspension pending corrective action |
| GDPR Art. 32 finding | Supervisory authority engagement; fines to 4% of global turnover |

### The compounding problem

Absence of access review is the mechanism by which privilege accumulates.
Without it, access granted for a temporary project persists for years and
eventually becomes [BCN-T1-IAM-002 — Excessive Standing Privilege](high-privilege-accounts.md).
Tier 2 governance gaps are how Tier 1 findings get manufactured.

---

## Scope of this finding

This document covers three distinct deficiencies. Record them separately —
remediating one does not close the others.

| ID | Finding | Core question |
|----|---------|---------------|
| `BCN-T2-IAM-001` | Non-compliant authentication policy | Do the settings meet the mandated minimums? |
| `BCN-T2-IAM-002` | Missing periodic access reviews | Can you evidence that access was certified? |
| `BCN-T2-IAM-003` | Ungoverned service accounts | Does every non-human identity have an owner? |

---

## Regulatory Requirements

| Framework | Control | Requirement |
|-----------|---------|-------------|
| **PCI DSS v4.0** | 8.3.6 | Minimum 12-character passwords with alphanumeric complexity |
| **PCI DSS v4.0** | 7.2.4 | Review user accounts and access privileges at least every 6 months |
| **PCI DSS v4.0** | 8.6.1 | Interactive use of system/service accounts is restricted and justified |
| **PCI DSS v4.0** | 8.2.1 | Unique ID for every user with access to system components |
| **SOC 2** | CC6.2 / CC6.3 | Access is registered, authorized, and periodically reviewed |
| **ISO/IEC 27001:2022** | A.5.18 | Access rights reviewed, provisioned, and revoked per policy |
| **ISO/IEC 27001:2022** | A.5.16 | Identity management across the full lifecycle |
| **HIPAA** | §164.308(a)(4) | Information access management; periodic review |
| **NIST SP 800-63B** | 5.1.1 | Memorized secret requirements — length over composition |
| **GDPR** | Art. 32 | Access appropriate to risk; demonstrable |

### A note on conflicting guidance

NIST SP 800-63B now **discourages** mandatory periodic rotation and composition
rules, on the evidence that both drive predictable user behavior. PCI DSS v4.0
continues to specify minimums.

Where a policy must satisfy both, **the stricter requirement applies**. In
practice this means: adopt PCI's length minimum, adopt NIST's position on
rotation (rotate on evidence of compromise, not on a calendar), and screen
against a breach corpus. Document the reasoning — assessors accept this, but
only when it is written down.

---

## Detection Methods

### Tools
- **[PROWLER](https://prowler.cloud/):** IAM compliance checks mapped to CIS, PCI DSS, and SOC 2
- **[Nessus](https://www.tenable.com/products/nessus):** Password policy auditing against regulatory baselines
- **[ScoutSuite](https://github.com/nccgroup/ScoutSuite):** Multi-cloud IAM posture review

### `BCN-T2-IAM-001` — Authentication policy

**AWS account password policy:**
```bash
aws iam get-account-password-policy \
  --query 'PasswordPolicy.{MinLength:MinimumPasswordLength,
                            Reuse:PasswordReusePrevention,
                            MaxAge:MaxPasswordAge,
                            Symbols:RequireSymbols,
                            Numbers:RequireNumbers}'

# PROWLER — full IAM compliance sweep against PCI DSS
prowler aws --compliance pci_dss_v4.0_aws --service iam
```

**Azure Entra ID — authentication methods and policy exemptions:**
```powershell
# Which authentication methods are enabled tenant-wide
Get-MgPolicyAuthenticationMethodPolicy |
  Select-Object -ExpandProperty AuthenticationMethodConfigurations |
  Format-Table Id, State

# Conditional access policies and, critically, their exclusions
Get-MgIdentityConditionalAccessPolicy |
  Select-Object DisplayName, State,
    @{n='ExcludedUsers';e={$_.Conditions.Users.ExcludeUsers.Count}},
    @{n='ExcludedGroups';e={$_.Conditions.Users.ExcludeGroups.Count}}
```

> Exclusions are where non-compliance concentrates. A policy that reports
> "enabled" while exempting three groups enforces nothing for those groups, and
> that is exactly what an assessor samples for.

### `BCN-T2-IAM-002` — Access reviews

The test is not technical. **Ask for the last completed review and its
evidence.** Inability to produce it *is* the finding.

```bash
# AWS — surface stale access as review input
aws iam generate-credential-report
aws iam get-credential-report --output text --query 'Content' | base64 -d | \
  awk -F, 'NR>1 {print $1", last used: "$5}'

# Identify roles unused for 90+ days
aws iam list-roles --query 'Roles[].RoleName' --output text | tr '\t' '\n' | \
  while read -r role; do
    last=$(aws iam get-role --role-name "$role" \
      --query 'Role.RoleLastUsed.LastUsedDate' --output text 2>/dev/null)
    [ "$last" = "None" ] && echo "UNUSED: $role"
  done
```

```powershell
# Entra ID — completed access review campaigns
Get-MgIdentityGovernanceAccessReviewDefinition |
  Select-Object DisplayName, Status, CreatedDateTime
```

**Sample the leaver process.** Take the last ten departures from HR records and
confirm access was revoked within the defined period. This replicates the
assessor's test exactly.

### `BCN-T2-IAM-003` — Service account governance

```bash
# AWS — users with access keys but no console login are typically service identities
aws iam list-users --query 'Users[].UserName' --output text | tr '\t' '\n' | \
  while read -r u; do
    keys=$(aws iam list-access-keys --user-name "$u" \
      --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text)
    profile=$(aws iam get-login-profile --user-name "$u" 2>/dev/null && echo yes || echo no)
    [ -n "$keys" ] && [ "$profile" = "no" ] && echo "SERVICE IDENTITY: $u"
  done
```

```powershell
# Entra ID — service principals with credentials and their expiry
Get-MgServicePrincipal -All |
  ForEach-Object {
    $creds = Get-MgServicePrincipalPasswordCredential -ServicePrincipalId $_.Id
    if ($creds) {
      [PSCustomObject]@{
        Name    = $_.DisplayName
        Owner   = (Get-MgServicePrincipalOwner -ServicePrincipalId $_.Id).AdditionalProperties.displayName
        Expires = $creds.EndDateTime
      }
    }
  } | Where-Object { -not $_.Owner }   # unowned identities are the finding
```

---

## Qualifying Criteria

A finding qualifies as **Tier 2 Regulatory IAM Compliance** if any apply:

**Authentication policy — `BCN-T2-IAM-001`**
- [ ] Password length below the mandated minimum for an in-scope framework
- [ ] No account lockout threshold configured
- [ ] Session timeout absent or exceeding the required maximum
- [ ] MFA not extended to the full population the standard names
- [ ] Policy exemptions exist without a documented, time-bounded justification
- [ ] Federated or guest identities fall outside the policy

**Access reviews — `BCN-T2-IAM-002`**
- [ ] No recurring review process defined
- [ ] Process exists but produces no retained evidence
- [ ] Review cadence exceeds the framework requirement (PCI: 6 months)
- [ ] Reviews exclude contractors, third parties, or non-human identities
- [ ] Leaver access not revoked within the defined period
- [ ] Orphaned accounts with no identifiable owner

**Service accounts — `BCN-T2-IAM-003`**
- [ ] Non-human identities without a named owner
- [ ] Service accounts with interactive sign-in capability
- [ ] Shared service accounts spanning multiple applications
- [ ] Service accounts excluded from the review cycle
- [ ] Dormant service accounts retaining live credentials

> **Do not record here:** a service account discovered to hold wildcard
> administrative privilege. That is [BCN-T1-IAM-002](high-privilege-accounts.md)
> and carries a 24–72 hour SLA. Keep this finding scoped to the *governance*
> gap.

---

## Remediation

### Phase 1 — Establish the baseline (Days 1–7)

1. **Export effective policy** from every identity provider. Not the intended
   policy — the effective one, including exemptions.
2. **Build the identity inventory**: human accounts, service accounts, workload
   identities, federated and guest identities. Governance cannot be applied to
   an unknown population.
3. **Map each in-scope framework** to its specific control requirement, and
   record where they conflict.

### Phase 2 — Close the policy gaps (Days 7–21)

**AWS — password policy meeting PCI DSS v4.0:**
```bash
aws iam update-account-password-policy \
  --minimum-password-length 14 \
  --require-symbols \
  --require-numbers \
  --require-uppercase-characters \
  --require-lowercase-characters \
  --password-reuse-prevention 4 \
  --allow-users-to-change-password
```

**Entra ID — remove standing exemptions:**
```powershell
# Replace blanket exclusions with a break-glass group of no more than two accounts
$policy = Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq 'Require MFA for all users'"
Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policy.Id -BodyParameter @{
    Conditions = @{
        Users = @{
            IncludeUsers  = @("All")
            ExcludeGroups = @("<break-glass-group-object-id>")
        }
    }
}
```

### Phase 3 — Operationalize review (Days 21–30)

| Access type | Cadence | Reviewer |
|-------------|---------|----------|
| Privileged / administrative | Quarterly | System owner + security |
| Standard user | Semi-annually (PCI) or annually | Line manager |
| Service accounts | Quarterly | Named technical owner |
| Third party / contractor | Quarterly, plus on contract change | Relationship owner |

**Automate campaign generation.** Manual reviews degrade after the first cycle —
this is reliably observed and is the reason the evidence is missing when the
assessor asks.

```powershell
# Entra ID — recurring quarterly review of privileged role assignments
New-MgIdentityGovernanceAccessReviewDefinition -BodyParameter @{
    displayName = "Quarterly privileged access review"
    scope = @{
        "@odata.type" = "#microsoft.graph.principalResourceMembershipsScope"
        principalScopes = @(@{ "@odata.type" = "#microsoft.graph.accessReviewQueryScope"
                               query = "/v1.0/users"; queryType = "MicrosoftGraph" })
    }
    settings = @{
        mailNotificationsEnabled     = $true
        justificationRequiredOnApproval = $true
        defaultDecisionEnabled       = $true
        defaultDecision              = "Deny"        # fail closed
        instanceDurationInDays       = 14
        recurrence = @{ pattern = @{ type = "absoluteMonthly"; interval = 3 } }
    }
}
```

> Set the default decision to **Deny**. A review that defaults to approve and is
> completed by inaction produces evidence without producing assurance, and a
> competent assessor will say so.

### Phase 4 — Govern non-human identities

1. Assign an accountable owner to every service account; decommission any
   identity with no owner after a defined notice period.
2. Replace shared accounts with per-application identities — rotation and
   revocation are impossible otherwise.
3. Migrate to platform-managed workload identity where supported (IAM roles for
   service accounts, workload identity federation), which removes the stored
   credential entirely.
4. Remove interactive sign-in capability from all service accounts.

---

## Verification

The finding is closed when **all** of the following hold:

| Check | Evidence |
|-------|----------|
| Policy meets every applicable requirement | Configuration export from each IdP, with exemptions explained |
| Enforcement is real, not just configured | Test account confirms rejection of a non-compliant password |
| Review campaign complete for the current period | Per-reviewer attestations with identity and timestamp |
| Sampled revocations applied | Target system confirms access removed for ten sampled leavers |
| Every non-human identity has an owner | Inventory export with owner and purpose populated |

---

## Exception Handling

Where a requirement genuinely cannot be met within 30 days:

1. Record the specific control and the technical blocker
2. Implement a compensating control (IP allowlisting, enhanced monitoring,
   shortened session lifetime)
3. Obtain compliance owner sign-off
4. Set a review date — **exceptions without expiry become permanent, which is
   itself a finding** under [regulatory processing compliance](../processing-protection/regulatory-processing-compliance.md)
5. Disclose the exception to the assessor rather than letting them find it

---

## Monitoring Requirements

| Event | Action |
|-------|--------|
| Conditional access policy modified | Alert security team; record in change log |
| Exemption group membership changed | Alert and require justification |
| Access review campaign overdue | Escalate to compliance owner |
| Service account created without owner tag | Block at provisioning, or alert |
| Privileged role assigned outside JIT | Immediate investigation |
| Leaver access still active after SLA | Daily report to IT operations |

---

## References

- [PCI DSS v4.0](https://www.pcisecuritystandards.org/document_library/)
- [NIST SP 800-63B: Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [ISO/IEC 27001:2022 Annex A](https://www.iso.org/standard/27001)
- [AICPA SOC 2 Trust Services Criteria](https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services)

---

## Related Findings

- [Mandatory MFA](mandatory-mfa.md) — `BCN-T1-IAM-001`, Tier 1
- [High-Privilege Accounts](high-privilege-accounts.md) — `BCN-T1-IAM-002`, Tier 1
- [Secure Credential Management](secure-credential-management.md) — `BCN-T3-IAM-002`, Tier 3
- [RBAC](rbac.md) — `BCN-T3-IAM-001`, Tier 3

---

*For classification guidance, see [Classification Procedure](../CLASSIFICATION.md).
For scanner details, see [Scanners and Frameworks](../scanners-and-frameworks.md).*
