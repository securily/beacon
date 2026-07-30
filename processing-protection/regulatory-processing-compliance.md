# Regulatory Processing Compliance

## Tier: 2 - Regulatory
**Beacon IDs:** `BCN-T2-PRC-001`, `BCN-T2-PRC-002`, `BCN-T2-PRC-003`
**MITRE ATT&CK:** [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/), [T1195 - Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/)
**Remediation SLA:** 30 days
**Escalation:** Security manager review at 14 days

---

## Risk Description

This finding covers the **processes** that govern compute, rather than the state
of any individual system. Vulnerability management, change control, and incident
response are all explicitly mandated, all tested by sampling, and all cited
routinely — because an assessor can ask for evidence and either receive it or
not.

The critical insight is that a process gap is not itself an exposure. It is the
**mechanism by which Tier 1 findings go undetected**. An asset class excluded
from scanning produces no findings and therefore looks clean. A change that
bypasses the pipeline introduces the misconfiguration nobody reviewed. An
untested incident response plan reveals its gaps during the incident.

That is why these sit at Tier 2 rather than Tier 3: they are not urgent in
themselves, but they systematically manufacture urgency elsewhere.

### Business Impact

| Outcome | Consequence |
|---------|-------------|
| Qualified SOC 2 opinion on CC7 / CC8 | Enterprise procurement stalls |
| PCI DSS Requirement 11 failure | Loss of card-processing capability |
| Missed GDPR 72-hour notification | Regulatory penalty independent of the breach itself |
| Unscanned asset class | Tier 1 exposure that no one is aware of |
| No tested IR plan | Notification deadlines missed during a live incident |

---

## Scope of this finding

| ID | Finding | Core question |
|----|---------|---------------|
| `BCN-T2-PRC-001` | Vulnerability management process gaps | Does scanning actually cover every asset, with measured SLAs? |
| `BCN-T2-PRC-002` | Change management control gaps | Can you evidence review and approval for production changes? |
| `BCN-T2-PRC-003` | Untested incident response capability | Has the plan been exercised, and can you prove it? |

---

## Regulatory Requirements

| Framework | Control | Requirement |
|-----------|---------|-------------|
| **PCI DSS v4.0** | 11.3.1 / 11.3.2 | Internal and external vulnerability scans at least quarterly and after significant change |
| **PCI DSS v4.0** | 6.3.3 | Critical security patches installed within one month of release |
| **PCI DSS v4.0** | 6.5.1 | Documented change control procedures for all system changes |
| **PCI DSS v4.0** | 12.10.1 / 12.10.2 | Incident response plan, tested at least annually |
| **SOC 2** | CC7.1 | Vulnerabilities identified, evaluated, and remediated |
| **SOC 2** | CC7.4 / CC7.5 | Incident response and recovery procedures |
| **SOC 2** | CC8.1 | Changes authorised, designed, tested, approved, and implemented |
| **ISO/IEC 27001:2022** | A.8.8 | Management of technical vulnerabilities |
| **ISO/IEC 27001:2022** | A.8.32 | Change management |
| **ISO/IEC 27001:2022** | A.5.24 / A.5.25 | Incident management planning and assessment |
| **GDPR** | Art. 33 | Breach notification within 72 hours of awareness |
| **HIPAA** | §164.308(a)(6) | Security incident procedures |
| **NIST CSF 2.0** | ID.RA-01, RS.MA, RC.RP | Risk identification, response management, recovery |

---

## Detection Methods

### Tools
- **[PROWLER](https://prowler.cloud/):** Compliance frameworks mapped to cloud configuration
- **[Nessus](https://www.tenable.com/products/nessus) / [Qualys](https://www.qualys.com/):** Authenticated vulnerability scanning
- **[Trivy](https://trivy.dev/):** Container image and IaC scanning — the classic coverage gap
- **CloudTrail / Azure Activity Log:** Change provenance

### `BCN-T2-PRC-001` — Vulnerability management coverage

**The test is a reconciliation, not a scan.** Compare the scanned inventory
against the authoritative asset inventory; the difference is the finding.

```bash
# Authoritative inventory across regions
aws ec2 describe-instances \
  --query 'Reservations[].Instances[].{ID:InstanceId,Name:Tags[?Key==`Name`]|[0].Value}' \
  --output text | sort > /tmp/assets.txt

# Compare against your scanner's asset list
comm -23 /tmp/assets.txt /tmp/scanned.txt   # unscanned assets = the gap
```

Asset classes structurally excluded from scanning, in rough order of how often
they are missed:

| Asset class | Why it is missed | Coverage tool |
|-------------|------------------|---------------|
| Container images | No persistent host for an agent | Trivy, Grype in CI |
| Serverless functions | Ephemeral; no host | Dependency scanning at build |
| Network appliances | No agent support | Authenticated network scan |
| Managed services (RDS, ElastiCache) | Provider-managed | Cloud posture management |
| OT / embedded | Fragile under active scanning | Passive discovery |
| Ephemeral CI runners | Exist for minutes | Image scanning pre-publish |

**Measure attainment, not policy.** A stated SLA with no measurement is not a
control:

```sql
-- Time-to-remediate by severity for the current period
SELECT severity,
       COUNT(*)                                              AS findings,
       ROUND(AVG(closed_at::date - discovered_at::date), 1)  AS avg_days,
       SUM(CASE WHEN closed_at::date - discovered_at::date > sla_days
                THEN 1 ELSE 0 END)                           AS breached
FROM   findings
WHERE  closed_at >= NOW() - INTERVAL '90 days'
GROUP  BY severity;
```

### `BCN-T2-PRC-002` — Change management

Sample recent production changes and try to produce the required evidence for
each. This replicates the assessor's test exactly.

```bash
# Console-originated changes that bypassed the pipeline
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=RunInstances \
  --start-time "$(date -u -v-30d '+%Y-%m-%dT%H:%M:%SZ')" \
  --query 'Events[].{Time:EventTime,User:Username,Source:CloudTrailEvent}' \
  --output json | jq -r '.[] | select(.Source | fromjson.userAgent
                          | test("console|signin") ) | .Time + " " + .User'
```

```bash
# Does branch protection actually enforce review — including for admins?
gh api repos/:owner/:repo/branches/main/protection \
  --jq '{reviews: .required_pull_request_reviews.required_approving_review_count,
         enforce_admins: .enforce_admins.enabled,
         dismiss_stale: .required_pull_request_reviews.dismiss_stale_reviews}'
```

> `enforce_admins: false` means the control is advisory. Assessors ask for this
> specific setting.

### `BCN-T2-PRC-003` — Incident response

Not a technical test. **Ask for the plan and its last test record.** Either
being absent is the finding.

Check that the plan actually contains:

- [ ] Severity definitions with concrete thresholds
- [ ] Named roles, with current contact details
- [ ] Regulatory notification deadlines **per applicable regime and jurisdiction**
- [ ] Cloud and SaaS scenarios, not only on-premises
- [ ] Pre-arranged forensics and legal retainers
- [ ] Evidence-preservation procedure

---

## Qualifying Criteria

**Vulnerability management — `BCN-T2-PRC-001`**
- [ ] No documented scanning cadence, or cadence below the framework requirement
- [ ] Scanned inventory does not reconcile to the asset inventory
- [ ] Asset classes structurally excluded from scanning
- [ ] Remediation timeframes undefined by severity
- [ ] SLA attainment not measured or reported
- [ ] No formal risk-acceptance path
- [ ] Exceptions without owner, expiry, or compensating control

**Change management — `BCN-T2-PRC-002`**
- [ ] Production changes without recorded review or approval
- [ ] Branch protection not enforced for administrators
- [ ] No separation between change author and production deployer
- [ ] Console changes bypassing the pipeline
- [ ] No emergency change path (so urgent changes go undocumented)
- [ ] No rollback plan recorded

**Incident response — `BCN-T2-PRC-003`**
- [ ] No documented incident response plan
- [ ] Plan not tested within the required period
- [ ] Notification deadlines absent for an applicable regime
- [ ] Contact details or escalation paths stale
- [ ] No cloud or SaaS incident scenarios
- [ ] No post-incident review process

---

## Remediation

### Phase 1 — Vulnerability management (Days 1–14)

**Document the programme.** Scope, cadence, severity definitions, remediation
timeframes, and the exception path.

| Beacon tier | Remediation SLA | Framework alignment |
|-------------|-----------------|---------------------|
| Tier 1 | 24–72 hours | Exceeds PCI 6.3.3 |
| Tier 2 | 30 days | PCI 6.3.3 (one month) |
| Tier 3 | 90 days | Best practice |

**Close the coverage gaps:**

```yaml
# Container scanning in CI — closes the most common gap
- name: Scan image
  uses: aquasecurity/trivy-action@master
  with:
    image-ref: ${{ env.IMAGE }}
    format: sarif
    output: trivy-results.sarif
    severity: CRITICAL,HIGH
    exit-code: '1'          # fail the build; reporting alone is not a control
```

**Formalise risk acceptance.** Every exception needs a named approver, an expiry
date, and a compensating control. Perpetual undocumented exceptions are
themselves a finding.

```yaml
exception:
  finding_id:    BCN-T1-PRC-001
  asset:         legacy-appliance-01
  justification: Vendor patch pending; EOL scheduled Q3
  compensating:  Isolated VLAN, no internet route, enhanced monitoring
  approver:      <CISO>
  approved:      2026-07-01
  expires:       2026-10-01     # never open-ended
  review:        monthly
```

### Phase 2 — Change management (Days 14–25)

1. **Route all production change through the pipeline.** Remove standing console
   write access and replace it with just-in-time elevation.
2. **Enforce branch protection including for administrators.**
3. **Capture evidence automatically** as pipeline artefacts rather than as
   manual records — manual evidence collection fails silently.
4. **Define an emergency change path** with retrospective review, so urgent
   changes have a compliant route instead of an ad-hoc one.

```bash
gh api -X PUT repos/:owner/:repo/branches/main/protection \
  -f "required_pull_request_reviews[required_approving_review_count]=1" \
  -f "required_pull_request_reviews[dismiss_stale_reviews]=true" \
  -F "enforce_admins=true" \
  -f "required_status_checks[strict]=true"
```

```bash
# Alert on control-plane changes originating outside the pipeline
aws events put-rule --name detect-console-infra-change \
  --event-pattern '{
    "source": ["aws.ec2","aws.rds","aws.iam"],
    "detail": {
      "userIdentity": { "type": ["IAMUser","AssumedRole"] },
      "eventName": [{"anything-but": ["Describe*","List*","Get*"]}]
    }}'
```

### Phase 3 — Incident response (Days 25–30)

**Document the plan**, then **test it** — the test is what both the framework
and reality require.

| Severity | Definition | Response | Notification |
|----------|-----------|----------|--------------|
| **SEV-1** | Confirmed breach of regulated data; ransomware | Immediate war room | Legal + regulator clock starts |
| **SEV-2** | Confirmed compromise, no data exfiltration | 1 hour | Executive notification |
| **SEV-3** | Suspected compromise under investigation | 4 hours | Security leadership |
| **SEV-4** | Policy violation, no compromise | Next business day | Standard ticket |

**Notification deadlines to encode in the plan:**

| Regime | Deadline | Trigger |
|--------|----------|---------|
| GDPR | 72 hours | Awareness of a personal data breach |
| HIPAA | 60 days | Discovery of a breach of unsecured PHI |
| PCI DSS | Immediate | Suspected account data compromise |
| SEC (public cos.) | 4 business days | Determination of materiality |
| US state laws | Varies | Consult counsel per jurisdiction |

Run a tabletop against a realistic scenario — ransomware and cloud account
compromise deliver the most value. Record participants, findings, and the
resulting plan updates. **The update record is the evidence assessors want.**

---

## Verification

| Check | Evidence |
|-------|----------|
| Scan coverage reconciles to inventory | Reconciliation report with documented exclusions |
| SLA attainment measured | Report by severity for the current period |
| Exceptions governed | Register showing owner, compensating control, future expiry |
| Change evidence retrievable | Ten sampled changes each producing review, approval, testing artefacts |
| No unaccounted direct changes | Control-plane log analysis for the period |
| IR plan current and tested | Plan with deadlines, plus a test record within the required period |
| Post-test improvements applied | Change record showing plan updates after the exercise |

---

## Exception Handling

Where a process requirement cannot be met within 30 days:

1. Identify the specific control and the constraint
2. Implement an interim manual process with retained evidence — manual is
   acceptable to assessors; *undocumented* is not
3. Obtain compliance owner approval
4. Set a review date and a target for automation
5. Disclose in the assessment rather than waiting to be found

---

## Monitoring Requirements

| Event | Action |
|-------|--------|
| Scheduled scan failed or skipped | Alert vulnerability management owner |
| New asset without scanner coverage after 24h | Alert and auto-enrol |
| Tier 1 finding past SLA | Executive escalation |
| Exception past review date | Daily report to compliance owner |
| Production change outside pipeline | Alert and require retrospective justification |
| Branch protection modified | Immediate alert |
| IR plan test overdue | Quarterly escalation |

---

## References

- [PCI DSS v4.0](https://www.pcisecuritystandards.org/document_library/)
- [NIST SP 800-61r2 — Computer Security Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [NIST SP 800-40r4 — Enterprise Patch Management](https://csrc.nist.gov/publications/detail/sp/800-40/rev-4/final)
- [ISO/IEC 27001:2022 Annex A](https://www.iso.org/standard/27001)
- [GDPR Article 33 — Notification of a Personal Data Breach](https://gdpr-info.eu/art-33-gdpr/)

---

## Related Findings

- [Unprotected External Exposure](unprotected-external-exposure.md) — `BCN-T1-PRC-002`, Tier 1
- [DDoS Protection](ddos-protection.md) — `BCN-T1-PRC-003`, Tier 1
- [Processing Security Best Practices](processing-security-best-practices.md) — Tier 3

---

*For classification guidance, see [Classification Procedure](../CLASSIFICATION.md).
For scanner details, see [Scanners and Frameworks](../scanners-and-frameworks.md).*
