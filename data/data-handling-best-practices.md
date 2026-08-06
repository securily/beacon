# Data Handling Best Practices

## Tier: 3 - Best Practices
**Beacon IDs:** `BCN-T3-DAT-001`, `BCN-T3-DAT-002`, `BCN-T3-DAT-003`
**MITRE ATT&CK:** [T1048 - Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/), [T1490 - Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
**Remediation SLA:** 90 days
**Escalation:** Quarterly planning review

---

## Risk Description

Defense-in-depth for data: the controls that reduce blast radius and preserve
recoverability once the preventive controls have already failed.

None of these is urgent in isolation, and each requires substantial tuning to
deploy without disrupting legitimate work — which is exactly the Tier 3 profile.
The returns are real but gradual, and they are realized at the worst moment
rather than during normal operation.

### Scope of this finding

| ID | Finding | What it buys you |
|----|---------|------------------|
| `BCN-T3-DAT-001` | No data loss prevention coverage | Catches inadvertent disclosure and low-sophistication insider exfiltration |
| `BCN-T3-DAT-002` | Unverified backup restoration | The difference between recovery and paying a ransom |
| `BCN-T3-DAT-003` | Database configuration hardening | Limits what a partial compromise yields |

---

## `BCN-T3-DAT-001` — Data Loss Prevention

### What DLP actually does

DLP addresses **inadvertent disclosure and casual insider exfiltration**. It
does not stop a determined attacker — encrypted channels, staged exfiltration,
and simple encoding defeat it comfortably.

Positioning DLP as an anti-breach control leads to over-investment here relative
to Tier 1 work, which is a substantially worse outcome than not deploying it at
all. Deploy it for what it is: a control against the accidental send and the
departing employee with a USB stick.

| Threat | DLP effectiveness |
|--------|-------------------|
| Wrong recipient on an email | High |
| Bulk download before resignation | Moderate — detects volume anomalies |
| Regulated data in a public support ticket | High |
| Determined attacker with encryption | Low |
| Compromised credential exfiltrating over TLS to a cloud service | Low |

### Detection

```bash
# Are alerts actually reviewed, or merely generated?
# A monitor-only deployment nobody reads is functionally no coverage.
aws macie2 list-findings --max-results 50 \
  --finding-criteria '{"criterion":{"archived":{"eq":["false"]}}}' \
  --query 'findingIds' --output text | wc -l
```

**The practical test:** send a benign marker file resembling regulated data
through each channel and see whether anything happens.

```
Test artifact:  synthetic PAN 4111 1111 1111 1111 (a known test number)

Channel                          Detected?   Enforced?
─────────────────────────────────────────────────────
Corporate email → external          ?           ?
Cloud storage → public link         ?           ?
Endpoint → USB                      ?           ?
Collaboration platform → guest      ?           ?
Personal webmail via browser        ?           ?
```

Any channel where the answer is "no" is uncovered, regardless of what the vendor
console reports.

### Qualifying Criteria

- [ ] No DLP capability on any channel
- [ ] Coverage on some channels but not others (email covered, endpoint not)
- [ ] Deployed in monitor-only mode indefinitely with no enforcement plan
- [ ] Alerts generated but no named triage owner
- [ ] Detection rules are vendor defaults, not matched to the data you hold
- [ ] Rules not aligned to the classification scheme from `BCN-T2-DAT-003`

### Remediation

1. **Start with the highest-volume channel** — usually email or a single
   collaboration platform. Estate-wide rollouts stall.
2. **Monitor first, tune against real traffic, then enforce.** Enforcing untuned
   policy generates disruption and erodes organizational support for the whole
   program; recovering that support is harder than the original deployment.
3. **Align rules to your classification scheme** rather than generic patterns.
4. **Route alerts to a named owner** with a defined triage process.
5. Extend to further channels once the first enforces cleanly.

```yaml
# Policy shape — tie enforcement to classification, not to regex alone
policy:
  name: restricted-data-egress
  applies_to:
    classification: Restricted        # from BCN-T2-DAT-003
  channels: [email, cloud_storage, endpoint_removable]
  detection:
    - type: credit_card               # validated by Luhn, not pattern alone
      confidence: high
      count_threshold: 5
    - type: custom_regex
      pattern: 'ACCT-[0-9]{8}'        # your identifiers, not the vendor's
  actions:
    - block
    - notify_sender_with_reason       # education reduces recurrence
    - alert_security
  exceptions:
    - group: finance-approved-senders
      requires: justification
```

---

## `BCN-T3-DAT-002` — Backup Restoration Verification

### The core problem

**An untested backup is an assumption, not a control.**

Backup jobs report success. Restoration is what fails — and it fails at the
worst possible moment, for reasons that were discoverable at any point
beforehand: incomplete application state, missing encryption keys, recovery
times far exceeding the stated objective, or backups encrypted along with
production because they were reachable with production credentials.

Modern ransomware operators target backup infrastructure **first and
specifically**. Immutability is the control that determines whether you recover
or negotiate.

### Detection

```bash
# Are backups reachable with production credentials? If so, ransomware reaches them too.
aws s3api get-object-lock-configuration --bucket backup-bucket 2>/dev/null \
  || echo "NO OBJECT LOCK — backups are mutable"

aws backup list-backup-vaults \
  --query 'BackupVaultList[].{Name:BackupVaultName,Locked:Locked,
                              MinRetention:MinRetentionDays}' --output table
```

```bash
# Is the restoration key itself recoverable independently of the system being restored?
aws kms describe-key --key-id alias/backup-key \
  --query 'KeyMetadata.{State:KeyState,Manager:KeyManager,
                        Rotation:KeyRotationEnabled}'
```

**Ask for the last successful restoration test.** Job success reports are not
evidence of recoverability, and treating them as such is the finding.

### Qualifying Criteria

- [ ] No restoration test performed within the defined period
- [ ] Restoration never tested end to end for a critical system
- [ ] No immutable or logically-isolated copy
- [ ] Backup infrastructure reachable with production credentials
- [ ] Encryption keys required for restoration are not independently recoverable
- [ ] Actual restoration time unmeasured, or exceeds the recovery objective
- [ ] Backup scope excludes configuration, IaC state, or secrets needed to rebuild

> **Escalate:** a critical system with **no backup at all** is not Tier 3. That
> is an immediate business-continuity exposure — escalate it rather than
> scheduling it on a 90-day clock.

### Remediation

**Implement immutability first.** It is the single change that most affects
outcome.

```bash
# S3 Object Lock in compliance mode — cannot be overridden, including by root
aws s3api put-object-lock-configuration \
  --bucket backup-bucket \
  --object-lock-configuration '{
    "ObjectLockEnabled":"Enabled",
    "Rule":{"DefaultRetention":{"Mode":"COMPLIANCE","Days":30}}}'

# AWS Backup Vault Lock
aws backup put-backup-vault-lock-configuration \
  --backup-vault-name prod-vault \
  --min-retention-days 30 \
  --max-retention-days 365 \
  --changeable-for-days 3
```

> `COMPLIANCE` mode cannot be shortened or deleted by any principal, including
> the account root, for the retention period. `GOVERNANCE` mode can be
> overridden with a specific permission — which means an attacker who obtains
> that permission can delete your backups. Use `COMPLIANCE` for anything you
> would need after a full account compromise.

**Isolate backup credentials from the production identity plane**, so that
compromising production does not grant the ability to delete backups.

**Test restoration properly** — into an isolated environment, timed, end to end:

```bash
# Restore into an isolated VPC, measure elapsed time, validate integrity
START=$(date +%s)
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier restore-test-$(date +%Y%m%d) \
  --db-snapshot-identifier prod-snapshot-latest \
  --db-subnet-group-name isolated-restore-subnet \
  --no-publicly-accessible

aws rds wait db-instance-available \
  --db-instance-identifier restore-test-$(date +%Y%m%d)
echo "Restoration completed in $(( ($(date +%s) - START) / 60 )) minutes"
```

Then **validate the restored data**, not just the instance state:

```sql
SELECT COUNT(*) AS row_count, MAX(created_at) AS most_recent
FROM   critical_table;
-- Compare against production. A restored instance with stale or partial
-- data is a failed test, even though the restore "succeeded".
```

Record the elapsed time against the recovery objective. **Treat a failed test as
a finding**, not as a completed exercise.

---

## `BCN-T3-DAT-003` — Database Configuration Hardening

### Why it matters

These settings determine how much an attacker gains from a **partial**
compromise:

| Setting | What it costs you when wrong |
|---------|------------------------------|
| Verbose client errors | Accelerates injection exploitation by revealing schema |
| Audit logging disabled | No record of what was accessed during an incident |
| Unnecessary extensions | Privilege escalation paths (`xp_cmdshell`, untrusted PLs) |
| Sample schemas retained | Known-credential entry points |
| Superuser used by applications | A single SQL injection reaches everything |

None is exploitable alone. All of them reduce the effort required once
[BCN-T1-DAT-001](critical-database-protection-issues.md) is exploited.

### Detection

```bash
# CIS Benchmark assessment for the specific engine and version
oscap xccdf eval --profile cis \
  --results db-hardening-results.xml \
  ssg-postgresql-ds.xml
```

```sql
-- PostgreSQL — error verbosity, logging, and dangerous extensions
SHOW log_error_verbosity;      -- 'terse' for client-facing
SHOW log_statement;            -- 'ddl' or 'mod' minimum
SHOW log_connections;

SELECT extname FROM pg_extension
WHERE  extname NOT IN ('plpgsql');   -- justify each remaining extension

-- Application roles must not be superusers
SELECT rolname, rolsuper, rolcreaterole, rolcreatedb
FROM   pg_roles WHERE rolsuper = true;
```

```sql
-- MySQL
SHOW VARIABLES LIKE 'general_log';
SHOW VARIABLES LIKE 'local_infile';       -- should be OFF
SELECT user, host FROM mysql.user WHERE authentication_string = '';
```

### Qualifying Criteria

- [ ] Benchmark pass rate below target for the engine
- [ ] Detailed error messages returned to clients
- [ ] Audit logging disabled or not forwarded to central storage
- [ ] Sample schemas or default accounts retained
- [ ] Unnecessary extensions or stored procedures enabled
- [ ] Applications connecting as a superuser
- [ ] Hardened configuration not encoded in the provisioning template

### Remediation

**Apply the benchmark to a non-production instance first** to identify
application breakage before touching production. Skipping this step is how
hardening work gets abandoned after the first outage.

```ini
# postgresql.conf
log_error_verbosity = terse          # detail stays server-side
log_statement = 'ddl'
log_connections = on
log_disconnections = on
log_line_prefix = '%m [%p] %q%u@%d '
shared_preload_libraries = 'pgaudit'
pgaudit.log = 'write,ddl,role'
```

```sql
-- Least-privilege application role
CREATE ROLE app_user LOGIN PASSWORD '<from-secret-store>';
GRANT CONNECT ON DATABASE appdb TO app_user;
GRANT USAGE  ON SCHEMA public   TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_user;
REVOKE CREATE ON SCHEMA public FROM app_user;   -- no DDL from the app
```

**Encode it in the provisioning template** so new instances inherit the hardened
configuration:

```hcl
resource "aws_db_parameter_group" "hardened" {
  family = "postgres16"

  parameter { name = "log_statement"        value = "ddl" }
  parameter { name = "log_connections"      value = "1"   }
  parameter { name = "log_error_verbosity"  value = "terse" }
  parameter { name = "rds.force_ssl"        value = "1"   }
}
```

> Benchmark output routinely includes genuine Tier 1 items — public
> accessibility, absent authentication, default credentials still active. Triage
> each item individually. **The report's own severity ratings are not Beacon
> tiers.**

---

## Verification

| Finding | Check | Evidence |
|---------|-------|----------|
| `BCN-T3-DAT-001` | Marker file blocked on each covered channel | Alert reaching the triage owner, per channel |
| `BCN-T3-DAT-002` | Critical system restored within objective | Timed test record with data validation |
| `BCN-T3-DAT-002` | Backups survive credential compromise | Object Lock in COMPLIANCE mode; deletion attempt denied |
| `BCN-T3-DAT-003` | Benchmark target met | Assessment report with documented exceptions |
| `BCN-T3-DAT-003` | Errors reveal no schema detail | Client-side error output from a malformed query |
| `BCN-T3-DAT-003` | Audit events centralized | Sampled event retrievable from central log storage |

---

## Monitoring Requirements

| Event | Action |
|-------|--------|
| DLP policy disabled or modified | Alert security team |
| Bulk download exceeding baseline | Investigate; correlate with HR events |
| Backup job failed | Alert; failures on consecutive days are an incident |
| Object Lock configuration changed | Critical alert — a known ransomware precursor |
| Restoration test overdue | Quarterly escalation |
| Database audit logging disabled | Critical alert |
| New database extension installed | Review at next change window |

---

## References

- [NIST SP 800-34 — Contingency Planning Guide](https://csrc.nist.gov/publications/detail/sp/800-34/rev-1/final)
- [CISA — Ransomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
- [ISO/IEC 27001:2022 A.8.12 — Data Leakage Prevention](https://www.iso.org/standard/27001)

---

## Related Findings

- [Database Security](database-security.md) — `BCN-T1-DAT-002`, Tier 1
- [Critical Database Protection Issues](critical-database-protection-issues.md) — `BCN-T1-DAT-001`, Tier 1
- [Regulatory Data Compliance](regulatory-data-compliance.md) — `BCN-T2-DAT-001`, Tier 2

---

*For classification guidance, see [Classification Procedure](../CLASSIFICATION.md).
For scanner details, see [Scanners and Frameworks](../scanners-and-frameworks.md).*
