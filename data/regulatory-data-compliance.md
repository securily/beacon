# Regulatory Data Compliance

## Tier: 2 - Regulatory
**Beacon IDs:** `BCN-T2-DAT-001`, `BCN-T2-DAT-002`, `BCN-T2-DAT-003`
**MITRE ATT&CK:** [T1040 - Network Sniffing](https://attack.mitre.org/techniques/T1040/), [T1213 - Data from Information Repositories](https://attack.mitre.org/techniques/T1213/)
**Remediation SLA:** 30 days
**Escalation:** Security manager review at 14 days

---

## Risk Description

Data protection is where regulation has the sharpest teeth. Encryption
requirements, retention limits, and classification obligations are written
explicitly into PCI DSS, HIPAA, and GDPR, and they are tested directly rather
than inferred.

The distinguishing property of Tier 2 data findings is that **the data is
protected, but not to the standard you are legally or contractually held to**.
Absent encryption on a reachable store is Tier 1 — see
[Database Security](database-security.md). Encryption present but using a
deprecated cipher, or with keys stored beside the data, is Tier 2: real
protection, non-conforming implementation.

That distinction carries money. Most breach-notification regimes offer a safe
harbour for **properly** encrypted data. Encryption that does not meet the
standard generally does not qualify, which means the same incident becomes
notifiable — with the disclosure costs, regulatory engagement, and reputational
consequence that follow.

### Business Impact

| Outcome | Consequence |
|---------|-------------|
| Breach safe harbour forfeited | Notification obligation triggers on an otherwise contained incident |
| GDPR Art. 32 / Art. 5 finding | Fines to €20M or 4% of global turnover |
| PCI DSS Requirement 3 failure | Loss of card-processing capability |
| HIPAA Security Rule violation | Civil monetary penalties per record, per year |
| Unfulfilled erasure request | Supervisory authority complaint with individual standing |

---

## Scope of this finding

| ID | Finding | Core question |
|----|---------|---------------|
| `BCN-T2-DAT-001` | Encryption below regulatory standard | Is the algorithm, key length, and key custody conforming? |
| `BCN-T2-DAT-002` | Retention and deletion non-compliance | Are you still holding data you have no lawful basis to hold? |
| `BCN-T2-DAT-003` | Absent data classification | Can you state where regulated data actually lives? |

Record these separately. They have different owners and different remediation
paths.

---

## Regulatory Requirements

| Framework | Control | Requirement |
|-----------|---------|-------------|
| **PCI DSS v4.0** | 3.5.1 | PAN rendered unreadable wherever stored |
| **PCI DSS v4.0** | 3.6 / 3.7 | Documented key-management lifecycle; split knowledge and dual control |
| **PCI DSS v4.0** | 3.2.1 | Retain account data only as long as necessary; documented retention policy |
| **PCI DSS v4.0** | 4.2.1 | Strong cryptography for transmission over open networks |
| **GDPR** | Art. 32(1)(a) | Encryption and pseudonymisation appropriate to risk |
| **GDPR** | Art. 5(1)(e) | Storage limitation — kept no longer than necessary |
| **GDPR** | Art. 17 | Right to erasure, across all copies |
| **GDPR** | Art. 30 | Records of processing activities |
| **HIPAA** | §164.312(a)(2)(iv) | Encryption and decryption of ePHI |
| **HIPAA** | §164.312(e)(1) | Transmission security |
| **ISO/IEC 27001:2022** | A.8.24 | Use of cryptography per policy |
| **ISO/IEC 27001:2022** | A.5.12 | Classification of information |

---

## Approved Cryptography

| Use | Acceptable | Deprecated — treat as a finding |
|-----|-----------|--------------------------------|
| Symmetric encryption | AES-256, AES-128 (GCM/CBC) | 3DES, RC4, DES, Blowfish |
| Asymmetric | RSA ≥ 2048, ECC P-256 or better | RSA < 2048, DSA-1024 |
| Hashing | SHA-256, SHA-384, SHA-512 | MD5, SHA-1 |
| Password storage | Argon2id, scrypt, bcrypt, PBKDF2 (high iteration) | Unsalted hashes, single-round SHA |
| Transport | TLS 1.2 (strong suites), TLS 1.3 | TLS 1.0, TLS 1.1, SSLv2, SSLv3 |

**Key custody matters as much as the algorithm.** Keys held in the same system,
account, or backup as the data they protect provide substantially less assurance
than the configuration implies — a compromise that reaches the data reaches the
keys. Assessors increasingly test for this specifically.

---

## Detection Methods

### Tools
- **[testssl.sh](https://testssl.sh/):** Protocol version and cipher suite enumeration
- **[PROWLER](https://prowler.cloud/):** Cloud encryption posture and KMS configuration
- **[Cloudsploit](https://cloudsploit.com/):** Data compliance checks across cloud providers
- **[Nessus](https://www.tenable.com/products/nessus):** Cryptographic configuration auditing
- **AWS Macie / Azure Purview:** Automated sensitive-data discovery

### `BCN-T2-DAT-001` — Encryption conformance

```bash
# Full TLS posture for an endpoint — protocols, ciphers, certificate strength
testssl.sh --protocols --cipher-per-proto --severity MEDIUM https://app.example.com

# AWS — RDS instances without encryption, or using an AWS-managed key
# where policy requires a customer-managed key
aws rds describe-db-instances \
  --query 'DBInstances[].{ID:DBInstanceIdentifier,
                           Encrypted:StorageEncrypted,
                           Key:KmsKeyId}' --output table

# Snapshots are the most commonly missed category
aws rds describe-db-snapshots --snapshot-type manual \
  --query 'DBSnapshots[?Encrypted==`false`].DBSnapshotIdentifier'

aws ec2 describe-snapshots --owner-ids self \
  --query 'Snapshots[?Encrypted==`false`].{ID:SnapshotId,Vol:VolumeId,Started:StartTime}'
```

```bash
# Key rotation evidence — assessors ask for this, not for the setting
aws kms list-keys --query 'Keys[].KeyId' --output text | tr '\t' '\n' | \
  while read -r k; do
    rot=$(aws kms get-key-rotation-status --key-id "$k" \
      --query 'KeyRotationEnabled' --output text 2>/dev/null)
    [ "$rot" = "False" ] && echo "NO ROTATION: $k"
  done
```

### `BCN-T2-DAT-002` — Retention and deletion

The decisive test is a **traced deletion**. Issue a test data-subject erasure
request and follow it end to end. Incompleteness is always found downstream:

```
Primary database        ✔ deleted
Read replica            ✔ propagated
Analytics warehouse     ✘ still present      <- the finding
Search index            ✘ still present      <- the finding
Backup set              ✘ retained 90 days   <- needs documented approach
Log aggregation         ✘ PII in log lines   <- the finding
Third-party processor   ? unconfirmed        <- the finding
```

```sql
-- Identify data past its retention period
SELECT table_name,
       COUNT(*)        AS rows_beyond_retention,
       MIN(created_at) AS oldest_record
FROM   customer_records
WHERE  created_at < NOW() - INTERVAL '7 years'
GROUP  BY table_name;
```

### `BCN-T2-DAT-003` — Classification

Ask where regulated data resides, then run discovery and compare. **The delta is
the finding.**

```bash
# AWS Macie — sensitive data discovery across S3
aws macie2 create-classification-job \
  --job-type ONE_TIME \
  --name "regulated-data-discovery" \
  --s3-job-definition '{"bucketDefinitions":[{"accountId":"<acct>","buckets":["<bucket>"]}]}'

aws macie2 list-findings \
  --finding-criteria '{"criterion":{"classificationDetails.result.sensitiveData.category":
                       {"eq":["PERSONAL_INFORMATION","FINANCIAL_INFORMATION"]}}}'
```

Regulated data in file shares, ticketing systems, and collaboration platforms is
the usual surprise. Scope discovery beyond the databases you already know about.

---

## Qualifying Criteria

**Encryption — `BCN-T2-DAT-001`**
- [ ] Deprecated protocol or cipher suite in use (TLS 1.0/1.1, 3DES, RC4)
- [ ] Key length below the mandated minimum
- [ ] Keys stored in the same system, account, or backup as the data
- [ ] No documented key-management lifecycle
- [ ] No key rotation record for the current period
- [ ] Split knowledge / dual control absent where PCI DSS requires it

**Retention — `BCN-T2-DAT-002`**
- [ ] No documented retention schedule per data category
- [ ] Data retained beyond its stated lawful basis or business need
- [ ] Deletion does not propagate to warehouses, indexes, caches, or logs
- [ ] Processor contracts lack deletion obligations, or they are not exercised
- [ ] No tracked process for data-subject erasure requests
- [ ] Statutory response deadlines not met

**Classification — `BCN-T2-DAT-003`**
- [ ] No classification scheme, or one that exists only on paper
- [ ] Labels drive no enforced control
- [ ] Regulated data discovered outside the documented inventory
- [ ] New systems onboarded without classification
- [ ] No named data owner per system

> **Escalate, do not absorb:** regulated data discovered during classification
> work in an *exposed* location is Tier 1, not Tier 2. Record it under
> [BCN-T1-NET-002](../network/publicly-accessible-resources.md) or
> [BCN-T1-DAT-002](database-security.md) and remediate on that clock.

---

## Remediation

### Phase 1 — Cryptography (Days 1–14)

**Disable deprecated protocols at the edge, then work inward:**

```bash
# AWS ALB — enforce a modern TLS policy
aws elbv2 modify-listener \
  --listener-arn <listener-arn> \
  --ssl-policy ELBSecurityPolicy-TLS13-1-2-Res-2021-06
```

```nginx
# Nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers off;
ssl_session_tickets off;
```

**Re-encrypt data held under deprecated algorithms.** Changing the setting
affects new writes only — existing data stays as it was written, and that is
what the assessor samples.

```bash
# Encrypted copy of an unencrypted snapshot, then delete the original
aws rds copy-db-snapshot \
  --source-db-snapshot-identifier legacy-snap \
  --target-db-snapshot-identifier legacy-snap-encrypted \
  --kms-key-id alias/regulated-data

aws rds delete-db-snapshot --db-snapshot-identifier legacy-snap
```

**Separate key custody from the data plane:**

```json
{
  "Sid": "SeparateKeyAdministrationFromUse",
  "Effect": "Allow",
  "Principal": { "AWS": "arn:aws:iam::<acct>:role/key-administrators" },
  "Action": ["kms:Create*", "kms:Describe*", "kms:Enable*",
             "kms:List*", "kms:Put*", "kms:Update*", "kms:Revoke*",
             "kms:Disable*", "kms:Get*", "kms:ScheduleKeyDeletion"],
  "Resource": "*"
}
```

Key administrators must not also hold `kms:Decrypt` on production data, and the
application role must not hold key administration. That separation is the
control.

### Phase 2 — Retention (Days 14–25)

1. **Publish a retention schedule** per data category, stating the lawful basis
   and the period.
2. **Automate deletion** at period end. Periodic manual purges do not survive
   contact with a busy quarter.
3. **Extend deletion to every downstream copy.** Where backup architecture makes
   selective deletion impractical, document the compensating approach —
   typically per-subject key destruction (crypto-shredding), which regulators
   accept when it is designed deliberately rather than claimed retrospectively.

```yaml
# S3 lifecycle — expiry plus non-current version cleanup
Rules:
  - Id: regulated-data-7yr
    Status: Enabled
    Filter: { Prefix: "customer-records/" }
    Expiration: { Days: 2555 }
    NoncurrentVersionExpiration: { NoncurrentDays: 30 }
    AbortIncompleteMultipartUpload: { DaysAfterInitiation: 7 }
```

### Phase 3 — Classification (Days 25–30)

Keep the scheme to **three or four levels**. Elaborate schemes are not applied
consistently, and a scheme nobody applies provides no assurance.

| Level | Definition | Required controls |
|-------|-----------|-------------------|
| **Restricted** | Regulated: PAN, ePHI, government identifiers | Encryption at rest + in transit, CMK, access logging, DLP, defined retention |
| **Confidential** | Business-sensitive, personal data | Encryption at rest + in transit, RBAC, retention schedule |
| **Internal** | Non-public operational data | Access control, encryption in transit |
| **Public** | Approved for release | Integrity protection only |

Bind labels to enforcement — encryption, access, retention, and DLP policy
should all key off the label. Labels that affect nothing provide no assurance,
and assessors say so.

---

## Verification

| Check | Evidence |
|-------|----------|
| Only approved protocols and ciphers | `testssl.sh` output, internal and external endpoints |
| At-rest encryption meets algorithm and key requirements | Configuration export per store and snapshot |
| Key rotation performed | KMS rotation record for the current period |
| Key custody separated from data access | IAM policy showing administrators lack `kms:Decrypt` |
| Erasure completes across all systems | Traced test request with per-system confirmation, within statutory window |
| Automated retention deletion runs | Lifecycle execution logs |
| Regulated data inventory is current | Discovery scan showing no significant unclassified regulated data |

---

## Exception Handling

Legacy systems that cannot support modern cryptography:

1. Document the specific technical constraint and the affected data
2. Isolate the system — network segmentation reduces exposure and often reduces
   assessment scope
3. Apply a compensating control: tokenisation, an encrypting proxy, or
   application-layer encryption ahead of the legacy store
4. Record a decommissioning date, not an indefinite exception
5. Disclose to the assessor proactively

---

## Monitoring Requirements

| Event | Action |
|-------|--------|
| Encryption disabled on a store | Critical alert; treat as suspected incident |
| KMS key scheduled for deletion | Immediate alert; require dual approval |
| Key policy modified | Alert and record in change log |
| Deprecated TLS negotiated | Log, alert, and identify the client |
| Retention job failed | Alert compliance owner |
| Erasure request past SLA | Daily escalation report |
| Unclassified regulated data discovered | Route to data owner within 24 hours |

---

## References

- [PCI DSS v4.0 Requirement 3 — Protect Stored Account Data](https://www.pcisecuritystandards.org/document_library/)
- [GDPR Article 32 — Security of Processing](https://gdpr-info.eu/art-32-gdpr/)
- [GDPR Article 17 — Right to Erasure](https://gdpr-info.eu/art-17-gdpr/)
- [HHS HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/index.html)
- [NIST SP 800-57 — Key Management Recommendations](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)

---

## Related Findings

- [Database Security](database-security.md) — `BCN-T1-DAT-002`, Tier 1
- [Critical Database Protection Issues](critical-database-protection-issues.md) — `BCN-T1-DAT-001`, Tier 1
- [Data Handling Best Practices](data-handling-best-practices.md) — Tier 3

---

*For classification guidance, see [Classification Procedure](../CLASSIFICATION.md).
For scanner details, see [Scanners and Frameworks](../scanners-and-frameworks.md).*
