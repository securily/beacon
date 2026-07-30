# Beacon Finding Catalog

**36 canonically-identified finding classes across 3 tiers and 4 domains.**

Machine-readable form: [`beacon-catalog.json`](beacon-catalog.json)

---

## Identifier format

```
BCN-T1-NET-001
 │   │   │   └── Sequence number within tier and domain
 │   │   └────── Domain: NET | IAM | DAT | PRC
 │   └────────── Tier: T1 | T2 | T3
 └────────────── Namespace
```

### Stability guarantee

**Identifiers are permanent.** A finding class may be reworded, re-mapped to
different frameworks, or superseded — but its identifier is **never reused and
never renumbered**.

This is what makes Beacon citable. An identifier written into a penetration test
report, a ticket, or a customer-facing remediation plan still resolves years
later. See [VERSIONING.md](VERSIONING.md) for the full stability policy.

### Finding classes vs. instances

| Concept | Definition | Example |
|---------|-----------|---------|
| **Finding class** | A named category of security condition | `BCN-T1-NET-001` |
| **Finding instance** | One occurrence on one asset | `BCN-T1-NET-001` on `prod-bastion-03` |

Your scanner reports instances. Beacon classifies them. One class typically
accounts for many instances across an estate.

---

## Tier 1 — Critical

**SLA: 24–72 hours** · Escalation: CISO and executive sponsor at 48 hours

*Routes here when: an untrusted party can reach it right now, and exploitation
grants access, privilege, or data in one step.*

| ID | Finding | SLA | Documentation |
|----|---------|-----|---------------|
| `BCN-T1-NET-001` | Internet-Exposed Remote Administration Services | 24h | [critical-open-ports](network/critical-open-ports.md) |
| `BCN-T1-NET-002` | Publicly Accessible Storage and Data Services | 24h | [publicly-accessible-resources](network/publicly-accessible-resources.md) |
| `BCN-T1-NET-003` | No Segmentation Between Trust Zones | 72h | [lack-of-firewalls](network/lack-of-firewalls.md) |
| `BCN-T1-IAM-001` | Missing MFA on Privileged Accounts | 24h | [mandatory-mfa](identity-and-access-management/mandatory-mfa.md) |
| `BCN-T1-IAM-002` | Excessive Standing Privilege | 48h | [high-privilege-accounts](identity-and-access-management/high-privilege-accounts.md) |
| `BCN-T1-IAM-003` | Long-Lived Privileged Credentials | 72h | [secure-password-policies](identity-and-access-management/secure-password-policies.md) |
| `BCN-T1-DAT-001` | Injection Flaws on Internet-Facing Applications | 24h | [critical-database-protection-issues](data/critical-database-protection-issues.md) |
| `BCN-T1-DAT-002` | Unauthenticated Database Endpoints | 24h | [database-security](data/database-security.md) |
| `BCN-T1-DAT-003` | Unencrypted Sensitive Data at Rest | 48h | [database-security](data/database-security.md) |
| `BCN-T1-PRC-001` | Known-Exploited Vulnerabilities | 24h | [known-exploited-vulnerabilities](processing-protection/known-exploited-vulnerabilities.md) |
| `BCN-T1-PRC-002` | Exposed Management and Orchestration Interfaces | 24h | [unprotected-external-exposure](processing-protection/unprotected-external-exposure.md) |
| `BCN-T1-PRC-003` | No Availability Protection on Revenue-Critical Services | 48h | [ddos-protection](processing-protection/ddos-protection.md) |

---

## Tier 2 — Regulatory

**SLA: 30 days** · Escalation: security manager review at 14 days

*Routes here when: a named auditor, regulator, or contractual counterparty would
record it as a deficiency.*

| ID | Finding | Documentation |
|----|---------|---------------|
| `BCN-T2-NET-001` | Regulated Environment Segmentation Gaps | [regulatory-network-compliance](network/regulatory-network-compliance.md) |
| `BCN-T2-NET-002` | Insufficient Logging and Retention | [regulatory-network-compliance](network/regulatory-network-compliance.md) |
| `BCN-T2-NET-003` | Missing Intrusion Detection Coverage | [regulatory-network-compliance](network/regulatory-network-compliance.md) |
| `BCN-T2-IAM-001` | Non-Compliant Authentication Policy | [regulatory-iam-compliance](identity-and-access-management/regulatory-iam-compliance.md) |
| `BCN-T2-IAM-002` | Missing Periodic Access Reviews | [regulatory-iam-compliance](identity-and-access-management/regulatory-iam-compliance.md) |
| `BCN-T2-IAM-003` | Ungoverned Service Accounts | [regulatory-iam-compliance](identity-and-access-management/regulatory-iam-compliance.md) |
| `BCN-T2-DAT-001` | Encryption Below Regulatory Standard | [regulatory-data-compliance](data/regulatory-data-compliance.md) |
| `BCN-T2-DAT-002` | Retention and Deletion Non-Compliance | [regulatory-data-compliance](data/regulatory-data-compliance.md) |
| `BCN-T2-DAT-003` | Absent Data Classification | [regulatory-data-compliance](data/regulatory-data-compliance.md) |
| `BCN-T2-PRC-001` | Vulnerability Management Process Gaps | [regulatory-processing-compliance](processing-protection/regulatory-processing-compliance.md) |
| `BCN-T2-PRC-002` | Change Management Control Gaps | [regulatory-processing-compliance](processing-protection/regulatory-processing-compliance.md) |
| `BCN-T2-PRC-003` | Untested Incident Response Capability | [regulatory-processing-compliance](processing-protection/regulatory-processing-compliance.md) |

---

## Tier 3 — Best Practices

**SLA: 90 days** · Escalation: quarterly planning review · Formal deferral is a
legitimate outcome

*Routes here when: fixing it reduces the number or severity of future Tier 1 and
Tier 2 findings.*

| ID | Finding | Documentation |
|----|---------|---------------|
| `BCN-T3-NET-001` | Non-Critical Service Exposure | [non-critical-open-ports](network/non-critical-open-ports.md) |
| `BCN-T3-NET-002` | Cloud Network Hardening Gaps | [hardening-of-cloud-resources](network/hardening-of-cloud-resources.md) |
| `BCN-T3-NET-003` | Incomplete Egress Filtering | [hardening-of-cloud-resources](network/hardening-of-cloud-resources.md) |
| `BCN-T3-IAM-001` | Coarse-Grained Role Design | [rbac](identity-and-access-management/rbac.md) |
| `BCN-T3-IAM-002` | Manual Credential Lifecycle | [secure-credential-management](identity-and-access-management/secure-credential-management.md) |
| `BCN-T3-IAM-003` | Fragmented Identity Federation | [rbac](identity-and-access-management/rbac.md) |
| `BCN-T3-DAT-001` | No Data Loss Prevention Coverage | [data-handling-best-practices](data/data-handling-best-practices.md) |
| `BCN-T3-DAT-002` | Unverified Backup Restoration | [data-handling-best-practices](data/data-handling-best-practices.md) |
| `BCN-T3-DAT-003` | Database Configuration Hardening | [data-handling-best-practices](data/data-handling-best-practices.md) |
| `BCN-T3-PRC-001` | Container and Image Hardening | [processing-security-best-practices](processing-protection/processing-security-best-practices.md) |
| `BCN-T3-PRC-002` | CI/CD Pipeline Hardening | [processing-security-best-practices](processing-protection/processing-security-best-practices.md) |
| `BCN-T3-PRC-003` | Infrastructure-as-Code Security Gaps | [processing-security-best-practices](processing-protection/processing-security-best-practices.md) |

---

## Cross-reference: MITRE ATT&CK

| Technique | Name | Beacon findings |
|-----------|------|-----------------|
| [T1040](https://attack.mitre.org/techniques/T1040/) | Network Sniffing | `BCN-T2-DAT-001` |
| [T1046](https://attack.mitre.org/techniques/T1046/) | Network Service Discovery | `BCN-T3-NET-001` |
| [T1048](https://attack.mitre.org/techniques/T1048/) | Exfiltration Over Alternative Protocol | `BCN-T3-NET-003`, `BCN-T3-DAT-001` |
| [T1068](https://attack.mitre.org/techniques/T1068/) | Exploitation for Privilege Escalation | `BCN-T1-PRC-001` |
| [T1071](https://attack.mitre.org/techniques/T1071/) | Application Layer Protocol | `BCN-T3-NET-003` |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | `BCN-T1-IAM-001`, `BCN-T2-IAM-001`, `BCN-T2-IAM-002`, `BCN-T3-IAM-001`, `BCN-T3-IAM-003` |
| [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Valid Accounts: Cloud Accounts | `BCN-T1-IAM-002`, `BCN-T1-IAM-003`, `BCN-T2-IAM-003` |
| [T1110](https://attack.mitre.org/techniques/T1110/) | Brute Force | `BCN-T1-NET-001`, `BCN-T1-IAM-001`, `BCN-T2-IAM-001` |
| [T1133](https://attack.mitre.org/techniques/T1133/) | External Remote Services | `BCN-T1-NET-001`, `BCN-T1-PRC-002` |
| [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application | `BCN-T1-NET-001`, `BCN-T1-DAT-001`, `BCN-T1-PRC-001`, `BCN-T2-PRC-001` |
| [T1195.002](https://attack.mitre.org/techniques/T1195/002/) | Compromise Software Supply Chain | `BCN-T3-PRC-002` |
| [T1203](https://attack.mitre.org/techniques/T1203/) | Exploitation for Client Execution | `BCN-T1-PRC-001` |
| [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services | `BCN-T1-NET-003` |
| [T1213](https://attack.mitre.org/techniques/T1213/) | Data from Information Repositories | `BCN-T1-DAT-002`, `BCN-T2-DAT-002`, `BCN-T3-DAT-003` |
| [T1485](https://attack.mitre.org/techniques/T1485/) | Data Destruction | `BCN-T1-DAT-002` |
| [T1486](https://attack.mitre.org/techniques/T1486/) | Data Encrypted for Impact | `BCN-T2-PRC-003`, `BCN-T3-DAT-002` |
| [T1490](https://attack.mitre.org/techniques/T1490/) | Inhibit System Recovery | `BCN-T3-DAT-002` |
| [T1498](https://attack.mitre.org/techniques/T1498/) | Network Denial of Service | `BCN-T1-PRC-003` |
| [T1530](https://attack.mitre.org/techniques/T1530/) | Data from Cloud Storage | `BCN-T1-NET-002`, `BCN-T1-DAT-002`, `BCN-T1-DAT-003` |
| [T1552](https://attack.mitre.org/techniques/T1552/) | Unsecured Credentials | `BCN-T1-IAM-003`, `BCN-T3-IAM-002` |
| [T1562.008](https://attack.mitre.org/techniques/T1562/008/) | Impair Defenses: Disable Cloud Logs | `BCN-T2-NET-002` |
| [T1578](https://attack.mitre.org/techniques/T1578/) | Modify Cloud Compute Infrastructure | `BCN-T3-PRC-003` |
| [T1610](https://attack.mitre.org/techniques/T1610/) | Deploy Container | `BCN-T1-PRC-002`, `BCN-T3-PRC-001` |
| [T1611](https://attack.mitre.org/techniques/T1611/) | Escape to Host | `BCN-T3-PRC-001` |

---

## Cross-reference: Compliance frameworks

Beacon does **not** replace these standards. It maps to them, so that
compliance-driven work is scheduled against the audit calendar rather than
competing with threat-driven work for the same urgency.

| Framework | Beacon findings that map to it |
|-----------|-------------------------------|
| **PCI DSS v4.0** | `BCN-T1-NET-001`, `BCN-T1-NET-002`, `BCN-T1-IAM-001`, `BCN-T1-DAT-001`–`003`, `BCN-T1-PRC-001`, `BCN-T2-NET-001`–`003`, `BCN-T2-IAM-001`–`003`, `BCN-T2-DAT-001`–`002`, `BCN-T2-PRC-001`–`003`, `BCN-T3-NET-001`, `BCN-T3-DAT-003` |
| **ISO/IEC 27001:2022** | `BCN-T1-NET-001`, `BCN-T1-NET-003`, `BCN-T1-IAM-002`–`003`, `BCN-T1-PRC-002`–`003`, `BCN-T2-NET-002`–`003`, `BCN-T2-IAM-001`–`003`, `BCN-T2-DAT-001`–`003`, `BCN-T2-PRC-001`–`003`, `BCN-T3-NET-001`–`003`, `BCN-T3-IAM-001`–`003`, `BCN-T3-DAT-001`–`003`, `BCN-T3-PRC-001`, `BCN-T3-PRC-003` |
| **SOC 2** | `BCN-T1-NET-001`–`002`, `BCN-T1-IAM-001`–`002`, `BCN-T1-DAT-001`, `BCN-T1-PRC-003`, `BCN-T2-NET-002`, `BCN-T2-IAM-001`–`003`, `BCN-T2-PRC-001`–`003`, `BCN-T3-IAM-001`–`003`, `BCN-T3-DAT-001`–`002`, `BCN-T3-PRC-002`–`003` |
| **GDPR** | `BCN-T1-NET-002`, `BCN-T1-DAT-001`, `BCN-T1-DAT-003`, `BCN-T2-DAT-001`–`003`, `BCN-T2-PRC-003`, `BCN-T3-DAT-001` |
| **HIPAA** | `BCN-T1-NET-002`, `BCN-T1-IAM-001`, `BCN-T1-DAT-002`–`003`, `BCN-T2-NET-002`, `BCN-T2-IAM-001`, `BCN-T2-DAT-001`, `BCN-T2-PRC-003`, `BCN-T3-DAT-002` |
| **NIST CSF 2.0** | `BCN-T1-NET-001`, `BCN-T1-NET-003`, `BCN-T1-IAM-001`, `BCN-T1-IAM-003`, `BCN-T1-PRC-001`–`003`, `BCN-T2-NET-003`, `BCN-T2-PRC-001`, `BCN-T3-NET-001`–`003`, `BCN-T3-IAM-002`–`003`, `BCN-T3-PRC-003` |
| **CIS Benchmarks** | `BCN-T3-NET-002`, `BCN-T3-DAT-003`, `BCN-T3-PRC-001` |
| **SLSA / NIST SSDF** | `BCN-T3-PRC-002` |

---

## Using the catalog programmatically

The machine-readable catalog is published as
[`beacon-catalog.json`](beacon-catalog.json) so that scanners, ticketing
systems, and reporting pipelines can consume finding classes directly rather
than transcribing them.

```bash
# All Tier 1 findings with their SLAs
jq '.findings[] | select(.tier == 1) | {id, name, sla}' beacon-catalog.json

# Findings that map to a given ATT&CK technique
jq --arg t T1078 '.findings[] |
  select(.mappings.mitreAttack[]?.id == $t) | .id' beacon-catalog.json

# Findings relevant to a given compliance framework
jq --arg f "PCI DSS v4.0" '.findings[] |
  select(.mappings.compliance[]?.framework == $f) |
  {id, name}' beacon-catalog.json

# Resolve an identifier from a report back to its documentation
jq -r --arg id BCN-T1-NET-001 '.findings[] |
  select(.id == $id) | .documentation' beacon-catalog.json
```

### Schema

Each entry in `.findings[]` provides:

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Canonical identifier — permanent |
| `tier` | integer | `1`, `2`, or `3` |
| `domain` | string | `network`, `iam`, `data`, `processing` |
| `name` | string | Human-readable finding class name |
| `summary` | string | One sentence |
| `sla` | string | Remediation deadline for this specific finding |
| `documentation` | string | Repository-relative path to the full entry |
| `mappings.mitreAttack[]` | array | `{id, name}` |
| `mappings.compliance[]` | array | `{framework, control}` |
| `scanners[]` | array | Tools that commonly surface this finding |

Consumers should treat unknown fields as additive and ignore them — see
[VERSIONING.md](VERSIONING.md).

---

## Related documents

- [Classification Procedure](CLASSIFICATION.md) — how to assign a tier
- [Glossary](GLOSSARY.md) — terms as this standard uses them
- [Sources](SOURCES.md) — evidence behind every figure cited
- [Versioning](VERSIONING.md) — stability guarantees for consumers
- [Contributing](CONTRIBUTING.md) — how to propose changes
