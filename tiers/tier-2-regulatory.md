# Tier 2: Regulatory

## Classification: COMPLIANCE-CRITICAL
**Remediation SLA:** 30 days  
**Risk Level:** Audit failure / Regulatory penalty  
**Business Impact:** Certification loss, fines, legal liability

---

## Executive Summary

Tier 2 findings directly impact your organization's ability to operate in regulated environments. These are not just security issues—they are compliance violations that can result in failed audits, lost certifications, regulatory fines, and legal liability. For organizations subject to PCI DSS, HIPAA, SOC 2, GDPR, or similar frameworks, Tier 2 remediation is not optional.

### Why Tier 2 Matters

- **GDPR fines** can reach €20M or 4% of global annual revenue
- **HIPAA penalties** range from $100 to $50,000 per violation, up to $1.5M annually per category
- **PCI DSS non-compliance** can result in $5,000-$100,000/month in fines from payment processors
- **SOC 2 exceptions** can derail enterprise sales and partnerships

---

## Compliance Framework Coverage

| Framework | Scope | Key Requirements |
|-----------|-------|------------------|
| **PCI DSS** | Payment card data | Network segmentation, encryption, access control |
| **HIPAA** | Protected health information | Access controls, audit logs, encryption |
| **SOC 2** | Service organization controls | Security, availability, confidentiality |
| **GDPR** | EU personal data | Data protection, consent, breach notification |
| **ISO 27001** | Information security management | Risk assessment, controls, continuous improvement |
| **CCPA** | California consumer data | Access rights, deletion, disclosure |
| **NIST CSF** | Critical infrastructure | Identify, protect, detect, respond, recover |

---

## Network Compliance

### Regulatory Network Compliance
**Applicable Frameworks:** PCI DSS 1.x, HIPAA §164.312(e), SOC 2 CC6.6, ISO 27001 A.13

| Severity | Compliance Impact | SLA |
|----------|------------------|-----|
| High | Direct audit finding | 30 days |

**Compliance Requirements:**

| Framework | Specific Requirement |
|-----------|---------------------|
| **PCI DSS 1.3** | Prohibit direct public access between internet and cardholder data environment |
| **PCI DSS 1.4** | Install personal firewall software on all mobile/employee-owned devices |
| **HIPAA** | Implement technical security measures to guard against unauthorized network access |
| **SOC 2** | Logical and physical access controls to protect against unauthorized access |

**Detection Tools:**
- [Nessus](https://www.tenable.com/products/nessus) - Compliance scanning with framework templates
- [PROWLER](https://prowler.cloud/) - CIS Benchmark and regulatory compliance checks

**Qualifying Criteria:**
- Missing network segmentation between cardholder data environment and other networks (PCI)
- Firewall rules allowing any-to-any traffic in regulated zones
- Lack of documented network diagrams showing data flows
- Missing intrusion detection/prevention on network perimeter
- Unencrypted network traffic containing regulated data

**Remediation:**
1. Implement network segmentation isolating regulated data environments
2. Document all network diagrams with data flow mappings
3. Deploy and tune IDS/IPS on regulated network segments
4. Encrypt all network traffic containing regulated data (TLS 1.2+)
5. Conduct quarterly firewall rule reviews

**Evidence Required:**
- Network topology diagrams
- Firewall rule documentation and change logs
- IDS/IPS deployment records and alert logs
- Penetration test reports showing segmentation effectiveness

---

## Identity and Access Management Compliance

### Regulatory IAM Compliance
**Applicable Frameworks:** PCI DSS 7.x/8.x, HIPAA §164.312(d), SOC 2 CC6.1-CC6.3, ISO 27001 A.9

| Severity | Compliance Impact | SLA |
|----------|------------------|-----|
| High | Direct audit finding | 30 days |

**Compliance Requirements:**

| Framework | Specific Requirement |
|-----------|---------------------|
| **PCI DSS 7.1** | Limit access to system components to only those individuals whose job requires access |
| **PCI DSS 8.3** | Secure all individual administrative access using multi-factor authentication |
| **HIPAA** | Implement procedures to verify identity of persons seeking access to ePHI |
| **SOC 2** | Logical access security software, infrastructure, and architectures |
| **GDPR Art. 32** | Ability to ensure ongoing confidentiality, integrity, availability of processing |

**Detection Tools:**
- [Nessus](https://www.tenable.com/products/nessus) - IAM configuration compliance
- [PROWLER](https://prowler.cloud/) - Cloud IAM compliance assessment

**Qualifying Criteria:**
- User access not reviewed quarterly (PCI DSS 7.1.4)
- MFA not enabled for administrative access (PCI DSS 8.3)
- No unique user IDs for all users (PCI DSS 8.1)
- No access logging or audit trails (HIPAA, SOC 2)
- Terminated users not removed within 24 hours
- No segregation of duties for critical functions

**Remediation:**
1. Implement quarterly user access reviews with documented evidence
2. Enable MFA for all administrative and remote access
3. Ensure unique user identification for every user
4. Deploy comprehensive access logging with 1-year retention
5. Automate user deprovisioning workflows
6. Document and enforce segregation of duties matrix

**Evidence Required:**
- Quarterly access review reports with approvals
- MFA enrollment reports showing 100% coverage
- User provisioning/deprovisioning procedures
- Access log retention policies and sample logs
- Segregation of duties documentation

---

## Processing Compliance

### Regulatory Processing Compliance
**Applicable Frameworks:** PCI DSS 6.x, HIPAA §164.308(a)(1), SOC 2 CC7.x, ISO 27001 A.12

| Severity | Compliance Impact | SLA |
|----------|------------------|-----|
| High | Direct audit finding | 30 days |

**Compliance Requirements:**

| Framework | Specific Requirement |
|-----------|---------------------|
| **PCI DSS 6.2** | Install critical security patches within one month of release |
| **PCI DSS 6.5** | Address common coding vulnerabilities in development processes |
| **HIPAA** | Implement procedures for regular review of activity records |
| **SOC 2** | Change management controls for system modifications |
| **GDPR Art. 32** | Process of regularly testing and evaluating security measures |

**Detection Tools:**
- [Nessus](https://www.tenable.com/products/nessus) - Patch compliance assessment
- [PROWLER](https://prowler.cloud/) - Configuration compliance verification

**Qualifying Criteria:**
- Critical patches not applied within 30 days
- No documented change management process
- Missing or incomplete system hardening
- No vulnerability scanning performed quarterly
- Lack of penetration testing (annual requirement)
- Missing or disabled audit logging

**Remediation:**
1. Implement automated patch management with 30-day SLA for critical patches
2. Document and enforce change management procedures
3. Apply CIS Benchmarks or equivalent hardening standards
4. Conduct quarterly internal vulnerability scans
5. Perform annual penetration testing by qualified assessor
6. Enable comprehensive audit logging on all systems

**Evidence Required:**
- Patch management reports showing compliance
- Change management tickets and approval records
- Hardening documentation and compliance scans
- Quarterly vulnerability scan reports with remediation tracking
- Annual penetration test reports
- Audit log retention evidence

---

## Data Compliance

### Regulatory Data Compliance
**Applicable Frameworks:** PCI DSS 3.x/4.x, HIPAA §164.312(a)(2)(iv), GDPR Art. 32, SOC 2 CC6.7

| Severity | Compliance Impact | SLA |
|----------|------------------|-----|
| High | Direct audit finding | 30 days |

**Compliance Requirements:**

| Framework | Specific Requirement |
|-----------|---------------------|
| **PCI DSS 3.4** | Render PAN unreadable anywhere it is stored (encryption, hashing, truncation, tokenization) |
| **PCI DSS 4.1** | Use strong cryptography to safeguard cardholder data during transmission |
| **HIPAA** | Implement mechanism to encrypt/decrypt ePHI |
| **GDPR Art. 32** | Encryption of personal data (where appropriate) |
| **SOC 2** | Protection of information during transmission and storage |

**Detection Tools:**
- [Nessus](https://www.tenable.com/products/nessus) - Encryption verification
- [Cloudsploit](https://cloudsploit.com/) - Cloud storage encryption assessment

**Qualifying Criteria:**
- Regulated data stored without encryption at rest
- Data transmitted without TLS 1.2 or higher
- Encryption keys not rotated annually
- No documented data retention/destruction policy
- PII/PHI/PAN stored beyond required retention period
- Missing data classification scheme

**Remediation:**
1. Enable encryption at rest for all regulated data storage
2. Enforce TLS 1.2+ for all data in transit
3. Implement annual key rotation with documented procedures
4. Document and enforce data retention/destruction policies
5. Deploy data discovery and classification tools
6. Conduct data minimization review

**Evidence Required:**
- Encryption-at-rest configuration evidence
- TLS configuration scans and certificates
- Key management procedures and rotation logs
- Data retention policy and destruction certificates
- Data inventory and classification documentation

---

## Audit Preparation Checklist

Before any compliance audit, verify:

- [ ] All Tier 2 findings remediated or documented in POA&M
- [ ] Evidence packages prepared for each control area
- [ ] Access review documentation current (within 90 days)
- [ ] Penetration test report available (within 12 months)
- [ ] Vulnerability scan reports available (within 90 days)
- [ ] Policy documents reviewed and approved (within 12 months)
- [ ] Training records current for all personnel
- [ ] Incident response procedures tested (within 12 months)

---

## Summary

Tier 2 compliance is not optional for regulated organizations. Failed audits can result in immediate business impact—lost certifications, customer attrition, and regulatory penalties. Treat Tier 2 findings as business-critical issues that require dedicated resources and executive sponsorship.

**Key Metrics to Track:**
- Compliance finding aging
- Audit exception trends
- Time to remediation by framework
- Control testing pass rate

---

*For details on detection tools, see [Scanners and Frameworks](../scanners-and-frameworks.md).*
