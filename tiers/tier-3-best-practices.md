# Tier 3: Best Practices

## Classification: SECURITY HYGIENE
**Remediation SLA:** 90 days  
**Risk Level:** Defense-in-depth improvement  
**Business Impact:** Reduced security debt, improved resilience

---

## Executive Summary

Tier 3 findings represent security hygiene improvements that strengthen your overall defensive posture. While not immediately exploitable, these findings represent technical debt that can enable future attacks, complicate incident response, or become exploitable as attack techniques evolve.

Organizations with mature security programs address Tier 3 findings as part of continuous improvement. Those that ignore them accumulate risk that compounds over time.

### Why Tier 3 Matters

- **Defense-in-depth** requires multiple layers—Tier 3 strengthens these layers
- **Attacker economics** favor targets with weak security hygiene
- **Incident response** is faster and more effective with proper baselines
- **Technical debt** in security compounds interest just like financial debt

---

## Network Best Practices

### Non-Critical Open Ports
**CIS Controls:** 4.4 - Implement and Manage a Firewall on Servers

| Severity | Risk Level | SLA |
|----------|------------|-----|
| Low | Attack surface reduction | 90 days |

**Risk Description:**  
Open ports that are not critical to business operations expand the attack surface unnecessarily. While not immediately exploitable, each open port is a potential future vulnerability.

**Detection Tools:**
- [Nmap](https://nmap.org/) - Comprehensive port scanning
- [Nessus](https://www.tenable.com/products/nessus) - Service identification and risk assessment

**Qualifying Criteria:**
- Open ports without documented business justification
- Legacy services running on non-standard ports
- Duplicate services on multiple ports
- Development or debugging services in production
- Services configured but unused

**Best Practice Recommendations:**
1. Document business justification for every open port
2. Implement regular port audits (quarterly minimum)
3. Close or firewall all unnecessary ports
4. Use non-standard ports only with strong justification
5. Implement port-based monitoring and alerting

**Implementation Priority:**
- Production systems: 60 days
- Development systems: 90 days
- Legacy systems: Document and plan for decommissioning

---

### Hardening of Cloud Resources
**CIS Controls:** 4.1 - Establish and Maintain a Secure Configuration Process

| Severity | Risk Level | SLA |
|----------|------------|-----|
| Medium | Configuration drift prevention | 90 days |

**Risk Description:**  
Cloud resources deployed with default configurations often lack security controls that prevent exploitation. Proper hardening reduces the attack surface and limits blast radius.

**Detection Tools:**
- [Cloudsploit](https://cloudsploit.com/) - Cloud security posture assessment
- [PROWLER](https://prowler.cloud/) - CIS Benchmark compliance checking

**Qualifying Criteria:**
- Resources not conforming to CIS Benchmarks
- Missing resource tagging (owner, environment, data classification)
- Default security group configurations
- Instance metadata service v1 enabled (AWS)
- Missing logging or monitoring configuration
- Unused or orphaned cloud resources

**Best Practice Recommendations:**
1. Adopt CIS Benchmarks as baseline configuration
2. Implement infrastructure-as-code with security guardrails
3. Deploy automated compliance scanning in CI/CD
4. Enforce mandatory tagging policies
5. Conduct monthly cloud resource hygiene reviews
6. Disable IMDSv1 in favor of IMDSv2 (AWS)

**Implementation Approach:**
- New resources: Enforce at deployment via IaC policies
- Existing resources: Prioritize by data sensitivity and exposure

---

## Identity and Access Management Best Practices

### Role-Based Access Control (RBAC)
**CIS Controls:** 6.8 - Define and Maintain Role-Based Access Control

| Severity | Risk Level | SLA |
|----------|------------|-----|
| Medium | Privilege minimization | 90 days |

**Risk Description:**  
Incomplete or poorly designed RBAC implementations result in excessive permissions, making lateral movement easier for attackers and increasing blast radius of compromised accounts.

**Detection Tools:**
- [PROWLER](https://prowler.cloud/) - IAM policy analysis
- [Cloudsploit](https://cloudsploit.com/) - Permission evaluation

**Qualifying Criteria:**
- Users with direct permissions instead of role-based
- Roles with excessive permissions beyond job function
- No documented RBAC model or permission matrix
- Missing role lifecycle management process
- Roles not reviewed for least privilege periodically
- Service accounts using user roles

**Best Practice Recommendations:**
1. Document role definitions tied to job functions
2. Implement role request and approval workflows
3. Conduct semi-annual role entitlement reviews
4. Use attribute-based access control (ABAC) where appropriate
5. Separate service account roles from user roles
6. Implement just-in-time access for elevated privileges

**Implementation Approach:**
- Start with most privileged roles
- Expand to all roles over 90-day period
- Automate role assignment based on HR systems where possible

---

### Secure Credential Management
**CIS Controls:** 16.1 - Establish and Maintain a Secure Application Development Process

| Severity | Risk Level | SLA |
|----------|------------|-----|
| Medium | Credential hygiene | 90 days |

**Risk Description:**  
Poor credential management practices—hardcoded secrets, infrequent rotation, insecure storage—create persistent access vectors for attackers.

**Detection Tools:**
- [Nessus](https://www.tenable.com/products/nessus) - Credential security assessment
- [PROWLER](https://prowler.cloud/) - Secret management evaluation

**Qualifying Criteria:**
- API keys older than 180 days
- Secrets not stored in secrets management solution
- Application credentials in environment variables
- Shared service accounts without individual attribution
- No automated credential rotation for non-critical systems
- Missing credential usage monitoring

**Best Practice Recommendations:**
1. Deploy secrets management (HashiCorp Vault, AWS Secrets Manager, etc.)
2. Implement automated credential rotation (180 days for non-critical)
3. Eliminate hardcoded credentials from code and configuration
4. Assign individual service accounts for attribution
5. Monitor credential usage for anomalies
6. Implement credential expiration policies

**Implementation Approach:**
- Inventory all credentials and secrets
- Prioritize migration to secrets management
- Implement rotation for highest-risk credentials first

---

## Processing Best Practices

### Processing Security Best Practices
**CIS Controls:** 7.1 - Establish and Maintain a Vulnerability Management Process

| Severity | Risk Level | SLA |
|----------|------------|-----|
| Medium | Operational security | 90 days |

**Risk Description:**  
Systems without proper security hygiene—missing patches, outdated configurations, insufficient logging—are more susceptible to compromise and harder to investigate after incidents.

**Detection Tools:**
- [Nessus](https://www.tenable.com/products/nessus) - Configuration and patch assessment
- [Cloudsploit](https://cloudsploit.com/) - Cloud configuration analysis

**Qualifying Criteria:**
- Non-critical patches older than 90 days
- Systems not conforming to hardening baselines
- Insufficient logging (less than 90-day retention)
- Missing endpoint detection and response (EDR)
- No configuration management or drift detection
- Legacy operating systems beyond extended support

**Best Practice Recommendations:**
1. Implement 90-day patching SLA for non-critical patches
2. Deploy EDR on all endpoints and servers
3. Enable comprehensive logging with 90+ day retention
4. Implement configuration management (Ansible, Puppet, Chef)
5. Deploy configuration drift detection and alerting
6. Plan migration path for legacy systems

**Implementation Priority:**
- Internet-facing systems: 60 days
- Internal systems with sensitive data: 90 days
- Development/test systems: As resources permit

---

## Data Best Practices

### Data Handling Best Practices
**CIS Controls:** 3.1 - Establish and Maintain a Data Management Process

| Severity | Risk Level | SLA |
|----------|------------|-----|
| Medium | Data lifecycle management | 90 days |

**Risk Description:**  
Poor data handling practices—unclear classification, excessive retention, missing backup verification—increase breach impact and complicate compliance and incident response.

**Detection Tools:**
- [Cloudsploit](https://cloudsploit.com/) - Cloud data configuration assessment
- [Nessus](https://www.tenable.com/products/nessus) - Data handling policy verification

**Qualifying Criteria:**
- No data classification scheme implemented
- Data retained beyond business or regulatory need
- Backup integrity not verified regularly
- Missing data loss prevention (DLP) controls
- No data minimization practices
- Unclear data ownership assignments

**Best Practice Recommendations:**
1. Implement data classification (Public, Internal, Confidential, Restricted)
2. Define and enforce retention policies by data class
3. Test backup restoration quarterly
4. Deploy DLP for sensitive data egress monitoring
5. Conduct annual data minimization reviews
6. Assign data owners for all datasets

**Implementation Approach:**
- Start with most sensitive data classifications
- Expand classification and controls progressively
- Integrate data handling into development lifecycle

---

## Maturity Model Integration

Tier 3 findings map to security maturity levels:

| Maturity Level | Tier 3 Posture |
|----------------|----------------|
| **Level 1 - Initial** | Tier 3 findings untracked |
| **Level 2 - Developing** | Tier 3 findings documented |
| **Level 3 - Defined** | Tier 3 remediation in backlog |
| **Level 4 - Managed** | Tier 3 actively remediated within SLA |
| **Level 5 - Optimizing** | Proactive Tier 3 prevention |

---

## Summary

Tier 3 findings represent the difference between adequate security and mature security. Organizations that consistently address Tier 3 findings build resilient environments that resist attack, recover quickly from incidents, and demonstrate security excellence to stakeholders.

**Key Metrics to Track:**
- Tier 3 finding age distribution
- Security debt trend over time
- Configuration compliance percentage
- Time from finding to remediation

**Success Indicators:**
- Average Tier 3 finding age < 60 days
- 90%+ configuration compliance
- Zero Tier 3 findings > 180 days old
- Declining trend in new Tier 3 findings

---

*For details on detection tools, see [Scanners and Frameworks](../scanners-and-frameworks.md).*
