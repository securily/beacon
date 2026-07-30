# Tier 1: High Priority

## Classification: CRITICAL
**Remediation SLA:** 24-72 hours  
**Risk Level:** Immediate exploitation possible  
**Business Impact:** Severe - potential for complete compromise

---

## Executive Summary

Tier 1 findings represent vulnerabilities that attackers actively exploit in the wild. These are not theoretical risks—they are the exact attack vectors used in ransomware campaigns, data breaches, and targeted intrusions. Every day a Tier 1 finding remains unpatched is a day your organization is exposed to catastrophic loss.

### Why Tier 1 Matters

Every figure below is traceable to a public primary source — see
[SOURCES.md](../SOURCES.md).

- **Exploitation as an entry point is growing sharply.** The 2024 Verizon DBIR
  reported that exploitation of vulnerabilities as a path to initiate a breach
  almost tripled year over year, driven by mass exploitation of edge devices and
  file-transfer software ([S1](../SOURCES.md))
- **Ransomware moves faster than most remediation SLAs.** Median dwell time
  before ransomware deployment has fallen to roughly 24 hours, with a meaningful
  share of cases completing in under a day ([S3](../SOURCES.md)). *This is the
  reason the Tier 1 SLA is measured in hours: a remediation window longer than
  the attack window is not a control.*
- **The human element is involved in roughly two-thirds of breaches** — error,
  privilege misuse, stolen credentials, or social engineering ([S5](../SOURCES.md)).
  This is why MFA coverage and privilege scope sit at Tier 1 alongside software
  vulnerabilities.
- **Most CVEs are never exploited.** Roughly one in twenty published
  vulnerabilities is ever observed being exploited, and remediating by CVSS score
  alone performs little better than remediating at random ([S2](../SOURCES.md)).
  *This is the empirical basis for tiering on reachability and observed
  exploitation rather than on score.*

---

## Network Security

### Critical Open Ports
**MITRE ATT&CK:** [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)

| Severity | CVSS Range | SLA |
|----------|------------|-----|
| Critical | 7.5 - 10.0 | 24 hours |

**Risk Description:**  
Unnecessary open ports provide direct attack vectors. Services like SSH (22), RDP (3389), SMB (445), and database ports (3306, 5432, 1433) are primary targets for automated exploitation and credential stuffing attacks.

**Real-World Impact:**
- WannaCry ransomware exploited SMB port 445 globally
- Attackers scan for exposed RDP and deploy ransomware within hours
- Database ports lead to direct data exfiltration

**Detection Tools:**
- [Nmap](https://nmap.org/) - Network port scanning and service detection
- [Nessus](https://www.tenable.com/products/nessus) - Vulnerability identification on open services

**Qualifying Criteria:**
- Any internet-facing port running SSH, RDP, SMB, Telnet, or database services
- Management interfaces (22, 23, 3389, 5900) accessible from untrusted networks
- Services with known active CVEs in exploitation

**Remediation:**
1. Close unnecessary ports immediately via firewall rules
2. Place required services behind VPN or zero-trust access
3. Implement network segmentation for sensitive services

---

### Publicly Accessible Resources
**MITRE ATT&CK:** [T1530 - Data from Cloud Storage Object](https://attack.mitre.org/techniques/T1530/)

| Severity | CVSS Range | SLA |
|----------|------------|-----|
| Critical | 8.0 - 10.0 | 24 hours |

**Risk Description:**  
Cloud storage buckets, databases, and compute instances exposed to the internet without authentication. This is the leading cause of massive data breaches—billions of records exposed annually.

**Real-World Impact:**
- Capital One breach: 100M+ records from misconfigured AWS
- Microsoft exposed 250M customer support records via unprotected Elasticsearch
- Thousands of MongoDB databases ransomed monthly

**Detection Tools:**
- [Cloudsploit](https://cloudsploit.com/) - Cloud misconfiguration detection
- [Nuclei](https://nuclei.projectdiscovery.io/) - Template-based exposure scanning
- [PROWLER](https://prowler.cloud/) - Multi-cloud security assessment

**Qualifying Criteria:**
- S3 buckets, GCS buckets, or Azure blobs with public read/write access
- Databases accessible without authentication from 0.0.0.0/0
- EC2/GCE/Azure VMs with public IPs and no security group restrictions
- Elasticsearch, Redis, or MongoDB without authentication

**Remediation:**
1. Remove public access immediately
2. Implement bucket policies requiring authentication
3. Enable encryption in transit (TLS) and at rest
4. Deploy Cloud Security Posture Management (CSPM)

---

### Lack of Firewalls
**MITRE ATT&CK:** [T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)

| Severity | CVSS Range | SLA |
|----------|------------|-----|
| High | 7.0 - 9.0 | 48 hours |

**Risk Description:**  
Absence of network or application-layer firewalls leaves systems directly exposed to attack traffic. Without filtering, every service becomes an attack surface.

**Detection Tools:**
- [Nessus](https://www.tenable.com/products/nessus) - Firewall presence and configuration assessment
- [Burp Suite](https://portswigger.net/burp) - Web application firewall testing

**Qualifying Criteria:**
- Systems without network ACLs or security groups
- Web applications without WAF protection
- Missing egress filtering allowing command-and-control communication
- No IDS/IPS monitoring on critical network segments

**Remediation:**
1. Deploy network firewalls at all trust boundaries
2. Implement WAF for all public-facing web applications
3. Configure egress filtering to allow only necessary outbound traffic
4. Enable IDS/IPS with updated threat signatures

---

## Identity and Access Management

### High-Privilege Accounts
**MITRE ATT&CK:** [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)

| Severity | CVSS Range | SLA |
|----------|------------|-----|
| Critical | 8.0 - 10.0 | 24 hours |

**Risk Description:**  
Overprivileged accounts are the crown jewels attackers pursue. A single compromised admin account can lead to complete infrastructure takeover. Most APT attacks culminate in domain admin compromise.

**Real-World Impact:**
- SolarWinds attack leveraged privileged access for lateral movement
- Colonial Pipeline attack exploited a legacy VPN account without MFA
- The human element — including privilege misuse and stolen credentials — is
  involved in roughly two-thirds of breaches ([S5](../SOURCES.md))

**Detection Tools:**
- [PROWLER](https://prowler.cloud/) - IAM best practices assessment
- [Cloudsploit](https://cloudsploit.com/) - Privilege analysis

**Qualifying Criteria:**
- Root/Administrator accounts used for daily operations
- Service accounts with admin privileges
- Stale privileged accounts (unused >90 days)
- Shared admin credentials
- IAM policies with `*:*` or overly broad permissions

**Remediation:**
1. Implement Privileged Access Management (PAM)
2. Enforce just-in-time (JIT) privilege elevation
3. Audit and remove unused high-privilege accounts
4. Separate administrative and standard user accounts

---

### Mandatory MFA
**MITRE ATT&CK:** [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)

| Severity | CVSS Range | SLA |
|----------|------------|-----|
| Critical | 9.0 - 10.0 | 24 hours |

**Risk Description:**  
Accounts without MFA are trivially compromised via credential stuffing, phishing, and password spraying. MFA blocks 99.9% of automated attacks.

**Real-World Impact:**
- Colonial Pipeline: No MFA on legacy VPN led to $4.4M ransom
- Twitter breach: Social engineering bypassed single-factor auth
- Microsoft reports MFA prevents 99.9% of account compromise attempts

**Detection Tools:**
- [PROWLER](https://prowler.cloud/) - MFA enforcement verification
- [Cloudsploit](https://cloudsploit.com/) - User authentication analysis

**Qualifying Criteria:**
- Any user account without MFA enabled
- Privileged accounts (admin, root) without hardware token MFA
- API access without service account MFA or short-lived credentials
- Console access to cloud environments without MFA

**Remediation:**
1. Enable MFA for 100% of user accounts—no exceptions
2. Require phishing-resistant MFA (FIDO2, hardware tokens) for privileged accounts
3. Implement conditional access policies
4. Disable legacy authentication protocols that bypass MFA

---

### Secure Password and Access Key Policies
**MITRE ATT&CK:** [T1552 - Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)

| Severity | CVSS Range | SLA |
|----------|------------|-----|
| High | 7.0 - 9.0 | 48 hours |

**Risk Description:**  
Weak password policies and unrotated access keys provide persistent access for attackers. Exposed credentials in code repositories are discovered and exploited within minutes.

**Detection Tools:**
- [Nessus](https://www.tenable.com/products/nessus) - Password policy auditing
- [PROWLER](https://prowler.cloud/) - Access key rotation analysis

**Qualifying Criteria:**
- Password policies allowing fewer than 14 characters
- No password complexity requirements
- Access keys older than 90 days
- API keys committed to source control
- Passwords stored in plaintext configuration files

**Remediation:**
1. Enforce minimum 14-character passwords with complexity
2. Implement password managers for all users
3. Rotate access keys every 90 days maximum
4. Use secrets management (Vault, AWS Secrets Manager)
5. Scan repositories for exposed credentials

---

## Processing Protection

### Unprotected External Exposure
**MITRE ATT&CK:** [T1133 - External Remote Services](https://attack.mitre.org/techniques/T1133/)

| Severity | CVSS Range | SLA |
|----------|------------|-----|
| Critical | 8.0 - 10.0 | 24 hours |

**Risk Description:**  
Compute resources directly accessible from the internet without protective layers (load balancers, firewalls, bastion hosts) are prime targets for direct exploitation.

**Detection Tools:**
- [Cloudsploit](https://cloudsploit.com/) - Cloud resource exposure analysis
- [Nmap](https://nmap.org/) - External service enumeration

**Qualifying Criteria:**
- VMs with public IPs and no load balancer or firewall
- Kubernetes API servers exposed to the internet
- Management consoles accessible without VPN
- Development/staging environments with public access

**Remediation:**
1. Place compute resources behind load balancers
2. Implement bastion hosts/jump boxes for administrative access
3. Use private networking with NAT for egress
4. Deploy zero-trust network access (ZTNA)

---

### DDoS Protection
**MITRE ATT&CK:** [T1498 - Network Denial of Service](https://attack.mitre.org/techniques/T1498/)

| Severity | CVSS Range | SLA |
|----------|------------|-----|
| High | 7.0 - 9.0 | 48 hours |

**Risk Description:**  
Without DDoS mitigation, critical services can be rendered unavailable by commodity attack tools. DDoS attacks are frequently used as diversions during active intrusions.

**Detection Tools:**
- [Nessus](https://www.tenable.com/products/nessus) - Infrastructure resilience assessment
- [PROWLER](https://prowler.cloud/) - Cloud DDoS protection verification

**Qualifying Criteria:**
- Public-facing services without DDoS protection
- DNS infrastructure without anycast/DDoS mitigation
- Critical APIs without rate limiting
- No incident response playbook for DDoS events

**Remediation:**
1. Enable cloud-native DDoS protection (AWS Shield, GCP Armor, Azure DDoS)
2. Deploy CDN with DDoS mitigation capabilities
3. Implement rate limiting on all APIs
4. Develop and test DDoS response procedures

---

## Data Security

### Database Security
**MITRE ATT&CK:** [T1213 - Data from Information Repositories](https://attack.mitre.org/techniques/T1213/)

| Severity | CVSS Range | SLA |
|----------|------------|-----|
| Critical | 9.0 - 10.0 | 24 hours |

**Risk Description:**  
Databases containing sensitive data that are publicly accessible or lack encryption represent the highest-value targets. A single misconfigured database can expose millions of records.

**Detection Tools:**
- [Cloudsploit](https://cloudsploit.com/) - Database exposure detection
- [Nuclei](https://nuclei.projectdiscovery.io/) - Database vulnerability scanning

**Qualifying Criteria:**
- Databases accessible from 0.0.0.0/0 (any IP)
- Database instances without encryption at rest
- Missing TLS for database connections
- Default database credentials in use
- Databases without audit logging enabled

**Remediation:**
1. Restrict database access to specific application subnets
2. Enable encryption at rest using platform-native encryption
3. Enforce TLS 1.2+ for all database connections
4. Rotate database credentials immediately if defaults are in use
5. Enable comprehensive audit logging

---

### Critical Database Protection Issues
**MITRE ATT&CK:** [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)

| Severity | CVSS Range | SLA |
|----------|------------|-----|
| Critical | 8.0 - 10.0 | 24 hours |

**Risk Description:**  
SQL injection, NoSQL injection, and database misconfigurations remain among the most exploited vulnerabilities. These attacks can bypass all authentication and authorization controls.

**Detection Tools:**
- [Nessus](https://www.tenable.com/products/nessus) - Database vulnerability assessment
- [Burp Suite](https://portswigger.net/burp) - SQL injection testing

**Qualifying Criteria:**
- SQL injection vulnerabilities in production applications
- Missing database security patches
- Weak authentication mechanisms (no password, weak password)
- Database superuser accounts accessible from applications
- Unencrypted backup files

**Remediation:**
1. Deploy parameterized queries/prepared statements
2. Apply all critical database security patches
3. Implement database activity monitoring (DAM)
4. Use application-specific database accounts with minimal privileges
5. Encrypt all backup files

---

## Summary

Tier 1 findings demand immediate action. These are not future risks—they are current exposure. Organizations must treat Tier 1 remediation as incident response, with clear ownership, defined SLAs, and executive visibility.

**Key Metrics to Track:**
- Time to detection (TTD)
- Time to remediation (TTR)
- Tier 1 finding recurrence rate
- Percentage of assets with Tier 1 findings

---

*For details on detection tools, see [Scanners and Frameworks](../scanners-and-frameworks.md).*
