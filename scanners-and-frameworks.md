# Scanners and Frameworks

## Overview

Beacon Security Standards integrates with industry-leading security scanners and aligns with established penetration testing frameworks. This document provides implementation guidance for each tool and framework.

---

## Security Scanners

### Network and Vulnerability Scanners

#### Nmap
**Type:** Network Discovery and Security Auditing  
**Cost:** Free / Open Source  
**Website:** [https://nmap.org/](https://nmap.org/)  
**GitHub:** [https://github.com/nmap/nmap](https://github.com/nmap/nmap)

| Beacon Tier Coverage | Use Cases |
|---------------------|-----------|
| Tier 1, Tier 3 | Port scanning, service detection, OS fingerprinting |

**Integration with Beacon:**
- **Tier 1:** Identify critical open ports (SSH, RDP, SMB, databases)
- **Tier 3:** Document non-critical open ports for attack surface reduction

**Recommended Scan Profile:**
```bash
# Comprehensive service scan for Beacon assessments
nmap -sS -sV -sC -O -p- --script vuln -oX beacon-scan.xml TARGET
```

**Key Capabilities:**
- TCP/UDP port scanning
- Service and version detection
- Operating system fingerprinting
- NSE vulnerability scripts
- Output formats for integration (XML, JSON)

---

#### Nessus
**Type:** Vulnerability Scanner  
**Cost:** Commercial (Nessus Essentials free for 16 IPs)  
**Website:** [https://www.tenable.com/products/nessus](https://www.tenable.com/products/nessus)

| Beacon Tier Coverage | Use Cases |
|---------------------|-----------|
| All Tiers | Vulnerability scanning, configuration auditing, compliance |

**Integration with Beacon:**
- **Tier 1:** Critical CVEs, missing patches, dangerous misconfigurations
- **Tier 2:** Compliance scanning (PCI DSS, HIPAA, CIS)
- **Tier 3:** Best practice deviations, minor configuration issues

**Recommended Scan Policies:**
- Basic Network Scan - Initial discovery
- Advanced Scan - Deep vulnerability assessment
- Compliance Scans - PCI DSS, HIPAA, CIS Benchmark templates

**Key Capabilities:**
- CVE and vulnerability detection
- Configuration and compliance auditing
- Credential-based scanning
- Agent-based continuous monitoring
- Integration with SIEM and ticketing systems

---

#### Nuclei
**Type:** Template-Based Vulnerability Scanner  
**Cost:** Free / Open Source  
**Website:** [https://nuclei.projectdiscovery.io/](https://nuclei.projectdiscovery.io/)  
**GitHub:** [https://github.com/projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei)

| Beacon Tier Coverage | Use Cases |
|---------------------|-----------|
| Tier 1, Tier 2 | CVE detection, misconfigurations, exposure validation |

**Integration with Beacon:**
- **Tier 1:** Validate publicly accessible resources, database exposures
- **Tier 2:** Compliance-specific vulnerability templates

**Recommended Usage:**
```bash
# Run with Beacon-relevant templates
nuclei -u TARGET -t cves/ -t misconfigurations/ -t exposures/ -o beacon-nuclei.txt
```

**Key Capabilities:**
- Fast, template-based scanning
- 7,000+ community templates
- Custom template development
- CI/CD integration
- Low false positive rate

---

### Web Application Scanners

#### Burp Suite
**Type:** Web Application Security Testing  
**Cost:** Community (Free) / Professional ($449/year) / Enterprise  
**Website:** [https://portswigger.net/burp](https://portswigger.net/burp)

| Beacon Tier Coverage | Use Cases |
|---------------------|-----------|
| Tier 1, Tier 2 | Web application testing, API security, injection detection |

**Integration with Beacon:**
- **Tier 1:** SQL injection, authentication bypass, critical web vulnerabilities
- **Tier 2:** OWASP compliance, session management issues

**Recommended Scan Configuration:**
- Crawler: Full depth with authenticated session
- Audit: Active scanning for injection flaws
- Extensions: Autorize, JSON Beautifier, Logger++

**Key Capabilities:**
- Intercepting proxy
- Automated vulnerability scanning
- Manual testing toolkit
- Extensible via BApp Store
- CI/CD integration (Enterprise)

---

### Cloud Security Scanners

#### PROWLER
**Type:** Cloud Security Assessment  
**Cost:** Free / Open Source  
**Website:** [https://prowler.cloud/](https://prowler.cloud/)  
**GitHub:** [https://github.com/prowler-cloud/prowler](https://github.com/prowler-cloud/prowler)

| Beacon Tier Coverage | Use Cases |
|---------------------|-----------|
| All Tiers | AWS, GCP, Azure security posture assessment |

**Integration with Beacon:**
- **Tier 1:** MFA enforcement, privileged access, DDoS protection
- **Tier 2:** CIS Benchmark compliance, regulatory frameworks
- **Tier 3:** Cloud hardening, RBAC, credential management

**Recommended Usage:**
```bash
# Full security assessment with compliance
prowler aws --compliance cis_3.0_aws --severity critical high medium
prowler gcp --compliance cis_2.0_gcp
prowler azure --compliance cis_2.1_azure
```

**Key Capabilities:**
- Multi-cloud support (AWS, GCP, Azure, Kubernetes)
- 300+ security checks
- CIS Benchmark compliance
- PCI DSS, HIPAA, GDPR mappings
- Integration with Security Hub, Jira, Slack

---

#### Cloudsploit
**Type:** Cloud Security Posture Management (CSPM)  
**Cost:** Free / Open Source (Commercial SaaS available)  
**Website:** [https://cloudsploit.com/](https://cloudsploit.com/)  
**GitHub:** [https://github.com/aquasecurity/cloudsploit](https://github.com/aquasecurity/cloudsploit)

| Beacon Tier Coverage | Use Cases |
|---------------------|-----------|
| All Tiers | Cloud misconfiguration detection, posture assessment |

**Integration with Beacon:**
- **Tier 1:** Publicly accessible resources, database exposure, IAM issues
- **Tier 2:** Compliance violations, encryption gaps
- **Tier 3:** Hardening opportunities, best practice deviations

**Key Capabilities:**
- AWS, Azure, GCP, Oracle Cloud support
- 150+ configuration checks
- Continuous monitoring capability
- API-based integration
- Custom plugin development

---

## Penetration Testing Frameworks

### OWASP
**Full Name:** Open Web Application Security Project  
**Website:** [https://owasp.org/](https://owasp.org/)  
**GitHub:** [https://github.com/OWASP](https://github.com/OWASP)

**Beacon Integration:**

| OWASP Resource | Beacon Application |
|----------------|-------------------|
| **OWASP Top 10** | Web vulnerability categorization (Tier 1, 2) |
| **ASVS** | Application security verification (Tier 2) |
| **Testing Guide** | Penetration testing methodology |
| **API Security Top 10** | API vulnerability prioritization (Tier 1) |
| **Mobile Top 10** | Mobile application security (Tier 1, 2) |

**Key OWASP Top 10 (2021) Mapping:**

| OWASP Category | Beacon Tier |
|----------------|-------------|
| A01 - Broken Access Control | Tier 1 |
| A02 - Cryptographic Failures | Tier 1/2 |
| A03 - Injection | Tier 1 |
| A04 - Insecure Design | Tier 2/3 |
| A05 - Security Misconfiguration | Tier 1/2 |
| A06 - Vulnerable Components | Tier 1 |
| A07 - Authentication Failures | Tier 1 |
| A08 - Software & Data Integrity Failures | Tier 1/2 |
| A09 - Security Logging Failures | Tier 2/3 |
| A10 - SSRF | Tier 1 |

---

### MITRE ATT&CK
**Full Name:** MITRE Adversarial Tactics, Techniques, and Common Knowledge  
**Website:** [https://attack.mitre.org/](https://attack.mitre.org/)  
**GitHub:** [https://github.com/mitre/cti](https://github.com/mitre/cti)

**Beacon Integration:**

| ATT&CK Application | Beacon Usage |
|-------------------|--------------|
| Technique Mapping | Link vulnerabilities to attack techniques |
| Threat Intelligence | Prioritize based on active threat actors |
| Detection Engineering | Develop detection rules for findings |
| Red Team Operations | Validate remediation effectiveness |

**Key ATT&CK Techniques Addressed by Beacon:**

| Technique | Beacon Tier | Control |
|-----------|-------------|---------|
| [T1190](https://attack.mitre.org/techniques/T1190/) - Exploit Public-Facing Application | Tier 1 | Critical Open Ports, Database Security |
| [T1078](https://attack.mitre.org/techniques/T1078/) - Valid Accounts | Tier 1 | MFA, Privileged Accounts |
| [T1110](https://attack.mitre.org/techniques/T1110/) - Brute Force | Tier 1 | Password Policies, MFA |
| [T1530](https://attack.mitre.org/techniques/T1530/) - Data from Cloud Storage | Tier 1 | Publicly Accessible Resources |
| [T1552](https://attack.mitre.org/techniques/T1552/) - Unsecured Credentials | Tier 1/3 | Credential Management |
| [T1133](https://attack.mitre.org/techniques/T1133/) - External Remote Services | Tier 1 | External Exposure |
| [T1498](https://attack.mitre.org/techniques/T1498/) - Network DoS | Tier 1 | DDoS Protection |

---

## Additional Frameworks

### CIS Controls
**Website:** [https://www.cisecurity.org/controls](https://www.cisecurity.org/controls)

The CIS Critical Security Controls provide prioritized security actions. Beacon Tier 3 findings often map to CIS Control implementations.

### NIST Cybersecurity Framework
**Website:** [https://www.nist.gov/cyberframework](https://www.nist.gov/cyberframework)

Beacon tiers align with NIST CSF functions:
- **Identify:** Asset inventory for scanning
- **Protect:** Tier 1/2/3 controls
- **Detect:** Scanner integration
- **Respond:** Prioritized remediation
- **Recover:** Tier 3 resilience improvements

---

## Scanner Selection Guide

| Requirement | Recommended Scanner |
|-------------|-------------------|
| Network port scanning | Nmap |
| Vulnerability assessment | Nessus |
| Web application testing | Burp Suite |
| Cloud security posture | PROWLER, Cloudsploit |
| CVE validation | Nuclei |
| Compliance scanning | Nessus, PROWLER |

---

## Integration Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Beacon Standards                         │
│                   Prioritization Framework                      │
└───────────────────────────┬─────────────────────────────────────┘
                            │
            ┌───────────────┼───────────────┐
            │               │               │
            ▼               ▼               ▼
     ┌──────────┐    ┌──────────┐    ┌──────────┐
     │  Tier 1  │    │  Tier 2  │    │  Tier 3  │
     │ Critical │    │Regulatory│    │   Best   │
     │ 24-72hr  │    │  30 days │    │Practices │
     └────┬─────┘    └────┬─────┘    └────┬─────┘
          │               │               │
          └───────────────┼───────────────┘
                          │
                          ▼
     ┌─────────────────────────────────────────────────────────┐
     │                    Scanner Outputs                      │
     │  Nmap │ Nessus │ Burp │ Nuclei │ PROWLER │ Cloudsploit │
     └─────────────────────────────────────────────────────────┘
```

---

*For tier-specific guidance, see the respective tier documentation.*
