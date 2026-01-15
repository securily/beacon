# Critical Open Ports

## Tier: 1 - High Priority
**MITRE ATT&CK:** [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)  
**Remediation SLA:** 24 hours  
**CVSS Range:** 7.5 - 10.0

---

## Risk Description

Open ports on internet-facing systems are the primary attack vector for initial access. Attackers continuously scan the IPv4 address space for exposed services, and automated exploitation frameworks can compromise vulnerable services within minutes of discovery.

### Business Impact
- Direct system compromise leading to data exfiltration
- Ransomware deployment via exposed RDP, SMB, or SSH
- Botnet recruitment for DDoS or cryptomining
- Lateral movement pivot point into internal networks

### Attack Scenario
1. Attacker scans internet for exposed port 3389 (RDP)
2. Discovers target with RDP accessible from internet
3. Launches credential stuffing attack or exploits BlueKeep (CVE-2019-0708)
4. Gains initial access, escalates privileges, deploys ransomware

---

## Critical Port Classification

| Port | Service | Risk Level | Common Exploits |
|------|---------|------------|-----------------|
| 22 | SSH | Critical | Brute force, CVE-2024-6387 (regreSSHion) |
| 23 | Telnet | Critical | Cleartext credentials, ancient vulns |
| 445 | SMB | Critical | EternalBlue, SMBGhost, ransomware |
| 3389 | RDP | Critical | BlueKeep, credential stuffing, session hijack |
| 1433 | MSSQL | Critical | SQL injection, sa brute force |
| 3306 | MySQL | Critical | Default creds, UDF exploitation |
| 5432 | PostgreSQL | Critical | Default creds, extension abuse |
| 27017 | MongoDB | Critical | No auth by default (pre-4.0) |
| 6379 | Redis | Critical | No auth, LUA script execution |
| 9200 | Elasticsearch | Critical | No auth, arbitrary read/write |
| 5900 | VNC | Critical | Weak auth, session hijacking |

---

## Detection Methods

### Tools
- **[Nmap](https://nmap.org/):** Network port scanning with service detection
- **[Nessus](https://www.tenable.com/products/nessus):** Vulnerability identification on exposed services

### Scan Commands

```bash
# Quick critical port scan
nmap -Pn -sS -p 22,23,445,1433,3306,3389,5432,5900,6379,9200,27017 TARGET

# Full TCP scan with service detection
nmap -sS -sV -sC -p- -oX critical-ports.xml TARGET

# UDP critical services
nmap -sU -p 161,162,500,1194,1900 TARGET
```

### Indicators of Exposure
- Port open from any IP (0.0.0.0/0)
- Default service banners visible
- Authentication not required
- Known vulnerable versions detected

---

## Qualifying Criteria

A finding qualifies as Tier 1 Critical Open Port if:

- [ ] Port is accessible from internet (verified via external scan)
- [ ] Service runs SSH, RDP, SMB, Telnet, or database protocol
- [ ] No VPN, bastion host, or zero-trust gateway in front
- [ ] Port not documented as business-required with compensating controls
- [ ] Service version has known critical CVEs

---

## Remediation

### Immediate Actions (0-24 hours)
1. Block port at network firewall immediately
2. Verify no active compromise via log review
3. Document business impact of blocking

### Short-term (24-72 hours)
4. Move service behind VPN or ZTNA solution
5. Implement IP allowlisting if VPN not feasible
6. Enable MFA for any authentication
7. Update service to latest patched version

### Long-term
8. Implement network segmentation
9. Deploy jump box/bastion host architecture
10. Automate port exposure scanning in CI/CD

---

## Compensating Controls

If port must remain exposed:
- Implement geo-blocking (allow only required countries)
- Deploy fail2ban or equivalent brute force protection
- Enable comprehensive audit logging
- Implement real-time alerting on authentication failures
- Require MFA for all access
- Schedule recurring vulnerability scans

---

## References

- [CISA Alert: Critical RDP Vulnerabilities](https://www.cisa.gov/rdp)
- [SANS Internet Storm Center: Port Statistics](https://isc.sans.edu/port.html)
- [Shodan Search Engine](https://www.shodan.io/) - For exposure validation

---

*For scanner details, see [Scanners and Frameworks](../scanners-and-frameworks.md)*
