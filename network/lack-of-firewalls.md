# Lack of Firewalls

## Tier: 1 - High Priority
**MITRE ATT&CK:** [T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)  
**Remediation SLA:** 48 hours  
**CVSS Range:** 7.0 - 9.0

---

## Risk Description

Systems without network or application-layer firewall protection are directly exposed to all network traffic. Attackers can probe, enumerate, and exploit services without any filtering or detection. This is equivalent to leaving your front door wide open in a high-crime neighborhood.

### Business Impact
- Direct exploitation of all exposed services
- No barrier to lateral movement once inside
- Inability to detect or block malicious traffic
- No defense against automated attack tools

### Defense-in-Depth Failure
Firewalls represent the first layer of network defense:
- **Without firewalls:** Every service is an attack surface
- **With firewalls:** Only necessary services are exposed, with logging

---

## Firewall Types Required

### Network Firewalls
| Type | Purpose | Examples |
|------|---------|----------|
| Perimeter Firewall | Internet boundary protection | Palo Alto, Fortinet, pfSense |
| Cloud Security Groups | Virtual machine protection | AWS SG, GCP Firewall, Azure NSG |
| Host Firewall | OS-level filtering | iptables, Windows Firewall, firewalld |

### Application Firewalls
| Type | Purpose | Examples |
|------|---------|----------|
| Web Application Firewall | HTTP/HTTPS attack filtering | AWS WAF, Cloudflare, ModSecurity |
| Database Firewall | SQL attack protection | Oracle, DataSunrise |
| API Gateway | API-level protection | Kong, Apigee, AWS API Gateway |

---

## Detection Methods

### Tools
- **[Nessus](https://www.tenable.com/products/nessus):** Firewall presence and configuration assessment
- **[Burp Suite](https://portswigger.net/burp):** WAF detection and bypass testing

### Detection Techniques

```bash
# Check for WAF presence via response headers
curl -I https://target.com | grep -i "waf\|firewall\|protect"

# NMAP firewall detection
nmap --script=firewalk TARGET

# Cloud firewall audit (AWS)
aws ec2 describe-security-groups --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]]'
```

### Indicators of Missing Protection
- Services accessible without apparent filtering
- No connection rate limiting observed
- Attack payloads not blocked (SQLi, XSS)
- No security headers in HTTP responses
- Unrestricted egress traffic

---

## Qualifying Criteria

A finding qualifies as Tier 1 Lack of Firewall if:

- [ ] No network ACL or security group configured
- [ ] Security group allows 0.0.0.0/0 to all ports
- [ ] Web applications lack WAF protection
- [ ] No host-based firewall enabled
- [ ] Egress traffic completely unrestricted

---

## Remediation

### Network Firewall (0-48 hours)
1. Deploy default-deny security groups/ACLs
2. Allow only required ports from required sources
3. Enable stateful inspection
4. Configure logging for all allowed and denied traffic

### Example Security Group (AWS)
```json
{
  "IpPermissions": [
    {
      "IpProtocol": "tcp",
      "FromPort": 443,
      "ToPort": 443,
      "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "HTTPS inbound"}]
    },
    {
      "IpProtocol": "tcp",
      "FromPort": 22,
      "ToPort": 22,
      "IpRanges": [{"CidrIp": "10.0.0.0/8", "Description": "SSH from internal"}]
    }
  ]
}
```

### Web Application Firewall (7-14 days)
1. Deploy WAF in front of all public web applications
2. Enable OWASP Core Rule Set (CRS)
3. Configure custom rules for application-specific attacks
4. Tune false positives while maintaining protection
5. Enable bot management and rate limiting

### Host Firewall
```bash
# Linux - Enable UFW
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw enable

# Windows - Enable Windows Firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
```

### Egress Filtering
1. Block all outbound traffic by default
2. Allow only required destinations (DNS, NTP, updates)
3. Use proxy for HTTP/HTTPS egress
4. Monitor for command-and-control indicators

---

## Compensating Controls

If full firewall deployment is delayed:
- Implement network segmentation
- Deploy IDS/IPS for visibility
- Enable comprehensive logging
- Implement rate limiting at application layer
- Conduct more frequent vulnerability scanning

---

## Firewall Testing

Validate firewall effectiveness:
```bash
# Test blocked port
nc -zv target 3389  # Should timeout or be refused

# Test WAF (should be blocked)
curl "https://target.com/?id=1' OR '1'='1"

# Test egress filtering
curl -x proxy.internal:8080 https://external.com
```

---

## References

- [CIS Control 4: Secure Configuration of Network Devices](https://www.cisecurity.org/controls/secure-configuration-of-enterprise-assets-and-software)
- [NIST SP 800-41: Firewall Guidelines](https://csrc.nist.gov/publications/detail/sp/800-41/rev-1/final)
- [OWASP ModSecurity Core Rule Set](https://coreruleset.org/)

---

*For scanner details, see [Scanners and Frameworks](../scanners-and-frameworks.md)*
