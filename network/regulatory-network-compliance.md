# Regulatory Network Compliance

## Tier: 2 - Regulatory
**Applicable Frameworks:** PCI DSS 1.x, HIPAA §164.312(e), SOC 2 CC6.6, ISO 27001 A.13  
**Remediation SLA:** 30 days  
**Audit Impact:** Direct finding / Exception

---

## Compliance Overview

Network security controls are fundamental to every major compliance framework. Auditors specifically examine network architecture, segmentation, access controls, and monitoring. Non-compliance can result in failed audits, certification loss, and regulatory penalties.

### Framework Requirements Summary

| Framework | Key Network Requirements |
|-----------|-------------------------|
| **PCI DSS** | Network segmentation, firewall rules, restricted CDE access |
| **HIPAA** | Technical safeguards for ePHI transmission |
| **SOC 2** | Logical access controls, network monitoring |
| **ISO 27001** | Network security controls (A.13) |
| **NIST CSF** | Protect function - network security |

---

## PCI DSS Network Requirements

### Requirement 1: Install and Maintain Network Security Controls

| Sub-Req | Description | Evidence Required |
|---------|-------------|-------------------|
| 1.1.1 | Document network security controls | Network topology diagrams |
| 1.2.1 | Restrict inbound traffic to CDE | Firewall rule documentation |
| 1.3.1 | Restrict outbound traffic from CDE | Egress filtering evidence |
| 1.4 | Network segmentation for PCI scope reduction | Segmentation test results |

### Cardholder Data Environment (CDE) Segmentation
```
┌─────────────────────────────────────────────────────────────┐
│                    PCI DSS Network Model                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   Internet Zone                                             │
│       │                                                     │
│       ▼                                                     │
│   [Firewall] ─── Only HTTPS (443) permitted                │
│       │                                                     │
│       ▼                                                     │
│   DMZ Zone ─── Web servers, reverse proxies                │
│       │                                                     │
│       ▼                                                     │
│   [Firewall] ─── Application-specific ports only           │
│       │                                                     │
│       ▼                                                     │
│   CDE Zone ─── Payment processing, card data storage       │
│       │         Strictly segmented from other networks      │
│       │                                                     │
│   [Firewall] ─── Database-specific ports only              │
│       │                                                     │
│       ▼                                                     │
│   Database Zone ─── Encrypted card data at rest            │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Detection Methods

### Tools
- **[Nessus](https://www.tenable.com/products/nessus):** PCI DSS compliance scanning
- **[PROWLER](https://prowler.cloud/):** Cloud compliance assessment

### Compliance Scan Commands

```bash
# Nessus PCI DSS scan (via CLI)
nessuscli scan --policy "PCI DSS Compliance" --targets NETWORK_RANGE

# PROWLER PCI compliance
prowler aws --compliance pci_3.2.1_aws

# AWS Config PCI conformance pack
aws configservice put-conformance-pack \
  --conformance-pack-name pci-compliance \
  --template-s3-uri s3://awsconfigconforms/pci-dss-3.2.1-conformance-pack.yaml
```

---

## Qualifying Criteria

A finding qualifies as Tier 2 Network Compliance if:

**PCI DSS:**
- [ ] CDE not properly segmented from other networks
- [ ] Firewall rules not documented and reviewed quarterly
- [ ] Default passwords on network devices
- [ ] Inbound internet traffic allowed directly to CDE
- [ ] Missing IDS/IPS on CDE network segments

**HIPAA:**
- [ ] ePHI transmitted without encryption
- [ ] No access controls on network containing ePHI
- [ ] Missing audit logs for network access

**SOC 2:**
- [ ] No network monitoring or alerting
- [ ] Missing documentation of network changes
- [ ] Inadequate network access controls

---

## Remediation

### Network Segmentation

```hcl
# Terraform - AWS VPC segmentation
resource "aws_vpc" "pci" {
  cidr_block = "10.0.0.0/16"
  tags = { Name = "PCI-VPC", Compliance = "PCI-DSS" }
}

resource "aws_subnet" "cde" {
  vpc_id     = aws_vpc.pci.id
  cidr_block = "10.0.1.0/24"
  tags       = { Name = "CDE-Subnet", PCI-Zone = "CDE" }
}

resource "aws_network_acl" "cde" {
  vpc_id     = aws_vpc.pci.id
  subnet_ids = [aws_subnet.cde.id]
  
  # Deny all by default, allow specific
  ingress {
    rule_no    = 100
    action     = "allow"
    protocol   = "tcp"
    from_port  = 443
    to_port    = 443
    cidr_block = "10.0.0.0/24"  # Only from app tier
  }
  
  egress {
    rule_no    = 100
    action     = "deny"
    protocol   = "-1"
    from_port  = 0
    to_port    = 0
    cidr_block = "0.0.0.0/0"  # No internet egress from CDE
  }
}
```

### Firewall Rule Documentation

Maintain documentation including:
1. Rule number and priority
2. Source and destination (IP/range)
3. Ports and protocols
4. Business justification
5. Rule owner and approval date
6. Last review date

### Quarterly Review Process
1. Export current firewall rules
2. Compare to documented baseline
3. Investigate any discrepancies
4. Remove unnecessary rules
5. Document review completion
6. Sign-off by security manager

---

## Evidence Collection

| Requirement | Evidence Type | Retention |
|-------------|---------------|-----------|
| Network diagrams | PDF/Visio | Current + 1 year |
| Firewall rules | Export/screenshot | Current + quarterly |
| Change tickets | Ticket system export | 1 year minimum |
| Segmentation tests | Penetration test report | Annual |
| Review approvals | Signed documents | 1 year minimum |
| IDS/IPS logs | SIEM/log storage | 1 year (PCI) |

---

## Common Audit Findings

| Finding | Remediation |
|---------|-------------|
| Flat network (no segmentation) | Implement VLANs/subnets |
| Any-to-any firewall rules | Replace with specific rules |
| Missing rule justification | Document all rules |
| No quarterly rule review | Implement review process |
| Default device passwords | Rotate to strong passwords |
| Missing IDS/IPS | Deploy network monitoring |

---

## References

- [PCI DSS v4.0 Requirements](https://www.pcisecuritystandards.org/document_library/)
- [HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/)
- [SOC 2 Trust Services Criteria](https://www.aicpa.org/resources/landing/system-and-organization-controls-soc-suite-of-services)

---

*For scanner details, see [Scanners and Frameworks](../scanners-and-frameworks.md)*
