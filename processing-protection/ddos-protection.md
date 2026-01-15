# DDoS Protection

## Tier: 1 - High Priority
**MITRE ATT&CK:** [T1498 - Network Denial of Service](https://attack.mitre.org/techniques/T1498/)  
**Remediation SLA:** 48 hours  
**CVSS Range:** 7.0 - 9.0

---

## Risk Description

Distributed Denial of Service (DDoS) attacks overwhelm systems with malicious traffic, causing service outages. DDoS attacks are increasingly used as diversions during data breaches, as extortion leverage, and as competitive sabotage.

### Business Impact
- Service unavailability (revenue loss, SLA breaches)
- Average DDoS attack costs $40,000/hour for enterprises
- Reputational damage from prolonged outages
- Distraction from simultaneous data breach
- Regulatory implications for availability requirements

### Attack Landscape
| Attack Type | Layer | Volume | Mitigation |
|-------------|-------|--------|------------|
| Volumetric | L3/L4 | Tbps+ | CDN/Scrubbing |
| Protocol | L3/L4 | Gbps | Rate limiting |
| Application | L7 | Low volume | WAF/Bot management |

---

## DDoS Protection Services

### Cloud-Native Protection
| Provider | Service | Coverage |
|----------|---------|----------|
| AWS | Shield Standard/Advanced | L3/L4, L7 (Advanced) |
| GCP | Cloud Armor | L3/L4, L7 |
| Azure | DDoS Protection | L3/L4, L7 |
| Cloudflare | DDoS Mitigation | L3/L4, L7 |
| Akamai | Prolexic | L3/L4, L7 |

### Protection Layers
```
Internet → CDN (Edge) → WAF → Load Balancer → Application
           ↓              ↓           ↓
        Volumetric    App Layer   Rate Limiting
        Mitigation    Filtering   + Auto-scaling
```

---

## Detection Methods

### Tools
- **[Nessus](https://www.tenable.com/products/nessus):** Infrastructure resilience assessment
- **[PROWLER](https://prowler.cloud/):** Cloud DDoS protection verification

### Detection Commands

**AWS Shield:**
```bash
# Check Shield Advanced subscription
aws shield describe-subscription

# Check protected resources
aws shield list-protections

# PROWLER check
prowler aws -c shield_advanced_protection_in_route53_hosted_zones
```

**GCP Cloud Armor:**
```bash
# List security policies
gcloud compute security-policies list

# Check policy rules
gcloud compute security-policies describe POLICY_NAME
```

### Indicators of Insufficient Protection
- No CDN or DDoS protection service enabled
- Public IPs exposed directly without filtering
- No rate limiting on API endpoints
- Auto-scaling not configured for traffic spikes
- No incident response plan for DDoS

---

## Qualifying Criteria

A finding qualifies as Tier 1 DDoS Protection issue if:

- [ ] Internet-facing services lack DDoS protection
- [ ] Origin servers directly exposed (no CDN/proxy)
- [ ] No rate limiting on public APIs
- [ ] DNS infrastructure unprotected
- [ ] No auto-scaling for traffic spikes
- [ ] No DDoS response playbook exists

---

## Remediation

### Immediate Actions (0-48 hours)

1. **Enable cloud-native DDoS protection:**

**AWS Shield Standard** (automatic for all AWS customers):
```bash
# Shield Standard is automatic. Enable Shield Advanced:
aws shield create-subscription

# Protect specific resources
aws shield create-protection \
  --name "Production-ALB" \
  --resource-arn arn:aws:elasticloadbalancing:REGION:ACCOUNT:loadbalancer/app/ALB-NAME/ID
```

**GCP Cloud Armor:**
```bash
# Create security policy
gcloud compute security-policies create ddos-protection \
  --description "DDoS protection policy"

# Add rate limiting rule
gcloud compute security-policies rules create 1000 \
  --security-policy ddos-protection \
  --expression "true" \
  --action "rate-based-ban" \
  --rate-limit-threshold-count 1000 \
  --rate-limit-threshold-interval-sec 60 \
  --ban-duration-sec 600
```

2. **Deploy CDN with DDoS mitigation:**
```bash
# Cloudflare via Terraform
resource "cloudflare_zone_settings_override" "settings" {
  zone_id = var.zone_id
  settings {
    security_level = "high"
    challenge_ttl  = 1800
    browser_check  = "on"
  }
}
```

### Rate Limiting Configuration

**NGINX:**
```nginx
# Rate limiting zone
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;

server {
    location /api/ {
        limit_req zone=api burst=20 nodelay;
        limit_req_status 429;
    }
}
```

**AWS API Gateway:**
```bash
# Create usage plan with throttling
aws apigateway create-usage-plan \
  --name "Standard" \
  --throttle burstLimit=100,rateLimit=50
```

### Auto-Scaling Configuration
```hcl
# Terraform - AWS Auto Scaling
resource "aws_autoscaling_policy" "scale_out" {
  name                   = "scale-out-on-attack"
  scaling_adjustment     = 200  # Scale to 3x capacity
  adjustment_type        = "PercentChangeInCapacity"
  cooldown              = 60
  autoscaling_group_name = aws_autoscaling_group.web.name
}

resource "aws_cloudwatch_metric_alarm" "high_requests" {
  alarm_name          = "high-request-count"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "RequestCount"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Sum"
  threshold           = 10000
  alarm_actions       = [aws_autoscaling_policy.scale_out.arn]
}
```

---

## DDoS Response Playbook

### Phase 1: Detection (0-5 minutes)
- [ ] Confirm DDoS attack via monitoring
- [ ] Identify attack type and vector
- [ ] Alert incident response team
- [ ] Notify cloud provider (if applicable)

### Phase 2: Mitigation (5-30 minutes)
- [ ] Engage DDoS protection service
- [ ] Implement emergency rate limiting
- [ ] Scale infrastructure if applicable
- [ ] Block obvious attack sources

### Phase 3: Analysis (30+ minutes)
- [ ] Analyze attack patterns
- [ ] Identify targeted endpoints
- [ ] Check for concurrent data breach
- [ ] Fine-tune mitigation rules

### Phase 4: Recovery
- [ ] Gradually relax emergency controls
- [ ] Monitor for attack resumption
- [ ] Document lessons learned
- [ ] Update protection rules

---

## Architecture Best Practices

```
┌─────────────────────────────────────────────────────────────┐
│                    DDoS-Resistant Architecture              │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   Internet                                                  │
│      │                                                      │
│      ▼                                                      │
│   [Anycast DNS] ─── Geo-distributed DNS with DDoS          │
│      │                                                      │
│      ▼                                                      │
│   [CDN/Edge] ─── Cloudflare/Akamai/CloudFront              │
│      │           (Volumetric attack absorption)             │
│      ▼                                                      │
│   [WAF] ─── Application layer attack filtering              │
│      │                                                      │
│      ▼                                                      │
│   [Load Balancer] ─── Rate limiting, health checks          │
│      │                                                       │
│      ▼                                                      │
│   [Auto-Scaling App Tier] ─── Elastic capacity              │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Monitoring Requirements

| Metric | Normal | Alert Threshold |
|--------|--------|-----------------|
| Requests/sec | Baseline | 10x baseline |
| Bandwidth | Baseline | 5x baseline |
| Error rate (5xx) | <1% | >5% |
| Response time | Baseline | 3x baseline |
| Connection count | Baseline | 10x baseline |

---

## References

- [AWS Shield Best Practices](https://docs.aws.amazon.com/waf/latest/developerguide/ddos-overview.html)
- [CISA DDoS Attack Guidance](https://www.cisa.gov/sites/default/files/publications/understanding-and-responding-to-ddos-attacks_508c.pdf)
- [Cloudflare DDoS Trends Report](https://www.cloudflare.com/ddos-threat-report/)

---

*For scanner details, see [Scanners and Frameworks](../scanners-and-frameworks.md)*
