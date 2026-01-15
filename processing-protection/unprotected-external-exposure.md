# Unprotected External Exposure

## Tier: 1 - High Priority
**MITRE ATT&CK:** [T1133 - External Remote Services](https://attack.mitre.org/techniques/T1133/)  
**Remediation SLA:** 24 hours  
**CVSS Range:** 8.0 - 10.0

---

## Risk Description

Compute resources (virtual machines, containers, serverless functions) directly exposed to the internet without protective layers are prime targets for automated exploitation. Every minute these systems remain exposed increases the probability of compromise.

### Business Impact
- Direct exploitation of vulnerable services
- Cryptocurrency mining deployment
- Botnet recruitment
- Pivot point for internal network attacks
- Ransomware deployment

### Exposure Statistics
- Shodan indexes ~12M exposed services daily
- Average time to exploitation of new vulnerability: <15 minutes
- Automated scanners probe every IPv4 address multiple times daily

---

## Exposure Patterns

### High-Risk Exposures
| Resource Type | Risk | Attack Vector |
|---------------|------|---------------|
| SSH (22) | Critical | Brute force, CVE exploitation |
| RDP (3389) | Critical | BlueKeep, credential stuffing |
| Kubernetes API (6443) | Critical | Unauthenticated API access |
| Docker API (2375) | Critical | Container escape, host compromise |
| Admin consoles | Critical | Default creds, known CVEs |
| Development servers | High | Weaker security controls |

### Required Protective Layers
```
Internet → CDN/WAF → Load Balancer → Security Group → VM
                                           ↓
                                    Bastion/VPN for admin
```

---

## Detection Methods

### Tools
- **[Cloudsploit](https://cloudsploit.com/):** Cloud resource exposure detection
- **[Nmap](https://nmap.org/):** External service enumeration

### Detection Commands

**AWS:**
```bash
# Find EC2 instances with public IPs
aws ec2 describe-instances \
  --query 'Reservations[].Instances[?PublicIpAddress!=null].{ID:InstanceId,IP:PublicIpAddress,SG:SecurityGroups[*].GroupId}' \
  --output table

# Check security groups allowing 0.0.0.0/0
aws ec2 describe-security-groups \
  --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]].{ID:GroupId,Name:GroupName}'

# PROWLER checks
prowler aws -c ec2_instance_public_ip -c ec2_securitygroup_allow_ingress_from_internet_to_any_port
```

**GCP:**
```bash
# Find VMs with external IPs
gcloud compute instances list \
  --filter="networkInterfaces.accessConfigs.natIP:*" \
  --format="table(name,zone,networkInterfaces[0].accessConfigs[0].natIP)"

# Check firewall rules
gcloud compute firewall-rules list \
  --filter="sourceRanges:0.0.0.0/0"
```

**Kubernetes:**
```bash
# Check for exposed services
kubectl get services --all-namespaces -o wide | grep LoadBalancer

# Check API server exposure
kubectl cluster-info
```

---

## Qualifying Criteria

A finding qualifies as Tier 1 Unprotected External Exposure if:

- [ ] Compute resource has public IP without load balancer
- [ ] Management ports accessible from internet (SSH, RDP, etc.)
- [ ] No WAF or CDN in front of web services
- [ ] Kubernetes API publicly accessible
- [ ] Docker daemon exposed to internet
- [ ] Development/staging systems publicly accessible
- [ ] Admin interfaces without VPN/bastion requirement

---

## Remediation

### Immediate Actions (0-24 hours)

1. **Remove public IPs or block management ports:**

```bash
# AWS - Restrict security group
aws ec2 revoke-security-group-ingress \
  --group-id sg-123456 \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0

# Allow only from bastion
aws ec2 authorize-security-group-ingress \
  --group-id sg-123456 \
  --protocol tcp \
  --port 22 \
  --source-group sg-bastion
```

2. **Deploy load balancer for web traffic:**

```hcl
# Terraform - ALB in front of EC2
resource "aws_lb" "web" {
  name               = "web-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = var.public_subnets
}

resource "aws_security_group" "ec2" {
  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]  # Only from ALB
  }
}
```

### Bastion Host Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Secure Access Architecture               │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   Admin User                                                │
│       │                                                     │
│       ▼                                                     │
│   [VPN/SSO] ─── MFA Required                               │
│       │                                                     │
│       ▼                                                     │
│   [Bastion Host] ─── Session recording, audit logging      │
│       │               Hardened, minimal services            │
│       │               Auto-patching enabled                 │
│       ▼                                                     │
│   [Private Network]                                         │
│       │                                                     │
│       ▼                                                     │
│   [Target Servers] ─── No public IPs                       │
│                        No direct internet access            │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### AWS Session Manager (Eliminate SSH Exposure)
```bash
# Install SSM agent on EC2 (Amazon Linux)
sudo yum install -y amazon-ssm-agent
sudo systemctl enable amazon-ssm-agent
sudo systemctl start amazon-ssm-agent

# Connect without SSH
aws ssm start-session --target i-1234567890abcdef0
```

### Zero-Trust Network Access
```yaml
# Example: Cloudflare Access configuration
ingress:
  - hostname: admin.example.com
    service: http://internal-admin:8080
    originRequest:
      access:
        required: true
        teamName: "my-team"
```

---

## Kubernetes Hardening

```yaml
# Restrict API server access
apiVersion: v1
kind: Service
metadata:
  name: kubernetes
  namespace: default
spec:
  type: ClusterIP  # Not LoadBalancer
---
# Network policy to restrict pod traffic
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-external
spec:
  podSelector: {}
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector: {}  # Only from within cluster
```

---

## Monitoring Requirements

| Indicator | Detection | Response |
|-----------|-----------|----------|
| New public IP assigned | CloudTrail/Audit logs | Immediate alert |
| Security group opened to 0.0.0.0/0 | Config rules | Block and alert |
| SSH from internet | VPC Flow Logs | Investigate |
| Failed auth attempts | CloudWatch/SIEM | Rate limit and alert |
| New LoadBalancer service (K8s) | K8s audit logs | Review and approve |

---

## Compensating Controls

If immediate remediation not possible:
- Implement strict IP allowlisting
- Enable aggressive rate limiting
- Deploy IDS/IPS monitoring
- Enable comprehensive logging
- Conduct daily vulnerability scans
- Set hard deadline for proper architecture

---

## References

- [AWS VPC Security Best Practices](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-best-practices.html)
- [GCP Secure VM Access](https://cloud.google.com/compute/docs/access/oslogin)
- [Kubernetes Hardening Guide](https://kubernetes.io/docs/concepts/security/hardening-guide/)

---

*For scanner details, see [Scanners and Frameworks](../scanners-and-frameworks.md)*
