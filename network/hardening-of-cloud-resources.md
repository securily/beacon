# Hardening of Cloud Resources

## Tier: 3 - Best Practices
**CIS Controls:** 4.1 - Establish and Maintain a Secure Configuration Process  
**Remediation SLA:** 90 days  
**Risk Level:** Configuration drift prevention

---

## Overview

Cloud resource hardening involves applying security configurations that reduce the attack surface and limit potential damage from compromises. While default cloud configurations often prioritize functionality over security, hardened configurations follow the principle of least functionality.

### Why Hardening Matters
- Default configurations often insecure
- Reduces attack surface significantly
- Prevents configuration drift
- Enables consistent security posture
- Required for CIS Benchmark compliance

---

## CIS Benchmark Alignment

### AWS CIS Benchmark Key Controls

| Section | Control Area | Priority |
|---------|-------------|----------|
| 1.x | Identity and Access Management | High |
| 2.x | Storage (S3) | High |
| 3.x | Logging | High |
| 4.x | Monitoring | Medium |
| 5.x | Networking | High |

### GCP CIS Benchmark Key Controls

| Section | Control Area | Priority |
|---------|-------------|----------|
| 1.x | IAM | High |
| 2.x | Logging and Monitoring | Medium |
| 3.x | Networking | High |
| 4.x | Virtual Machines | High |
| 5.x | Storage | High |
| 6.x | Cloud SQL | High |

---

## Detection Methods

### Tools
- **[Cloudsploit](https://cloudsploit.com/):** Cloud security posture assessment
- **[PROWLER](https://prowler.cloud/):** CIS Benchmark compliance checking

### Compliance Scan Commands

```bash
# PROWLER - Full CIS compliance check
prowler aws --compliance cis_3.0_aws --output-formats json,html

# Cloudsploit
cloudsploit scan --cloud aws --compliance cis

# AWS Security Hub (if enabled)
aws securityhub get-findings --filters '{"GeneratorId":[{"Value":"cis-aws-foundations-benchmark","Comparison":"PREFIX"}]}'

# AWS Config conformance
aws configservice get-conformance-pack-compliance-summary \
  --conformance-pack-names operational-best-practices-for-cis-aws
```

---

## Qualifying Criteria

A finding qualifies as Tier 3 Hardening issue if:

- [ ] Resources not conforming to CIS Benchmarks
- [ ] Missing resource tagging (owner, environment, data classification)
- [ ] Default security group/firewall configurations
- [ ] Instance metadata service v1 enabled (AWS)
- [ ] Missing or disabled logging
- [ ] Unused or orphaned resources
- [ ] OS not following hardening standards

---

## Hardening Checklists

### Compute Instance Hardening

**AWS EC2:**
```bash
# Disable IMDSv1 (require IMDSv2)
aws ec2 modify-instance-metadata-options \
  --instance-id i-1234567890abcdef0 \
  --http-tokens required \
  --http-endpoint enabled

# Enable detailed monitoring
aws ec2 monitor-instances --instance-ids i-1234567890abcdef0

# Enforce EBS encryption
aws ec2 enable-ebs-encryption-by-default
```

**Terraform Implementation:**
```hcl
resource "aws_instance" "hardened" {
  ami           = var.hardened_ami_id
  instance_type = "t3.medium"
  
  # IMDSv2 only
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
  
  # Encrypted root volume
  root_block_device {
    encrypted   = true
    kms_key_id  = var.ebs_kms_key_id
  }
  
  # Monitoring
  monitoring = true
  
  # Required tags
  tags = {
    Name          = "hardened-instance"
    Owner         = "platform-team"
    Environment   = "production"
    DataClass     = "internal"
    CostCenter    = "engineering"
    BackupPolicy  = "daily"
  }
}
```

### Storage Hardening

**S3 Bucket Hardening:**
```hcl
resource "aws_s3_bucket" "hardened" {
  bucket = "hardened-bucket-${var.account_id}"
}

resource "aws_s3_bucket_public_access_block" "hardened" {
  bucket = aws_s3_bucket.hardened.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "hardened" {
  bucket = aws_s3_bucket.hardened.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "hardened" {
  bucket = aws_s3_bucket.hardened.id
  
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.s3_kms_key_id
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_logging" "hardened" {
  bucket        = aws_s3_bucket.hardened.id
  target_bucket = var.log_bucket_id
  target_prefix = "s3-access-logs/${aws_s3_bucket.hardened.id}/"
}
```

### Network Hardening

```hcl
# VPC Flow Logs
resource "aws_flow_log" "vpc" {
  vpc_id          = aws_vpc.main.id
  traffic_type    = "ALL"
  iam_role_arn    = aws_iam_role.flow_log.arn
  log_destination = aws_cloudwatch_log_group.flow_log.arn
}

# Default security group - deny all
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id
  # No ingress or egress rules = deny all
}

# Restrict default NACL
resource "aws_default_network_acl" "default" {
  default_network_acl_id = aws_vpc.main.default_network_acl_id
  
  # Explicit deny all (no rules = deny)
  tags = {
    Name = "default-deny"
  }
}
```

---

## OS Hardening

### Linux Hardening (CIS Benchmark)

```bash
# Disable unused filesystems
cat >> /etc/modprobe.d/CIS.conf << EOF
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install udf /bin/true
EOF

# Set permissions on sensitive files
chmod 600 /etc/shadow
chmod 644 /etc/passwd
chmod 644 /etc/group
chmod 600 /boot/grub/grub.cfg

# Configure SSH hardening
cat >> /etc/ssh/sshd_config << EOF
Protocol 2
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
MaxAuthTries 4
ClientAliveInterval 300
ClientAliveCountMax 0
AllowTcpForwarding no
X11Forwarding no
EOF

# Enable audit logging
systemctl enable auditd
systemctl start auditd
```

### Golden AMI Pipeline

```yaml
# Packer template for hardened AMI
source "amazon-ebs" "hardened" {
  ami_name      = "hardened-base-{{timestamp}}"
  instance_type = "t3.medium"
  region        = "us-east-1"
  
  source_ami_filter {
    filters = {
      virtualization-type = "hvm"
      name                = "amzn2-ami-hvm-*-x86_64-gp2"
      root-device-type    = "ebs"
    }
    most_recent = true
    owners      = ["amazon"]
  }
  
  ssh_username = "ec2-user"
}

build {
  sources = ["source.amazon-ebs.hardened"]
  
  provisioner "shell" {
    scripts = [
      "scripts/update-packages.sh",
      "scripts/cis-hardening.sh",
      "scripts/install-agents.sh",
      "scripts/cleanup.sh"
    ]
  }
  
  provisioner "inspec" {
    profile = "https://github.com/dev-sec/linux-baseline"
  }
}
```

---

## Tagging Standards

### Required Tags

| Tag Key | Description | Example |
|---------|-------------|---------|
| `Name` | Resource identifier | `prod-web-server-01` |
| `Owner` | Team/individual responsible | `platform-team` |
| `Environment` | Deployment stage | `production`, `staging`, `development` |
| `DataClassification` | Sensitivity level | `public`, `internal`, `confidential`, `restricted` |
| `CostCenter` | Billing allocation | `engineering-123` |
| `BackupPolicy` | Backup requirements | `daily`, `weekly`, `none` |
| `Compliance` | Regulatory scope | `pci`, `hipaa`, `none` |

### Tag Enforcement

```hcl
# AWS Config rule for required tags
resource "aws_config_config_rule" "required_tags" {
  name = "required-tags"
  
  source {
    owner             = "AWS"
    source_identifier = "REQUIRED_TAGS"
  }
  
  input_parameters = jsonencode({
    tag1Key   = "Owner"
    tag2Key   = "Environment"
    tag3Key   = "DataClassification"
    tag4Key   = "CostCenter"
  })
}
```

---

## Drift Detection

### Automated Compliance Monitoring

```yaml
# GitHub Actions - Daily compliance check
name: Cloud Compliance Check
on:
  schedule:
    - cron: '0 6 * * *'  # Daily at 6 AM

jobs:
  prowler:
    runs-on: ubuntu-latest
    steps:
      - name: Run PROWLER
        run: |
          pip install prowler
          prowler aws --compliance cis_3.0_aws \
            --severity critical high medium \
            --output-formats json \
            --output-directory reports/
            
      - name: Upload results
        uses: actions/upload-artifact@v3
        with:
          name: prowler-report
          path: reports/
          
      - name: Notify on failures
        if: failure()
        run: |
          # Send to Slack/email
```

---

## References

- [CIS Benchmarks](https://www.cisecurity.org/benchmark)
- [AWS Well-Architected Framework](https://aws.amazon.com/architecture/well-architected/)
- [GCP Security Best Practices](https://cloud.google.com/security/best-practices)
- [Azure Security Benchmark](https://docs.microsoft.com/en-us/security/benchmark/azure/)

---

*For scanner details, see [Scanners and Frameworks](../scanners-and-frameworks.md)*
