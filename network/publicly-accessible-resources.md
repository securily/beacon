# Publicly Accessible Resources

## Tier: 1 - High Priority
**MITRE ATT&CK:** [T1530 - Data from Cloud Storage Object](https://attack.mitre.org/techniques/T1530/)  
**Remediation SLA:** 24 hours  
**CVSS Range:** 8.0 - 10.0

---

## Risk Description

Cloud resources—storage buckets, databases, virtual machines, serverless functions—configured with public access represent the most common cause of massive data breaches. A single misconfigured S3 bucket can expose millions of records within hours of creation.

### Business Impact
- Mass data exposure (customer PII, credentials, proprietary data)
- Regulatory penalties (GDPR, HIPAA, PCI DSS violations)
- Reputational damage and customer trust erosion
- Ransomware via exposed storage or compute

### Real-World Incidents
| Incident | Cause | Records Exposed |
|----------|-------|-----------------|
| Capital One (2019) | Misconfigured WAF + SSRF | 100M+ |
| Microsoft (2019) | Unprotected Elasticsearch | 250M |
| Facebook (2019) | Public S3 buckets | 540M |
| Twitch (2021) | Exposed Git server | 125GB source code |

---

## Resource Types at Risk

### Storage
| Cloud | Service | Common Misconfiguration |
|-------|---------|------------------------|
| AWS | S3 Bucket | Public ACL, bucket policy |
| GCP | Cloud Storage | allUsers/allAuthenticatedUsers IAM |
| Azure | Blob Storage | Public container access |

### Databases
| Cloud | Service | Risk |
|-------|---------|------|
| AWS | RDS, DocumentDB, DynamoDB | Public subnet, no security group |
| GCP | Cloud SQL, Firestore | 0.0.0.0/0 authorized networks |
| Azure | SQL Database, Cosmos DB | Public endpoint enabled |

### Compute
| Cloud | Service | Risk |
|-------|---------|------|
| AWS | EC2, Lambda | Public IP, permissive security group |
| GCP | Compute Engine, Cloud Functions | External IP, open firewall |
| Azure | VMs, Functions | Public IP, permissive NSG |

---

## Detection Methods

### Tools
- **[Cloudsploit](https://cloudsploit.com/):** Cloud misconfiguration scanning
- **[Nuclei](https://nuclei.projectdiscovery.io/):** Template-based exposure detection
- **[PROWLER](https://prowler.cloud/):** Multi-cloud security assessment

### Example Commands

```bash
# PROWLER - Check for public resources
prowler aws -c s3_bucket_public_access -c rds_instance_publicly_accessible

# Cloudsploit
cloudsploit scan --cloud aws --config config.js

# AWS CLI - Manual S3 check
aws s3api get-bucket-acl --bucket BUCKET_NAME
aws s3api get-bucket-policy --bucket BUCKET_NAME
```

### Detection Queries

**AWS Config Rules:**
- `s3-bucket-public-read-prohibited`
- `rds-instance-public-access-check`
- `ec2-instance-no-public-ip`

---

## Qualifying Criteria

A finding qualifies as Tier 1 Publicly Accessible if:

- [ ] Resource accepts connections from 0.0.0.0/0 or `::/0`
- [ ] No authentication required for read or write access
- [ ] Resource contains or processes sensitive data
- [ ] Public access is not documented and approved
- [ ] No compensating controls (WAF, DDoS protection) in place

---

## Remediation

### Immediate Actions (0-24 hours)
1. Remove public access immediately
2. Review access logs for unauthorized access
3. Determine scope of potential exposure
4. Engage incident response if exposure confirmed

### AWS S3 Remediation
```bash
# Block all public access at account level
aws s3control put-public-access-block \
    --account-id ACCOUNT_ID \
    --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Remove bucket public ACL
aws s3api put-bucket-acl --bucket BUCKET --acl private
```

### Database Remediation
1. Move to private subnet
2. Update security groups to restrict access
3. Implement IAM authentication where possible
4. Enable encryption in transit (TLS)

### Preventive Controls
1. Enable AWS Organizations SCPs blocking public resources
2. Deploy CSPM for continuous monitoring
3. Implement IaC security scanning (tfsec, checkov)
4. Block public IP assignment by default

---

## Compensating Controls

If public access is required:
- Place behind CDN with authentication (CloudFront signed URLs)
- Implement presigned URLs with short expiration
- Enable comprehensive access logging
- Deploy WAF with rate limiting
- Monitor for anomalous access patterns

---

## References

- [AWS: Blocking Public Access to S3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
- [GCP: IAM Best Practices](https://cloud.google.com/iam/docs/using-iam-securely)
- [Azure: Secure Blob Storage](https://learn.microsoft.com/en-us/azure/storage/blobs/security-recommendations)

---

*For scanner details, see [Scanners and Frameworks](../scanners-and-frameworks.md)*
