# Database Security

## Tier: 1 - High Priority
**MITRE ATT&CK:** [T1213 - Data from Information Repositories](https://attack.mitre.org/techniques/T1213/)  
**Remediation SLA:** 24 hours  
**CVSS Range:** 9.0 - 10.0

---

## Risk Description

Databases are the crown jewels of any organization—they contain customer data, financial records, intellectual property, and credentials. A misconfigured or exposed database can result in the exfiltration of millions of records within hours.

### Business Impact
- Mass data breach (PII, PHI, financial data)
- Regulatory penalties (GDPR: €20M or 4% revenue, HIPAA: $1.5M/year)
- Customer trust destruction
- Ransomware and data extortion
- Competitive intelligence theft

### Real-World Incidents
| Incident | Database | Records | Cause |
|----------|----------|---------|-------|
| Equifax (2017) | Apache Struts | 147M | Unpatched vulnerability |
| Marriott (2018) | Oracle | 500M | Undetected breach for 4 years |
| First American (2019) | Document DB | 885M | No authentication |
| Microsoft (2019) | Elasticsearch | 250M | Public access misconfiguration |

---

## Critical Database Configurations

### Access Control
| Requirement | Implementation |
|-------------|----------------|
| Network isolation | Private subnet, no public IP |
| Authentication | Strong passwords, IAM integration |
| Authorization | Role-based, least privilege |
| Connection encryption | TLS 1.2+ required |

### Encryption
| Data State | Requirement |
|------------|-------------|
| At rest | AES-256 encryption enabled |
| In transit | TLS 1.2+ for all connections |
| Backups | Encrypted with separate key |
| Key management | HSM or managed KMS |

---

## Detection Methods

### Tools
- **[Cloudsploit](https://cloudsploit.com/):** Cloud database exposure detection
- **[Nuclei](https://nuclei.projectdiscovery.io/):** Database vulnerability scanning

### Detection Commands

**AWS RDS:**
```bash
# Check for publicly accessible databases
aws rds describe-db-instances --query \
  'DBInstances[?PubliclyAccessible==`true`].{ID:DBInstanceIdentifier,Public:PubliclyAccessible}'

# Check encryption status
aws rds describe-db-instances --query \
  'DBInstances[?StorageEncrypted==`false`].{ID:DBInstanceIdentifier,Encrypted:StorageEncrypted}'

# PROWLER checks
prowler aws -c rds_instance_publicly_accessible -c rds_instance_storage_encrypted
```

**MongoDB:**
```bash
# Check for unauthenticated access
mongo --host TARGET --eval "db.adminCommand('listDatabases')"
```

**Shodan Query:**
```
# Find exposed databases
port:27017 -authentication
port:3306 -authentication
port:5432 -authentication
```

---

## Qualifying Criteria

A finding qualifies as Tier 1 Database Security issue if:

- [ ] Database accessible from 0.0.0.0/0 (any IP)
- [ ] No authentication required
- [ ] Default credentials in use
- [ ] Encryption at rest disabled
- [ ] TLS not enforced for connections
- [ ] Database in public subnet
- [ ] Audit logging disabled

---

## Remediation

### Immediate Actions (0-24 hours)

1. **Remove public access:**
```bash
# AWS RDS - Disable public access
aws rds modify-db-instance \
  --db-instance-identifier INSTANCE \
  --no-publicly-accessible
```

2. **Rotate credentials:**
```bash
# Generate new password and update
aws secretsmanager rotate-secret --secret-id DATABASE_CREDS
```

3. **Enable audit logging:**
```bash
# AWS RDS - Enable enhanced monitoring
aws rds modify-db-instance \
  --db-instance-identifier INSTANCE \
  --enable-cloudwatch-logs-exports '["audit","error","general","slowquery"]'
```

### Network Isolation
```hcl
# Terraform - Private subnet only
resource "aws_db_instance" "secure" {
  publicly_accessible    = false
  db_subnet_group_name   = aws_db_subnet_group.private.name
  vpc_security_group_ids = [aws_security_group.db.id]
  storage_encrypted      = true
  kms_key_id            = aws_kms_key.db.arn
}

resource "aws_security_group" "db" {
  ingress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]  # App servers only
  }
}
```

### Encryption Configuration
```bash
# AWS RDS - Enable encryption (requires snapshot/restore)
aws rds create-db-snapshot --db-instance-identifier INSTANCE --db-snapshot-identifier encrypted-snapshot
aws rds copy-db-snapshot \
  --source-db-snapshot-identifier encrypted-snapshot \
  --target-db-snapshot-identifier encrypted-copy \
  --kms-key-id alias/rds-encryption-key
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier INSTANCE-encrypted \
  --db-snapshot-identifier encrypted-copy
```

### TLS Enforcement
```sql
-- MySQL: Require TLS for users
ALTER USER 'appuser'@'%' REQUIRE SSL;

-- PostgreSQL: Enforce TLS in pg_hba.conf
hostssl all all 10.0.0.0/8 scram-sha-256
```

---

## Database-Specific Hardening

### MongoDB
```javascript
// Enable authentication
use admin
db.createUser({
  user: "admin",
  pwd: "STRONG_PASSWORD",
  roles: ["root"]
})

// Bind to internal interface only
// mongod.conf
net:
  bindIp: 10.0.1.100
  tls:
    mode: requireTLS
    certificateKeyFile: /etc/ssl/mongo.pem
```

### PostgreSQL
```sql
-- Revoke public schema access
REVOKE ALL ON SCHEMA public FROM PUBLIC;

-- Enable row-level security
ALTER TABLE sensitive_data ENABLE ROW LEVEL SECURITY;

-- Audit logging
ALTER SYSTEM SET log_statement = 'all';
ALTER SYSTEM SET log_connections = on;
ALTER SYSTEM SET log_disconnections = on;
```

### Redis
```bash
# Enable authentication in redis.conf
requirepass STRONG_PASSWORD

# Disable dangerous commands
rename-command FLUSHALL ""
rename-command FLUSHDB ""
rename-command CONFIG ""

# Bind to internal only
bind 10.0.1.100
```

---

## Monitoring Requirements

| Metric | Threshold | Alert |
|--------|-----------|-------|
| Connection from unknown IP | Any | Critical |
| Failed authentication | 5+ in 5 min | High |
| Large data export | >1GB | Investigation |
| Schema changes | Any | Alert DBA |
| New user creation | Any | Audit |
| Privilege escalation | Any | Critical |

---

## References

- [CIS Database Benchmarks](https://www.cisecurity.org/benchmark)
- [OWASP Database Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html)
- [AWS RDS Security Best Practices](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_BestPractices.Security.html)

---

*For scanner details, see [Scanners and Frameworks](../scanners-and-frameworks.md)*
