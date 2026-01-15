# Critical Database Protection Issues

## Tier: 1 - High Priority
**MITRE ATT&CK:** [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)  
**Remediation SLA:** 24 hours  
**CVSS Range:** 8.0 - 10.0

---

## Risk Description

Database vulnerabilities—SQL injection, weak authentication, missing patches—remain among the most exploited attack vectors. These vulnerabilities can bypass all application-layer security controls, providing direct access to sensitive data.

### Business Impact
- Complete database compromise
- Mass data exfiltration in minutes
- Privilege escalation to OS level
- Data manipulation and integrity loss
- Ransomware via database-level encryption

### OWASP Top 10 Alignment
- **A03:2021 - Injection** (including SQL injection)
- **A07:2021 - Identification and Authentication Failures**
- **A05:2021 - Security Misconfiguration**

---

## Critical Vulnerability Categories

### SQL Injection (SQLi)
| Type | Risk | Example |
|------|------|---------|
| Classic SQLi | Data extraction | `' OR '1'='1` |
| Blind SQLi | Slow data extraction | Time-based inference |
| Out-of-band SQLi | Data exfiltration | DNS/HTTP exfiltration |
| Second-order SQLi | Delayed execution | Stored malicious input |

### Authentication Weaknesses
| Issue | Risk Level | Impact |
|-------|------------|--------|
| Default credentials | Critical | Immediate compromise |
| Weak passwords | High | Brute force success |
| No authentication | Critical | Unauthenticated access |
| Shared credentials | High | No accountability |

### Configuration Issues
| Misconfiguration | Risk | Remediation |
|------------------|------|-------------|
| Remote root login | Critical | Disable remote root |
| Excessive privileges | High | Principle of least privilege |
| Debug mode enabled | Medium | Disable in production |
| Backup exposure | Critical | Secure backup locations |

---

## Detection Methods

### Tools
- **[Nessus](https://www.tenable.com/products/nessus):** Database vulnerability assessment
- **[Burp Suite](https://portswigger.net/burp):** SQL injection testing

### SQL Injection Detection

```bash
# SQLMap - Automated SQLi testing
sqlmap -u "https://target.com/page?id=1" --dbs --batch

# Burp Suite Scanner - Active scan for injection points
# Configure scope and run active scan

# Manual testing
curl "https://target.com/api/user?id=1'" 
# Check for SQL error messages in response
```

### Database Security Scan

```bash
# Nessus database audit plugins
# - MySQL Unpassworded Account Check
# - PostgreSQL Default Credentials
# - Oracle TNS Listener Remote Poisoning
# - SQL Server xp_cmdshell Enabled

# MySQL security check
mysql -u root -p -e "SELECT user, host FROM mysql.user WHERE password='' OR authentication_string='';"

# PostgreSQL security check
psql -c "SELECT usename FROM pg_user WHERE passwd IS NULL;"
```

### Patch Status Verification

```bash
# MySQL version check
mysql -V
# Compare against: https://www.mysql.com/support/supportedplatforms/database.html

# PostgreSQL version
psql -V
# Compare against: https://www.postgresql.org/support/versioning/

# SQL Server
SELECT @@VERSION;
# Compare against Microsoft support lifecycle
```

---

## Qualifying Criteria

A finding qualifies as Tier 1 Critical Database Protection issue if:

**SQL Injection:**
- [ ] Application vulnerable to SQLi (confirmed)
- [ ] No parameterized queries/prepared statements
- [ ] Dynamic SQL with user input concatenation
- [ ] WAF bypass possible

**Authentication:**
- [ ] Default database credentials in use
- [ ] Database superuser used by application
- [ ] No password on administrative accounts
- [ ] Shared database credentials across applications

**Configuration:**
- [ ] Missing critical security patches
- [ ] Remote administrative access enabled
- [ ] Dangerous features enabled (xp_cmdshell)
- [ ] Backup files accessible without auth
- [ ] Database listening on public interface

---

## Remediation

### SQL Injection Prevention

**Use Parameterized Queries:**

```python
# Python - VULNERABLE
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# Python - SECURE
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

```java
// Java - VULNERABLE
String query = "SELECT * FROM users WHERE id = " + userId;
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(query);

// Java - SECURE
String query = "SELECT * FROM users WHERE id = ?";
PreparedStatement pstmt = conn.prepareStatement(query);
pstmt.setInt(1, userId);
ResultSet rs = pstmt.executeQuery();
```

```javascript
// Node.js - VULNERABLE
db.query(`SELECT * FROM users WHERE id = ${userId}`);

// Node.js - SECURE
db.query('SELECT * FROM users WHERE id = $1', [userId]);
```

**ORM Security:**
```python
# Django ORM - inherently parameterized
User.objects.filter(id=user_id)

# BUT AVOID raw queries:
# VULNERABLE: User.objects.raw(f'SELECT * FROM users WHERE id = {user_id}')
# SECURE: User.objects.raw('SELECT * FROM users WHERE id = %s', [user_id])
```

### Authentication Hardening

```sql
-- MySQL: Remove anonymous users
DELETE FROM mysql.user WHERE User='';

-- Remove remote root login
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');

-- Set strong passwords
ALTER USER 'root'@'localhost' IDENTIFIED BY 'STRONG_PASSWORD_HERE';

-- Create application-specific users
CREATE USER 'appuser'@'10.0.1.%' IDENTIFIED BY 'STRONG_PASSWORD';
GRANT SELECT, INSERT, UPDATE ON appdb.* TO 'appuser'@'10.0.1.%';
-- Never grant ALL PRIVILEGES to application accounts

FLUSH PRIVILEGES;
```

```sql
-- PostgreSQL: Enforce password authentication
-- pg_hba.conf
hostssl all all 10.0.0.0/8 scram-sha-256

-- Disable trust authentication
-- NEVER: host all all 0.0.0.0/0 trust

-- Create restricted user
CREATE USER appuser WITH PASSWORD 'STRONG_PASSWORD';
GRANT CONNECT ON DATABASE appdb TO appuser;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO appuser;
```

### Dangerous Features Disable

```sql
-- SQL Server: Disable xp_cmdshell
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 0;
RECONFIGURE;

-- Disable OLE Automation
EXEC sp_configure 'Ole Automation Procedures', 0;
RECONFIGURE;
```

```sql
-- MySQL: Disable dangerous functions
-- my.cnf
[mysqld]
local-infile=0
symbolic-links=0
```

### Patch Management

```bash
# MySQL upgrade (Ubuntu/Debian)
sudo apt update
sudo apt upgrade mysql-server

# PostgreSQL upgrade
sudo apt update
sudo apt upgrade postgresql

# Verify version after patch
mysql -V
psql -V
```

---

## Database Activity Monitoring

```sql
-- MySQL: Enable general query log (development/audit only)
SET GLOBAL general_log = 'ON';
SET GLOBAL general_log_file = '/var/log/mysql/query.log';

-- PostgreSQL: Enable logging
-- postgresql.conf
log_statement = 'all'
log_connections = on
log_disconnections = on
log_duration = on
```

### SIEM Integration

| Database | Log Source | Key Events |
|----------|------------|------------|
| MySQL | General log, Error log | Failed auth, DDL changes |
| PostgreSQL | pg_log | Connections, query errors |
| SQL Server | SQL Audit | Login failures, schema changes |
| Oracle | Audit trail | Privileged actions |

---

## Monitoring Requirements

| Event | Threshold | Alert |
|-------|-----------|-------|
| Failed authentication | 5 in 5 min | High |
| SQL syntax error spike | 10x baseline | Critical (possible SQLi) |
| Large data export | >100K rows | Investigation |
| Schema modification | Any | Immediate |
| New user creation | Any | Audit |
| Privilege grant | Any | Critical |

---

## References

- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [CIS Database Benchmarks](https://www.cisecurity.org/benchmark)
- [NIST Database Security Guidelines](https://csrc.nist.gov/publications/detail/sp/800-123/final)

---

*For scanner details, see [Scanners and Frameworks](../scanners-and-frameworks.md)*
