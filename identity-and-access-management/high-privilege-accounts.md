# High-Privilege Accounts

## Objective
Detect high-privilege accounts that are not in use or have excessive permissions and ensure they are disabled or removed to reduce risk.

### Tools
- **[PROWLER](https://prowler.cloud/)**: Checks for IAM best practices, including the use of high-privilege accounts[^1].
- **[Cloudsploit](https://cloudsploit.com/)**: Detects high-privilege accounts that are not in use[^1].

### Qualifying Tests
Scans should identify high-privilege accounts that are not in use or have excessive permissions, enforcing the principle of least privilege.

[^1]: For details on all scanners and frameworks used, see [Scanners and Frameworks](../scanners-and-frameworks.md).
