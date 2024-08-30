# Role-Based Access Control (RBAC)

## Objective
Ensure that Role-Based Access Control (RBAC) is properly implemented, allowing users access only to the resources they need.

### Tools
- **[PROWLER](https://prowler.cloud/)**: Assesses IAM configurations to ensure RBAC is properly implemented[^1].
- **[Cloudsploit](https://cloudsploit.com/)**: Evaluates IAM policies to ensure they follow the principle of least privilege[^1].

### Qualifying Tests
Scans should verify that RBAC is correctly implemented, ensuring that users only have access to the resources they need. Misconfigured roles or excessive permissions should be addressed.

[^1]: For details on all scanners and frameworks used, see [Scanners and Frameworks](../scanners-and-frameworks.md).
