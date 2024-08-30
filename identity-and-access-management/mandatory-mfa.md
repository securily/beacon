# Mandatory MFA

## Objective
Ensure that multi-factor authentication (MFA) is enforced across all users, especially those with elevated privileges.

### Tools
- **[PROWLER](https://prowler.cloud/)**: Checks for MFA enforcement across all users[^1].
- **[Cloudsploit](https://cloudsploit.com/)**: Monitors for MFA enforcement, identifying gaps in user authentication practices[^1].

### Qualifying Tests
Automated tests should verify that MFA is enforced for all users, especially those with elevated privileges. The absence of MFA should be flagged as a critical vulnerability.

[^1]: For details on all scanners and frameworks used, see [Scanners and Frameworks](../scanners-and-frameworks.md).
