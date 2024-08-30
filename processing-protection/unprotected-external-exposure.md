# Unprotected External Exposure

## Objective
Detect virtual machines and other processing units that are exposed to the internet without adequate protection.

### Tools
- **[Cloudsploit](https://cloudsploit.com/)**: Detects virtual machines and cloud resources exposed to the internet without necessary protective layers[^1].
- **[Nmap](https://nmap.org/)**: Identifies externally exposed systems and services that are vulnerable to attack[^1].

### Qualifying Tests
Scans should focus on detecting virtual machines or processing units that are exposed to the internet without adequate protection. The absence of firewalls, load balancers, or similar security measures should be flagged as critical.

[^1]: For details on all scanners and frameworks used, see [Scanners and Frameworks](../scanners-and-frameworks.md).
