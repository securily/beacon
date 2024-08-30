# Lack of Firewalls

## Objective
Detect the absence or misconfiguration of essential firewalls that could leave systems vulnerable to unauthorized access or attacks.

### Tools
- **[Nessus](https://www.tenable.com/products/nessus)**: Identifies the absence of firewalls or misconfigurations[^1].
- **[Burp Suite](https://portswigger.net/burp)**: Used for web application security and can detect issues with web application firewalls[^1].

### Qualifying Tests
Automated scans should detect the absence of essential firewalls at both the network and application layers. Tests should identify gaps in protection that could leave systems vulnerable to attacks.

[^1]: For details on all scanners and frameworks used, see [Scanners and Frameworks](../scanners-and-frameworks.md).
