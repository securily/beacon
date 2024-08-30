# Database Security

## Objective
Identify and secure databases that are publicly accessible or lack encryption at rest, which are critical vulnerabilities.

### Tools
- **[Cloudsploit](https://cloudsploit.com/)**: Detects databases that are publicly accessible or lack encryption at rest[^1].
- **[Nuclei](https://nuclei.projectdiscovery.io/)**: Identifies common vulnerabilities in databases, such as exposure to the internet or lack of encryption[^1].

### Qualifying Tests
Scans should identify databases that are accessible from the internet or lack encryption. The focus should be on ensuring that sensitive data is protected both at rest and in transit.

[^1]: For details on all scanners and frameworks used, see [Scanners and Frameworks](../scanners-and-frameworks.md).
