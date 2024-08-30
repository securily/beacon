# Publicly Accessible Resources

## Objective
Identify and secure cloud functions, virtual machines, databases, and other resources that are publicly accessible.

### Tools
- **[Cloudsploit](https://cloudsploit.com/)**: Detects misconfigurations in cloud environments, such as publicly accessible resources[^1].
- **[Nuclei](https://nuclei.projectdiscovery.io/)**: Uses templates to detect specific vulnerabilities in publicly accessible resources[^1].

### Qualifying Tests
Scans should focus on identifying resources that are exposed to the internet without adequate protection, such as cloud resources with public IPs, unprotected VMs, and databases accessible over the internet.

[^1]: For details on all scanners and frameworks used, see [Scanners and Frameworks](../scanners-and-frameworks.md).
