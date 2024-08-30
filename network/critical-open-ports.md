# Critical Open Ports

## Objective
Identify and mitigate the risk posed by open ports that could serve as entry points for attackers.

### Tools
- **[Nmap](https://nmap.org/)**: A powerful network scanning tool that identifies open ports and services running on a system[^1].
- **[Nessus](https://www.tenable.com/products/nessus)**: Provides vulnerability scanning and can identify misconfigurations or weak points in network security[^1].

### Qualifying Tests
Tests should focus on detecting open ports that are not necessary for business operations and could serve as entry points for attackers. Scans should be configured to identify high-risk ports like SSH, FTP, and SMB, and exclude commonly used ports like HTTP/HTTPS unless specific vulnerabilities are present.

[^1]: For details on all scanners and frameworks used, see [Scanners and Frameworks](../scanners-and-frameworks.md).
