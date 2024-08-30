# Non-Critical Open Ports

## Objective
Identify and address open ports that are not critical but still require attention to reduce the overall attack surface.

### Tools
- **[Nmap](https://nmap.org/)**: Identifies open ports that are not critical but may still present risks[^1].
- **[Nessus](https://www.tenable.com/products/nessus)**: Assesses the risk level of non-critical open ports[^1].

### Qualifying Tests
Scans should identify non-critical open ports that could be closed or better protected. While not immediately critical, these should be addressed to reduce the overall attack surface.

[^1]: For details on all scanners and frameworks used, see [Scanners and Frameworks](../scanners-and-frameworks.md).
