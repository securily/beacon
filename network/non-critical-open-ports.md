# Non-Critical Open Ports

## Tier: 3 - Best Practices
**Beacon ID:** `BCN-T3-NET-001`
**MITRE ATT&CK:** [T1046 - Network Service Discovery](https://attack.mitre.org/techniques/T1046/)
**Remediation SLA:** 90 days
**Escalation:** Quarterly planning review

---

## Risk Description

Services listening on internal networks without a current business need —
legacy applications retained after migration, daemons enabled by a base image and
never disabled, diagnostic endpoints left over from troubleshooting.

Nothing here is exploitable today from an untrusted position. That is the whole
basis for the Tier 3 assignment, and it is also why this work never gets done
without a tier of its own.

The risk is **deferred, not absent**. Each unnecessary service is:

- A future patch obligation, and therefore a future Tier 1 candidate the first
  time a critical CVE lands in it
- A lateral movement foothold once an attacker is already inside
- Reconnaissance value — service banners fingerprint your estate and reveal
  technology choices, versions, and naming conventions
- Ongoing maintenance cost with zero corresponding benefit

**The single most reliable remediation in security is removing something.** It
closes the finding class permanently rather than mitigating an instance.

> **Boundary condition:** this finding covers **internal** exposure only. *Any*
> unnecessary internet-facing service is Tier 1 under
> [Critical Open Ports](critical-open-ports.md) or
> [Unprotected External Exposure](../processing-protection/unprotected-external-exposure.md),
> regardless of how unimportant the service seems. "It's only a status page" is
> not a downgrade argument — reachability decides the tier.

---

## Scope

| In scope (Tier 3) | Out of scope (higher tier) |
|-------------------|---------------------------|
| Internal-only services with no identified consumer | Anything internet-reachable → **Tier 1** |
| Default daemons from base images | Administrative protocols reachable externally → **Tier 1** |
| Legacy systems retained post-migration | Services in the regulated environment lacking justification → **Tier 2** |
| Diagnostic and debug endpoints on internal interfaces | Debug endpoints exposing credentials or data → **Tier 1** |
| Services bound to `0.0.0.0` that only need loopback | Unauthenticated data services → **Tier 1** |

---

## Commonly Unnecessary Services

| Port | Service | Typical origin | Action |
|------|---------|----------------|--------|
| 111 | rpcbind | Default on many Linux images | Disable unless NFS is in use |
| 25 | SMTP | MTA installed by default | Bind to loopback for local mail only |
| 631 | CUPS | Desktop package group on servers | Remove |
| 5353 | mDNS/Avahi | Default on desktop-derived images | Disable on servers |
| 161 | SNMP | Monitoring agent, often with a default community string | Migrate to SNMPv3 or remove |
| 11211 | Memcached | Development convenience left in place | Bind to loopback; **Tier 1 if external** |
| 8080/8000 | Alternate HTTP | Debug or admin interfaces | Remove or restrict |
| 9090/9100 | Prometheus / node_exporter | Monitoring stack, frequently unauthenticated | Restrict to the monitoring subnet |
| 2049 | NFS | Legacy file sharing | Verify need; restrict by export |
| 5432/3306 | Database | Bound to all interfaces by default | Bind to the application subnet only |

> Memcached, Redis, and node_exporter appear at Tier 3 **only** when confirmed
> internal. Exposed externally they are unauthenticated data services and become
> Tier 1 — Memcached in particular has been used at scale for UDP amplification.

---

## Detection Methods

### Tools
- **[Nmap](https://nmap.org/):** Service and version discovery
- **[Nessus](https://www.tenable.com/products/nessus):** Risk-rated service inventory
- **VPC Flow Logs / NSG Flow Logs:** Evidence of actual usage
- **[OpenSCAP](https://www.open-scap.org/):** Baseline configuration comparison

### Discovering listeners

```bash
# Internal segment sweep with service and version detection
nmap -sS -sV -O -p- --min-rate 1000 10.0.0.0/16 -oA internal-sweep

# Compare against the documented service inventory
grep -E '^[0-9]+/tcp\s+open' internal-sweep.nmap | \
  awk '{print $1" "$3}' | sort -u > /tmp/actual.txt
comm -23 /tmp/actual.txt /tmp/documented.txt   # undocumented listeners
```

```bash
# On-host — which process owns each listener, and is it bound too broadly?
ss -tulpn | awk 'NR>1 {print $1, $5, $7}' | sort -u

# Listeners on all interfaces that may only need loopback
ss -tulpn | grep -E '0\.0\.0\.0:|\[::\]:'
```

### Proving a service is unused

This is the step that makes removal safe, and the step most often skipped.
**Observe before you disable.**

```bash
# VPC Flow Logs — connections to a candidate port over 30 days
aws logs start-query \
  --log-group-name /aws/vpc/flowlogs \
  --start-time "$(date -v-30d +%s)" \
  --end-time "$(date +%s)" \
  --query-string 'fields srcaddr, dstaddr, dstport
                  | filter dstport = 11211 and action = "ACCEPT"
                  | stats count() by srcaddr
                  | sort by count() desc'
```

```bash
# Host-level connection counting before removal
ss -tan state established '( dport = :11211 or sport = :11211 )' | wc -l
```

### Comparing against a hardened baseline

```bash
# Which services did the base image enable that nobody asked for?
systemctl list-units --type=service --state=running --no-pager --plain | \
  awk '{print $1}' > /tmp/running.txt
comm -23 <(sort /tmp/running.txt) <(sort baseline-approved-services.txt)
```

---

## Qualifying Criteria

A finding qualifies as **Tier 3 Non-Critical Open Ports** if all of the
following hold:

- [ ] The service is **not** reachable from the internet or any untrusted network
- [ ] The service is **not** an unauthenticated data store
- [ ] No current business consumer is identified
- [ ] No traffic observed over a representative window (30 days minimum)

…and any of:

- [ ] Service enabled by a base image and never explicitly required
- [ ] Legacy system retained after migration with no decommissioning date
- [ ] Diagnostic or debug endpoint left from troubleshooting
- [ ] Service bound to all interfaces where loopback would suffice
- [ ] Listener absent from the documented service inventory
- [ ] Monitoring or metrics endpoint reachable beyond the monitoring subnet

---

## Remediation

### Phase 1 — Observe (Days 1–30)

Do not disable anything yet. Establish which services genuinely have no
consumers, using flow data rather than assumption. Thirty days catches monthly
batch jobs; anything shorter will eventually break a quarterly process.

Record for each listener: host, port, process, owner, last observed connection.

### Phase 2 — Remove (Days 30–60)

Work in order of confidence — services with zero observed traffic and no
identified owner first.

```bash
# Disable and mask so a dependency cannot silently re-enable it
sudo systemctl stop rpcbind.socket rpcbind.service
sudo systemctl disable rpcbind.socket rpcbind.service
sudo systemctl mask rpcbind.socket rpcbind.service

# Remove the package entirely where nothing depends on it
sudo apt-get purge -y rpcbind cups avahi-daemon
```

**Bind to loopback where the service must remain but only serves locally:**

```ini
# PostgreSQL
listen_addresses = 'localhost'
```
```ini
# Redis
bind 127.0.0.1 ::1
protected-mode yes
```
```ini
# Memcached
-l 127.0.0.1
```

**Restrict rather than remove where a consumer exists:**

```bash
# node_exporter reachable only from the monitoring subnet
aws ec2 authorize-security-group-ingress \
  --group-id sg-app \
  --protocol tcp --port 9100 \
  --source-group sg-monitoring
```

### Phase 3 — Fix the source (Days 60–90)

Removing a service from running hosts without fixing the image means the next
instance reintroduces it. **The image is the finding.**

```dockerfile
# Minimal base — the smallest attack surface is the one you never install
FROM gcr.io/distroless/static-debian12
COPY --chown=nonroot:nonroot app /app
USER nonroot
ENTRYPOINT ["/app"]
```

```yaml
# Packer / cloud-init — explicitly disable defaults at build time
runcmd:
  - systemctl disable --now rpcbind.socket avahi-daemon cups
  - apt-get purge -y rpcbind avahi-daemon cups
```

**Decommission legacy systems formally.** Stopping the service is not
decommissioning — clean up DNS records, certificates, monitoring checks,
firewall rules, and the asset inventory entry, or the system reappears as a
finding in the next scan cycle with nobody able to explain it.

### Phase 4 — Detect drift

```bash
# Weekly comparison against the approved baseline
nmap -sS -p- --min-rate 1000 10.0.0.0/16 -oX current.xml
ndiff baseline.xml current.xml | grep -E '^\+' && \
  echo "New listeners detected — review required"
```

Alert on new listeners rather than discovering them at the next annual scan.

---

## Verification

| Check | Evidence |
|-------|----------|
| Internal scan reconciles to inventory | `nmap` output matching documented services, no unexplained listeners |
| Freshly-provisioned host is clean | New instance from the updated image exposes only intended services |
| Retained services are restricted | Security group or firewall rule limiting source |
| No service regression | Application health checks and error rates unchanged post-removal |
| Legacy systems fully decommissioned | DNS, certificates, monitoring, and inventory entries removed |
| Drift detection active | Alert fires on a deliberately-introduced test listener |

---

## Exception Handling

Where a service must remain despite having no clear consumer:

1. Record the business justification and the named owner
2. Restrict to the narrowest possible source range
3. Bind to a management interface rather than a general-purpose one
4. Set a review date — typically the system's next upgrade cycle
5. Ensure it is covered by patch management, since it is now a permanent asset

---

## Monitoring Requirements

| Event | Action |
|-------|--------|
| New listening port on a production host | Alert platform team within 24 hours |
| Service re-enabled after removal | Investigate — often an image or config-management regression |
| Connection to a deprecated service | Log source; may indicate an undiscovered consumer |
| Base image adds a new default service | Review at image promotion |
| Scan coverage gap | Monthly reconciliation against asset inventory |

---

## References

- [CIS Controls v8 — Control 4: Secure Configuration](https://www.cisecurity.org/controls/secure-configuration-of-enterprise-assets-and-software)
- [NIST SP 800-123 — Guide to General Server Security](https://csrc.nist.gov/publications/detail/sp/800-123/final)
- [Nmap Reference Guide](https://nmap.org/book/man.html)

---

## Related Findings

- [Critical Open Ports](critical-open-ports.md) — `BCN-T1-NET-001`, Tier 1
- [Publicly Accessible Resources](publicly-accessible-resources.md) — `BCN-T1-NET-002`, Tier 1
- [Lack of Firewalls](lack-of-firewalls.md) — `BCN-T1-NET-003`, Tier 1
- [Hardening of Cloud Resources](hardening-of-cloud-resources.md) — `BCN-T3-NET-002`, Tier 3

---

*For classification guidance, see [Classification Procedure](../CLASSIFICATION.md).
For scanner details, see [Scanners and Frameworks](../scanners-and-frameworks.md).*
