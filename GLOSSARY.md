# Glossary

Security vocabulary is imprecise, and imprecision in a categorization framework
is expensive. Where a term has both a general meaning and a specific meaning
inside Beacon, both are given.

---

### Attack surface

The complete set of points at which an untrusted party can attempt to interact
with a system.

**In Beacon:** Reducing attack surface is the most reliable remediation
available, because it closes finding *classes* rather than individual instances.
This is why Tier 1 remediation guidance consistently begins with removing
exposure rather than hardening the exposed component.

*See also: [Reachability](#reachability)*

---

### Beacon identifier

A permanent identifier of the form `BCN-T{tier}-{DOMAIN}-{sequence}`, naming one
finding class in the [catalog](CATALOG.md).

**In Beacon:** Identifiers are never reused and never renumbered. A finding may
be reworded, re-mapped, or superseded, but the identifier continues to denote
the same class — which is what makes it safe to cite in a report someone will
read years from now.

*See also: [Finding class](#finding-class), [VERSIONING.md](VERSIONING.md)*

---

### Blast radius

The extent of systems, data, and privilege an attacker gains from compromising a
single component. A property of architecture rather than of any individual
vulnerability.

**In Beacon:** The primary reason segmentation and privilege findings sit at
Tier 1 despite not being exploitable defects — they set the consequence of every
other compromise.

*See also: [Lateral movement](#lateral-movement), [Standing privilege](#standing-privilege)*

---

### CISA KEV

The Known Exploited Vulnerabilities catalog maintained by the US Cybersecurity
and Infrastructure Security Agency, listing vulnerabilities with confirmed
exploitation in the wild.

**In Beacon:** KEV membership combined with reachability places a finding in
Tier 1 regardless of its CVSS score. Beacon treats observed exploitation as
outranking modeled severity — see
[BCN-T1-PRC-001](processing-protection/known-exploited-vulnerabilities.md).

*See also: [EPSS](#epss), [CVSS](#cvss)*

---

### Compensating control

An alternative measure that reduces risk when the primary control cannot be
implemented — for example withdrawing internet reachability when a vulnerable
component cannot be patched.

**In Beacon:** A compensating control does **not** close a finding. It changes
the finding's tier by removing reachability or reducing consequence, and must be
recorded with a named owner and a review date.

*See also: [Risk acceptance](#risk-acceptance), [Reachability](#reachability)*

---

### CVSS

The Common Vulnerability Scoring System, an open standard producing a 0.0–10.0
severity score for a vulnerability from its intrinsic characteristics.

**In Beacon:** One input among several, never the tier by itself. Because the
base score describes the vulnerability rather than your environment, it cannot
express reachability, exploitation activity, or regulatory consequence — the
three factors that actually determine tier.

*See also: [EPSS](#epss), [CISA KEV](#cisa-kev), [SOURCES.md](SOURCES.md) S2*

---

### Dwell time

The interval between an attacker gaining access and being detected. Global
medians have fallen from over a year a decade ago to roughly ten days.

**In Beacon:** The reason Tier 1 SLAs are measured in hours. A remediation
window longer than the attacker's operating window is not a control, whatever
the policy document says.

*See also: [Time to remediate](#time-to-remediate)*

---

### EPSS

The Exploit Prediction Scoring System, which estimates the probability that a
given vulnerability will be exploited in the wild within the next thirty days.

**In Beacon:** Helps prioritize within the Tier 1 queue and triage CVEs not yet
listed in KEV. An input to tier assignment, not a substitute for it — a
probability does not name an owner or a deadline.

*See also: [CISA KEV](#cisa-kev), [CVSS](#cvss)*

---

### Finding class

A named, permanently-identified category of security condition, as distinct from
an individual instance of that condition on a specific asset.

**In Beacon:** The [catalog](CATALOG.md) defines finding classes such as
`BCN-T1-NET-001`. Your scanner reports *instances*; Beacon classifies them. One
class typically accounts for many instances across an estate.

*See also: [Beacon identifier](#beacon-identifier)*

---

### Just-in-time elevation

Granting privileged access for a bounded window on request and approval, rather
than holding it permanently.

**In Beacon:** The standard remediation for
[BCN-T1-IAM-002](identity-and-access-management/high-privilege-accounts.md).
Replacing standing privilege with just-in-time elevation reduces the value of any
single compromised credential.

*See also: [Standing privilege](#standing-privilege), [Least privilege](#least-privilege)*

---

### Lateral movement

An attacker's progression from an initial foothold to other systems within the
same environment. The initial foothold is rarely the objective.

**In Beacon:** Segmentation findings are tiered by how much lateral movement
they enable, which is why an absent enforcement point can be Tier 1 without being
an exploitable defect.

*See also: [Blast radius](#blast-radius), [Segmentation](#segmentation)*

---

### Least privilege

The principle that an identity should hold only the permissions its function
requires, and only while it requires them.

**In Beacon:** Split across two tiers by consequence. Broad standing
administrative privilege is Tier 1
([BCN-T1-IAM-002](identity-and-access-management/high-privilege-accounts.md));
refining already-bounded roles is Tier 3
([BCN-T3-IAM-001](identity-and-access-management/rbac.md)).

*See also: [Standing privilege](#standing-privilege), [Just-in-time elevation](#just-in-time-elevation)*

---

### MITRE ATT&CK

A knowledge base of adversary tactics and techniques derived from observed
real-world intrusions, maintained by MITRE.

**In Beacon:** Every Tier 1 catalog entry maps to the ATT&CK techniques that
exploit it, which supports threat-informed prioritization and lets detection
engineering work from the same references as remediation.

*See also: [Threat-informed defense](#threat-informed-defense)*

---

### Reachability

Whether an attacker in a given position can actually interact with a vulnerable
component. A vulnerability nothing can route to presents a materially different
risk from the same vulnerability on a public address.

**In Beacon:** The **first** question in the decision procedure and the most
common determinant of tier. Removing reachability is frequently the fastest
available remediation, and legitimately reduces the tier.

*See also: [Compensating control](#compensating-control), [Attack surface](#attack-surface)*

---

### Risk acceptance

A recorded decision by an accountable owner not to remediate a finding, with the
residual risk explicitly acknowledged.

**In Beacon:** Must carry a named owner, an expiry date, and a compensating
control where one exists. **Perpetual undocumented exceptions are themselves a
finding** under
[BCN-T2-PRC-001](processing-protection/regulatory-processing-compliance.md).

*See also: [Compensating control](#compensating-control)*

---

### Segmentation

Enforced separation between networks of differing trust or regulatory scope, such
that traffic between them passes an enforcement point.

**In Beacon:** Separated into two findings by consequence. Exposure of
crown-jewel systems to routine compromise is Tier 1
([BCN-T1-NET-003](network/lack-of-firewalls.md)); audit-scope expansion around a
regulated environment is Tier 2
([BCN-T2-NET-001](network/regulatory-network-compliance.md)).

*See also: [Lateral movement](#lateral-movement), [Blast radius](#blast-radius)*

---

### SLA

In this context, the maximum permitted time between a finding being identified
and being remediated, defined per tier.

**In Beacon:** 24–72 hours for Tier 1, 30 days for Tier 2, 90 days for Tier 3.
An SLA without an escalation path and without measurement is a statement of
intent rather than a control.

*See also: [Time to remediate](#time-to-remediate), [Risk acceptance](#risk-acceptance)*

---

### Standing privilege

Permissions that are permanently active on an identity, as opposed to granted on
request for a bounded period.

**In Beacon:** Broad standing privilege is Tier 1 because it multiplies the
impact of every credential-theft technique — phishing a user who holds permanent
production administrator rights is equivalent to phishing an administrator.

*See also: [Just-in-time elevation](#just-in-time-elevation), [Least privilege](#least-privilege)*

---

### Threat-informed defense

Prioritizing defensive work according to the techniques adversaries actually use,
rather than according to theoretical severity.

**In Beacon:** The organizing principle behind Tier 1. Observed exploitation and
real reachability determine urgency; intrinsic severity scores inform but do not
decide.

*See also: [MITRE ATT&CK](#mitre-attck), [CISA KEV](#cisa-kev)*

---

### Time to remediate

The elapsed time between a finding being identified and being verifiably closed.
Distinct from time to triage or time to acknowledge.

**In Beacon:** SLAs measure time to remediate, **not** time to ticket.
Programs that measure acknowledgement report attainment figures that bear no
relation to actual exposure.

*See also: [Dwell time](#dwell-time), [SLA](#sla)*

---

## Related documents

- [Classification Procedure](CLASSIFICATION.md) — how to assign a tier
- [Finding Catalog](CATALOG.md) — canonical identifiers
- [Sources](SOURCES.md) — evidence behind every figure cited
