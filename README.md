# Beacon Security Standards

## A universal way to categorize and prioritize security findings

**Version 1.1.0** · [GPL-3.0](LICENSE) · Published by Penti.ai

---

## The problem

Security teams do not struggle to *find* vulnerabilities. Scanners produce more
findings than any organization can remediate, and the constraint moved long ago
from detection to decision: which of these thousands of items matters this week,
and who works on it.

The industry default is to sort by CVSS. This fails because the base score
describes the vulnerability in the abstract and is therefore **identical for
every organization on earth**. It cannot express whether the affected component
is reachable, whether anyone is exploiting it, or what sits behind it. Published
research has repeatedly found that remediating by score alone performs little
better than working the list at random ([SOURCES.md](SOURCES.md) S2).

The deeper problem: a severity rating is not an instruction. A finding marked
*High* tells an engineer nothing about **when** it must be fixed, **who** owns
it, **whose budget** it comes from, or whether it may legitimately be deferred.

Beacon supplies exactly that layer — and supplies it consistently enough that two
people classifying the same finding reach the same answer.

---

## Start here

| If you want to… | Read |
|-----------------|------|
| **Classify a finding right now** | [CLASSIFICATION.md](CLASSIFICATION.md) — four questions, in order |
| Look up a specific finding | [CATALOG.md](CATALOG.md) — all 36 finding classes |
| Consume the standard in code | [`beacon-catalog.json`](beacon-catalog.json) |
| Understand a term | [GLOSSARY.md](GLOSSARY.md) |
| Check a statistic | [SOURCES.md](SOURCES.md) |
| Build against it safely | [VERSIONING.md](VERSIONING.md) |
| Propose a change | [CONTRIBUTING.md](CONTRIBUTING.md) |

---

## The classification procedure

Four questions. Apply them **in order**, stop at the first that returns *yes*.
The order is the method — it is what makes the framework repeatable.

| # | Question | If yes |
|---|----------|--------|
| **1** | Is it reachable by an untrusted party **right now**? | Continue to 2 |
| **2** | Does exploitation grant access, privilege, or data in **one step**? | **Tier 1** — 24–72h |
| **3** | Would a **named** auditor, regulator, or counterparty cite it? | **Tier 2** — 30 days |
| **4** | Does fixing it reduce **future** Tier 1 and Tier 2 findings? | **Tier 3** — 90 days |

If all four are *no*, it is not a Beacon finding. Close it, or route it to the
appropriate engineering backlog.

> **The most common way this goes wrong** is evaluating compliance before
> reachability. Teams that reverse questions 1 and 3 end up with an emergency
> queue full of audit items while real exposures sit on a 30-day clock.

Full procedure, six worked examples, and the six documented failure modes:
**[CLASSIFICATION.md](CLASSIFICATION.md)**

---

## The three tiers

A five-level severity scale fails because its middle levels carry no decision.
Three tiers is the smallest number that captures genuinely different
organizational responses — each maps to a different deadline, owner, and budget.

### [Tier 1: Critical](tiers/tier-1-critical-threat-management.md) — 24–72 hours

*Stop active bleeding.*

Conditions an attacker can act on now. The defining property is not severity
score but **reachability**: exposed to an untrusted network, exploitation
understood and tooled, success grants meaningful access.

Escalates to CISO and executive sponsor at 48 hours. Pre-empts sprint
commitments.

### [Tier 2: Regulatory](tiers/tier-2-regulatory.md) — 30 days

*Maintain the license to operate.*

Threatens certification, contract, or regulatory standing. The consequence is not
a breach but a finding in **someone else's report** — a qualified SOC 2 opinion,
a failed PCI DSS assessment, a GDPR Article 32 exposure.

Deadline-driven rather than threat-driven, and the deadline belongs to the
auditor.

### [Tier 3: Best Practices](tiers/tier-3-best-practices.md) — 90 days

*Reduce the rate at which the first two tiers refill.*

Structural improvements with compounding returns. Nothing here is urgent in
isolation — which is exactly why it never gets done without a tier of its own.

The only tier where **formal deferral is a legitimate, recorded outcome**.

---

## The four domains

Tier sets the **deadline**. Domain sets the **owner**.

| Domain | Code | Question it answers | Typical owner |
|--------|------|---------------------|---------------|
| [Network](network/) | `NET` | What can be reached, and from where? | Network / cloud platform |
| [Identity & Access](identity-and-access-management/) | `IAM` | Who can act, and how strongly is that proven? | Identity engineering / IT |
| [Data Protection](data/) | `DAT` | What happens to the data if everything else fails? | Data platform / application |
| [Processing Protection](processing-protection/) | `PRC` | Is the compute trustworthy and available? | Platform engineering / SRE |

Assign the domain of the **control that fixes it**, not the symptom. An exposed
database is a Network finding if the fix is a firewall rule, and a Data finding
if the fix is enabling authentication.

---

## Canonical identifiers

```
BCN-T1-NET-001
 │   │   │   └── Sequence within tier and domain
 │   │   └────── Domain: NET | IAM | DAT | PRC
 │   └────────── Tier: T1 | T2 | T3
 └────────────── Namespace
```

**Identifiers are permanent.** A finding may be reworded, re-mapped, or
superseded — but its identifier is never reused or renumbered. That is what makes
Beacon safe to cite in a report someone will read years from now.

Browse all 36: **[CATALOG.md](CATALOG.md)**

---

## Machine-readable catalog

The standard ships as [`beacon-catalog.json`](beacon-catalog.json) so scanners,
ticketing systems, and reporting pipelines consume it directly rather than
transcribing it.

```bash
# Tier 1 findings and their SLAs
jq '.findings[] | select(.tier == 1) | {id, name, sla}' beacon-catalog.json

# Everything mapping to an ATT&CK technique
jq --arg t T1078 '.findings[] |
  select(.mappings.mitreAttack[]?.id == $t) | .id' beacon-catalog.json

# Resolve an identifier from a report back to its documentation
jq -r --arg id BCN-T1-NET-001 '.findings[] |
  select(.id == $id) | .documentation' beacon-catalog.json
```

Consumers should read [VERSIONING.md](VERSIONING.md) before building against it.

---

## How Beacon relates to CVSS, EPSS and KEV

These are frequently presented as alternatives. They are not — each answers a
different question, and Beacon consumes them as inputs.

| System | Answers | Beacon's use |
|--------|---------|--------------|
| **CVSS** | How severe in the abstract? | Input to question 2. Never the tier by itself. |
| **EPSS** | How likely is exploitation? | Orders the Tier 1 queue; triages non-KEV CVEs |
| **CISA KEV** | Is it confirmed exploited? | Makes question 2 an automatic *yes* |
| **Reachability** | Can an attacker touch it? | Question 1 — the deciding factor |

> A CVSS 9.8 with no reachability is **Tier 2**.
> A CVSS 6.5 in the KEV catalog on an internet-facing host is **Tier 1**.
>
> Exploitation evidence outranks modeled severity.

None of those systems names an owner or a deadline, and none covers the
misconfigurations and identity gaps that carry no CVE at all — which in a modern
cloud estate is most of the real exposure.

---

## Framework alignment

Beacon does **not** replace these standards. It maps to them, so that
compliance-driven work is scheduled against the audit calendar rather than
competing with threat-driven work for the same urgency.

| Framework | Integration |
|-----------|-------------|
| [MITRE ATT&CK](https://attack.mitre.org/) | 24 techniques mapped across the catalog |
| [OWASP](https://owasp.org/) | Application vulnerability classification |
| [PCI DSS v4.0](https://www.pcisecuritystandards.org/) | Control-level mapping on 20+ findings |
| [ISO/IEC 27001:2022](https://www.iso.org/standard/27001) | Annex A control mapping |
| [SOC 2](https://www.aicpa-cima.com/) | Trust Services Criteria mapping |
| [GDPR](https://gdpr-info.eu/) / [HIPAA](https://www.hhs.gov/hipaa/) | Article and section mapping |
| [NIST CSF 2.0](https://www.nist.gov/cyberframework) | Function and category alignment |
| [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) | Hardening baselines |

Full cross-reference tables: [CATALOG.md](CATALOG.md)

---

## Scanner compatibility

Beacon defines **finding classes**, not tool integrations — scanner output maps
*into* the catalog. The mapping exercise is the same for any tool that produces
findings.

| Scanner | Type | Tier coverage |
|---------|------|---------------|
| [Nmap](https://nmap.org/) | Network discovery | 1, 3 |
| [Nessus](https://www.tenable.com/products/nessus) | Vulnerability scanning | All |
| [Burp Suite](https://portswigger.net/burp) | Web application | 1, 2 |
| [Nuclei](https://nuclei.projectdiscovery.io/) | Template scanning | 1, 2 |
| [PROWLER](https://prowler.cloud/) | Cloud security | All |
| [Cloudsploit](https://cloudsploit.com/) | Cloud posture | All |
| [Trivy](https://trivy.dev/) | Container / IaC | 1, 3 |
| [TruffleHog](https://github.com/trufflesecurity/trufflehog) | Secret detection | 1 |

Full documentation: [Scanners and Frameworks](scanners-and-frameworks.md)

---

## Adopting Beacon

Classifying a backlog takes a few days. Changing what the organization *does*
about it takes a quarter.

| Phase | Outcome |
|-------|---------|
| **Week 1** | Classify the existing backlog. Produce an honest Tier 1 count. |
| **Weeks 2–3** | Agree SLAs and the escalation path with engineering leadership. |
| **Weeks 3–4** | Wire tiers into the tracker engineers already use. Automate due dates from tier. |
| **Ongoing** | Run the exception process honestly. Measure time-to-remediate, not time-to-acknowledge. |

The framework is free and classification is fast. **The scarce resource is the
agreement that Tier 1 pre-empts planned work** — everything else is logistics.

> **The failure mode that destroys the framework:** silently missing SLAs. Once
> the Tier 1 queue contains items open for months, the tier stops meaning "this
> week" — and then it stops meaning anything.

### Metrics worth reporting

| Metric | Why |
|--------|-----|
| Tier 1 SLA attainment | The headline number |
| Tier 1 queue age (oldest open item) | One stale item does more credibility damage than a dozen recent ones |
| Classification stability | High churn means the procedure is being applied inconsistently |
| Tier 3 completion rate | A program that never closes Tier 3 keeps refilling Tiers 1 and 2 |
| Exceptions past review date | Should be zero; rarely is |

---

## Repository structure

```
beacon/
├── CLASSIFICATION.md        <- how to assign a tier
├── CATALOG.md               <- all 36 finding classes
├── beacon-catalog.json      <- machine-readable
├── GLOSSARY.md
├── SOURCES.md               <- evidence for every figure
├── VERSIONING.md            <- stability guarantees
├── CONTRIBUTING.md
│
├── tiers/                   <- tier definitions
├── network/                 <- NET domain
├── identity-and-access-management/   <- IAM domain
├── data/                    <- DAT domain
└── processing-protection/   <- PRC domain
```

---

## Contributing

The most valuable contribution is **disagreement about tier assignment**. If your
environment makes a finding clearly higher or lower risk than its assigned tier,
either the tier is wrong or the entry's rationale is not explaining itself well
enough — both are worth fixing.

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

[GNU General Public License v3.0](LICENSE).

Published by **Penti.ai**, building on work originated at **Securily**.

---

*Cut through the noise. Secure what matters.*
