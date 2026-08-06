# Classification Procedure

**How to assign a Beacon tier to any security finding.**

---

## Why this document exists

A tier system is only worth having if two people classifying the same finding
reach the same answer. Without a fixed procedure, tier assignment collapses into
argument-by-seniority, and the backlog ends up sorted by whoever cared most
loudly.

This document defines the procedure. It is deliberately short, deliberately
ordered, and deliberately answerable without a CVE, a CVSS score, or a specific
scanner.

---

## The four questions

Apply them **in order**. Stop at the first that returns *yes*.

```
                    ┌─────────────────────────────────────────────┐
                    │ 1. Reachable by an untrusted party RIGHT NOW?│
                    └────────────────┬────────────────────────────┘
                          yes ┌──────┴──────┐ no
                              ▼             ▼
        ┌─────────────────────────────┐   (go to 3)
        │ 2. Does exploitation grant   │
        │    access / privilege / data │
        │    in one step?              │
        └──────────┬──────────────────┘
              yes  │        no
                   ▼         └────────► (go to 3)
              ┌─────────┐
              │ TIER 1  │  24–72 hours
              └─────────┘

                    ┌─────────────────────────────────────────────┐
                    │ 3. Would a NAMED auditor, regulator, or      │
                    │    contractual counterparty cite it?         │
                    └────────────────┬────────────────────────────┘
                          yes ┌──────┴──────┐ no
                              ▼             ▼
                         ┌─────────┐   ┌─────────────────────────────┐
                         │ TIER 2  │   │ 4. Does fixing it reduce     │
                         │ 30 days │   │    future Tier 1 / Tier 2?   │
                         └─────────┘   └──────────┬──────────────────┘
                                             yes  │  no
                                                  ▼   └──► Not a Beacon finding
                                             ┌─────────┐
                                             │ TIER 3  │  90 days
                                             └─────────┘
```

---

### Question 1 — Is it reachable by an untrusted party right now?

Not in theory. Not after a chain of preconditions. **Right now**, from where an
attacker actually stands.

A vulnerability on a host that nothing can route to is a materially different
problem from the same vulnerability on a public address. This question is first
because it eliminates most of the backlog immediately, and because — unlike
severity — it is objectively testable.

| Answer | Action |
|--------|--------|
| **Yes** | Continue to question 2 |
| **No** | Skip to question 3. Re-evaluate when the network changes. |

**How to answer it honestly:**

- Scan from *outside* your own network. Cloud-internal scanning misses exposure
  created by public load balancers and NAT rules.
- Check internet-wide scan data (Shodan, Censys) for your netblocks — that is
  what the attacker sees.
- "Reachable" includes reachable from a routinely-compromised segment, such as a
  general-purpose workstation VLAN. An attacker who phishes one user is inside
  that segment.

---

### Question 2 — Does exploitation grant access, privilege, or data in one step?

A single step with a known technique — not a five-stage theoretical path.

- Reading an open storage bucket **qualifies**: reading *is* the exploit.
- A race condition requiring local access and precise timing **does not**.
- If confirmed exploitation exists in the wild, the answer is *yes* by
  definition. The [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
  is the authority.

| Answer | Result |
|--------|--------|
| **Yes** (with Q1 yes) | **Tier 1** — remediate in 24–72 hours, escalate to CISO at 48 hours |
| **No** | Continue to question 3 |

---

### Question 3 — Would a named auditor, regulator, or counterparty cite it?

**Named**, not hypothetical. If you can point to the framework and the control —
PCI DSS 8.3.6, ISO 27001 A.5.18, SOC 2 CC6.2 — the answer is yes.

If the answer is "a strict auditor *might*", it is not Tier 2.

The distinguishing consequence is a finding in *someone else's* report, with a
deadline that belongs to them.

| Answer | Result |
|--------|--------|
| **Yes** | **Tier 2** — remediate in 30 days, scheduled against the audit calendar |
| **No** | Continue to question 4 |

---

### Question 4 — Does fixing it reduce future Tier 1 and Tier 2 findings?

This is the compounding test.

Infrastructure-as-code policy gates prevent the entire class of public-storage
findings. Role refinement reduces what any future credential theft yields.
Neither is urgent; both pay down the rate at which the upper tiers refill.

| Answer | Result |
|--------|--------|
| **Yes** | **Tier 3** — remediate in 90 days, or defer formally on the record |
| **No** | **Not a Beacon finding.** Close it, or route it to the appropriate engineering backlog. |

Recording non-findings as findings dilutes the queue and is itself a failure
mode.

---

## Why the order cannot be changed

Reachability comes **first** because it is objectively testable and because it
eliminates most of the backlog immediately.

Compliance comes **third** because a control obligation says nothing about
urgency. A great deal of mandated work is genuinely not urgent, and a small
amount of unmandated work genuinely is.

Teams that reverse these two end up with an emergency queue full of audit items
while real exposures sit on a 30-day clock. This is the single most common way
the framework is misapplied.

---

## Then assign a domain

Tier sets the **deadline**. Domain sets the **owner**.

| Domain | Code | Question it answers | Typical owner |
|--------|------|---------------------|---------------|
| [Network](network/) | `NET` | What can be reached, and from where? | Network / cloud platform |
| [Identity & Access](identity-and-access-management/) | `IAM` | Who can act, and how strongly is that proven? | Identity engineering / IT |
| [Data Protection](data/) | `DAT` | What happens to the data if everything else fails? | Data platform / application |
| [Processing Protection](processing-protection/) | `PRC` | Is the compute that runs the business trustworthy and available? | Platform engineering / SRE |

**Assign the domain of the control that fixes it, not the domain of the
symptom.** An exposed database is a Network finding if the fix is a firewall
rule, and a Data finding if the fix is enabling authentication.

---

## Worked examples

Each of these is a case where the intuitive answer and the correct answer
differ.

### 1. CVSS 9.8 RCE in a library used by an internal batch job with no listener

| Step | Answer |
|------|--------|
| Q1 — reachable? | **No.** Nothing routes to it. |
| Q3 — auditor deficiency? | **Yes.** Unpatched critical vulnerabilities breach vulnerability-management requirements. |

→ **Tier 2**

*The 9.8 is doing no work here. Score describes the vulnerability; reachability
describes your exposure.*

---

### 2. CVSS 6.5 in an internet-facing edge appliance, listed in CISA KEV

| Step | Answer |
|------|--------|
| Q1 — reachable? | **Yes.** It is the edge. |
| Q2 — one step? | **Yes.** KEV membership means confirmed exploitation. |

→ **Tier 1**

*A mid-range score outranks a 9.8 because someone is actually using this one.
Observed exploitation beats modeled severity.*

---

### 3. S3 bucket with public read, containing only marketing images

| Step | Answer |
|------|--------|
| Q1 — reachable? | **Yes.** Anonymously, from the internet. |
| Q2 — one step? | **Yes.** Reading is the exploit. |

→ **Tier 1**

*Classify by what the permissions allow, not by an inventory of current
contents. If write access is also open, the bucket becomes a malware
distribution point trading on your domain's reputation.*

---

### 4. Password policy sets a 10-character minimum; PCI DSS v4.0 requires 12

| Step | Answer |
|------|--------|
| Q1 — reachable? | **No**, in the sense meant — no attacker acts on the policy itself. |
| Q3 — auditor deficiency? | **Yes.** PCI DSS 8.3.6, objectively verifiable from a config export. |

→ **Tier 2**

*Authentication-related does not mean Tier 1. Missing MFA on privileged accounts
is Tier 1; a policy shortfall on the general population is a compliance
deficiency.*

---

### 5. Terraform pipeline has no policy gate blocking public buckets

| Step | Answer |
|------|--------|
| Q1 — reachable? | **No.** The pipeline is not exposed. |
| Q3 — auditor deficiency? | **No.** No framework mandates this specific gate. |
| Q4 — reduces future findings? | **Yes, decisively.** It prevents the public-bucket class entirely. |

→ **Tier 3**

*The highest-leverage Tier 3 work looks unremarkable in a backlog. Its value is
measured in the Tier 1 findings that never get created.*

---

### 6. Developer group holds permanent `AdministratorAccess` in production

| Step | Answer |
|------|--------|
| Q1 — reachable? | **Yes.** Any of those developers is reachable by phishing. |
| Q2 — one step? | **Yes.** One credential yields full administrative control. |

→ **Tier 1**

*No CVE, no scanner severity, and still Tier 1. Standing privilege sets the
blast radius of every other compromise.*

---

## Six ways classification goes wrong

| Failure mode | Why it happens | Correction |
|--------------|----------------|------------|
| **Evaluating compliance before reachability** | "Is this a compliance issue?" feels like the easier question | Follow the order. This is the reason the order exists. |
| **Treating CVSS as the tier** | The score is already in the scanner output | A 9.8 with no reachability is Tier 2; a 6.5 in KEV on the edge is Tier 1 |
| **Downgrading because an environment is labeled non-production** | The label is taken at face value | Dev databases are routinely seeded with production data and share credentials. Classify by data present and credentials accepted. |
| **Downgrading because a service is patched** | Patch state feels like it resolves the finding | An internet-facing SSH service with current patches is still Tier 1 until reachability is removed |
| **Folding a Tier 1 finding into a Tier 3 program** | It was discovered *during* the Tier 3 work | Exposed pipeline credentials found during CI/CD hardening are Tier 1. Record separately or you silently apply a 90-day SLA to a 72-hour problem. |
| **Importing a benchmark report wholesale at one tier** | The report has its own severity column | CIS output mixes genuine Tier 1 items with Tier 3 hygiene. Triage each item; the report's ratings are not tiers. |

---

## Tier changes are expected

The same technical condition can be Tier 1 in one environment and Tier 3 in
another, because tier depends on context — principally reachability and the data
at stake.

Tier also changes when context changes. **Removing internet exposure
legitimately reduces a Tier 1 finding**, which is why withdrawing reachability is
so often the fastest available remediation: it converts an emergency into
scheduled work.

Record the reason for any tier change. A finding whose tier moves without a
recorded rationale is indistinguishable from one that was misclassified.

---

## What each tier commits you to

A tier is not a label. It names a deadline, an owner, an escalation path, and the
budget the work comes from.

| | **Tier 1** | **Tier 2** | **Tier 3** |
|---|---|---|---|
| **Name** | Critical | Regulatory | Best Practices |
| **Deadline** | 24–72 hours | 30 days | 90 days |
| **Escalation** | CISO + exec sponsor at 48h | Security manager at 14d | Quarterly planning review |
| **Owner** | Security ops, named engineering owner | Compliance, engineering executes | Platform / engineering |
| **Budget** | Unplanned — pre-empts sprint commitments | Planned — against the audit calendar | Planned — standing capacity allocation |
| **Deferral** | Requires exec sign-off + compensating control | Requires documented exception | Legitimate, recorded outcome |

---

## When the SLA cannot be met

Record the exception. Do **not** quietly extend the deadline.

A Tier 1 finding that cannot be remediated within 72 hours requires:

1. A documented compensating control (frequently: withdraw reachability)
2. A named accountable owner
3. A review date
4. Escalation to executive level

The escalation is the mechanism that produces either the resources or an
explicit, accountable decision to accept the risk.

> **The failure mode that destroys the framework:** silently missing SLAs. Once
> the Tier 1 queue contains items open for months, the tier stops meaning "this
> week" — and then it stops meaning anything. No amount of process recovers it.

---

## Related documents

- [Tier 1: Critical](tiers/tier-1-critical-threat-management.md)
- [Tier 2: Regulatory](tiers/tier-2-regulatory.md)
- [Tier 3: Best Practices](tiers/tier-3-best-practices.md)
- [Finding Catalog](CATALOG.md) — canonical identifiers for every finding class
- [Glossary](GLOSSARY.md) — terms as this standard uses them
- [Sources](SOURCES.md) — evidence behind every figure cited
