# Sources

**Every quantitative claim in this standard resolves to an entry here, and every
entry names a public, linkable primary source.**

---

## The rule for contributors

If a number cannot be traced to a published report that a reader can open and
check, it does not go in the standard.

This matters more here than in most documentation. Beacon is used to justify
remediation spend and to argue for engineering time against competing
priorities. A figure that turns out to be unsourced — or worse, circular —
undermines every other claim in the document it appears in.

Figures drift between annual editions. **`As of` records the edition each claim
was taken from.** When updating to a newer edition, update the figure and the
edition together; do not carry a number forward across editions on the
assumption it still holds.

---

## S1 — Exploitation as a breach entry point

> **Claim:** Exploitation of vulnerabilities as an initial access vector grew
> substantially year over year — roughly tripling in the 2024 reporting period.

| | |
|---|---|
| **Publisher** | Verizon |
| **Source** | [Data Breach Investigations Report](https://www.verizon.com/business/resources/reports/dbir/) |
| **As of** | 2024 edition |

**What the source says:** The 2024 DBIR reported that exploitation of
vulnerabilities as a critical path to initiate a breach almost tripled from the
prior year, driven substantially by mass exploitation of edge devices and
managed file-transfer software.

**Where used:** [README](README.md), [Tier 1](tiers/tier-1-critical-threat-management.md),
[Known-Exploited Vulnerabilities](processing-protection/known-exploited-vulnerabilities.md)

---

## S2 — Most CVEs are never exploited

> **Claim:** Only a small minority of published CVEs are ever exploited in the
> wild — roughly one in twenty.

| | |
|---|---|
| **Publisher** | Cyentia Institute (with Kenna Security) |
| **Source** | [Prioritization to Prediction research series](https://www.cyentia.com/research/) |
| **As of** | P2P volumes, 2019–2023 |

**What the source says:** Successive volumes found that approximately one in
twenty published vulnerabilities is ever observed being exploited, and —
critically — that remediating by CVSS score alone performs little better than
remediating at random.

**Why this matters to Beacon:** This is the empirical basis for the entire
framework. It is the reason [CLASSIFICATION.md](CLASSIFICATION.md) asks about
reachability and observed exploitation *before* it asks about anything else, and
the reason CVSS is an input rather than the decision.

**Where used:** [README](README.md), [CLASSIFICATION](CLASSIFICATION.md),
[Known-Exploited Vulnerabilities](processing-protection/known-exploited-vulnerabilities.md)

---

## S3 — Ransomware operates faster than most remediation SLAs

> **Claim:** In ransomware intrusions the interval between initial access and
> encryption is frequently under 24 hours.

| | |
|---|---|
| **Publisher** | Secureworks |
| **Source** | [State of the Threat Report](https://www.secureworks.com/resources/rp-state-of-the-threat-2023) |
| **As of** | 2023 edition |

**What the source says:** Median dwell time before ransomware deployment fell to
approximately 24 hours, with a meaningful share of cases completing in under a
day.

**Why this matters to Beacon:** This is the justification for the 24-hour Tier 1
SLA. **A remediation window longer than the attack window is not a control** — it
is a statement of intent. Tier 1 SLAs are set below observed attacker operating
time deliberately.

**Where used:** [Tier 1](tiers/tier-1-critical-threat-management.md),
[CLASSIFICATION](CLASSIFICATION.md)

---

## S4 — Attacker dwell time

> **Claim:** Global median attacker dwell time is now measured in days rather
> than months.

| | |
|---|---|
| **Publisher** | Mandiant (Google Cloud) |
| **Source** | [M-Trends](https://cloud.google.com/security/resources/m-trends) |
| **As of** | Recent editions |

**What the source says:** Recent M-Trends editions report a global median dwell
time of approximately ten days, down from over 400 days a decade earlier.

**Interpretation note:** Shorter dwell time reflects *both* improved detection
and the rise of ransomware, which announces itself. It should not be read purely
as a defensive improvement.

**Where used:** [Tier 1](tiers/tier-1-critical-threat-management.md), [GLOSSARY](GLOSSARY.md)

---

## S5 — The human element in breaches

> **Claim:** The human element is involved in roughly two-thirds of breaches.

| | |
|---|---|
| **Publisher** | Verizon |
| **Source** | [Data Breach Investigations Report](https://www.verizon.com/business/resources/reports/dbir/) |
| **As of** | 2024 edition |

**What the source says:** The 2024 DBIR attributed 68% of breaches to a
non-malicious human element — error, privilege misuse, stolen credentials, or
social engineering.

**Why this matters to Beacon:** This is why MFA coverage
([BCN-T1-IAM-001](identity-and-access-management/mandatory-mfa.md)) and privilege
scope ([BCN-T1-IAM-002](identity-and-access-management/high-privilege-accounts.md))
sit at Tier 1 alongside software vulnerabilities. A framework that only tiers
CVEs addresses a minority of real exposure.

**Where used:** [README](README.md), [Tier 1](tiers/tier-1-critical-threat-management.md)

---

## S6 — Cost of a breach

> **Claim:** The global average cost of a data breach is approximately USD 4.9
> million.

| | |
|---|---|
| **Publisher** | IBM Security / Ponemon Institute |
| **Source** | [Cost of a Data Breach Report](https://www.ibm.com/reports/data-breach) |
| **As of** | 2024 edition |

**What the source says:** The 2024 report put the global average at USD 4.88
million, its highest recorded figure. The same report consistently finds that
shorter identification-and-containment cycles correlate with materially lower
cost.

**Where used:** [README](README.md), tier documentation

---

## S7 — MFA effectiveness

> **Claim:** MFA blocks the overwhelming majority of automated account-compromise
> attacks.

| | |
|---|---|
| **Publisher** | Microsoft |
| **Source** | [One simple action you can take to prevent 99.9 percent of attacks on your accounts](https://www.microsoft.com/security/blog/2019/08/20/one-simple-action-you-can-take-to-prevent-99-9-percent-of-account-attacks/) |
| **As of** | 2019 |

**What the source says:** Microsoft reported that MFA blocks over 99.9% of
automated account compromise attempts.

**Interpretation note — read this before citing the figure:** The 99.9% applies
to **automated, commodity attacks**: credential stuffing, password spraying,
bulk phishing. It does **not** apply to adversary-in-the-middle phishing kits,
MFA fatigue attacks, or SIM-swap against SMS-based factors, all of which are now
routine. This is precisely why
[BCN-T1-IAM-001](identity-and-access-management/mandatory-mfa.md) requires
*phishing-resistant* MFA (FIDO2/WebAuthn) for privileged accounts rather than
treating all MFA as equivalent.

**Where used:** [Mandatory MFA](identity-and-access-management/mandatory-mfa.md),
[Tier 1](tiers/tier-1-critical-threat-management.md)

---

## S8 — The KEV catalog is a small fraction of published CVEs

> **Claim:** The authoritative list of vulnerabilities confirmed to be exploited
> in the wild is a fraction of a percent of all published CVEs.

| | |
|---|---|
| **Publisher** | CISA |
| **Source** | [Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| **As of** | Continuously updated |

**What the source says:** The KEV catalog lists on the order of a thousand-plus
entries against a published CVE corpus in the hundreds of thousands.

**Why this matters to Beacon:** The narrowness *is* the value. A list small
enough to action completely is more useful than a severity rating applied to
everything. This is why
[BCN-T1-PRC-001](processing-protection/known-exploited-vulnerabilities.md)
exists as a distinct finding rather than as a severity attribute.

**Where used:** [Known-Exploited Vulnerabilities](processing-protection/known-exploited-vulnerabilities.md),
[CLASSIFICATION](CLASSIFICATION.md)

---

## Claims removed from this standard

Recorded here so they are not reintroduced.

| Removed claim | Reason |
|---------------|--------|
| *"Reduce MTTR for critical vulnerabilities by up to 70%"* | No traceable source. It described an outcome the framework had not measured, presented as an established result. |
| *"73% of ransomware attacks exploit Tier 1 findings"* | **Circular.** Tier 1 is defined as the findings attackers exploit, so the statistic restates the definition rather than evidencing it. |
| *"61% of successful breaches are credential-based"* | Figure could not be traced to a specific edition of a named report. Superseded by **S5**, which is traceable. |
| *"80% of breaches involve privileged credential abuse"* | Widely repeated in vendor material without a consistent primary source. Superseded by **S5**. |

---

## Adding a source

1. Find the **primary** source — the report itself, not an article summarising it
2. Record publisher, title, stable URL, and the edition or date
3. Quote or closely paraphrase **what the source actually says**, not the
   strongest reading of it
4. State where the claim is used, so it can be updated everywhere at once
5. Add an interpretation note wherever the figure is commonly over-applied (see
   **S7** for the pattern)

If a claim is useful but unsourceable, either present it explicitly as
first-party experience — clearly labelled as such — or cut it. Do not present it
as an established finding.

---

*See [CONTRIBUTING.md](CONTRIBUTING.md) for the full contribution process.*
