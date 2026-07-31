# Contributing to Beacon Security Standards

Beacon is developed openly under [GPL-3.0](LICENSE). Contributions from
practitioners are what keep it grounded.

---

## The most valuable contributions

In rough order of value:

1. **Disagreement about tier assignment.** If your environment makes a finding
   clearly higher or lower risk than its assigned tier, that is the most useful
   thing you can tell us. Either the tier is wrong, or the entry's rationale is
   not explaining itself well enough — both are worth fixing.

2. **Finding classes the catalog is missing.** Especially misconfigurations,
   identity weaknesses, and process gaps, which carry no CVE and are
   under-represented in every framework.

3. **Detection commands that actually work.** Verified against a real
   environment, with the provider and version noted.

4. **Corrections to framework mappings.** Control references drift between
   framework versions.

5. **Sources for existing claims**, or challenges to claims that look unsourced.

---

## What to open

| Type | Use for |
|------|---------|
| **Issue** | Tier disagreement, missing finding, factual error, ambiguity |
| **Pull request** | Documentation improvement, verified command, mapping correction, new finding |
| **Discussion issue first** | Anything touching the [stability guarantee](VERSIONING.md) |

---

## Proposing a new finding class

A new finding class needs to justify its existence. Before proposing, check that
it is not already covered by an existing entry in [CATALOG.md](CATALOG.md) —
overlapping classes create classification arguments, which is exactly what the
framework exists to prevent.

Include:

- **Name and one-sentence summary**
- **Proposed tier**, with the [four-question walkthrough](CLASSIFICATION.md)
  showing how you reached it
- **Proposed domain**, using the fix's domain rather than the symptom's
- **Why existing entries do not cover it**
- **Detection method** — how someone determines whether they have it
- **Remediation steps**, ordered
- **Verification** — the test that proves it is fixed
- **Framework mappings** where they apply

Maintainers assign the identifier. Do not assign one yourself; sequence numbers
are allocated centrally to keep them unique and permanent.

---

## Writing a finding entry

Match the structure used throughout the standard. The reference example is
[mandatory-mfa.md](identity-and-access-management/mandatory-mfa.md).

```markdown
# Finding Name

## Tier: N - Tier Name
**Beacon ID:** `BCN-TN-XXX-000`
**MITRE ATT&CK:** [TNNNN - Technique](https://attack.mitre.org/techniques/TNNNN/)
**Remediation SLA:** N hours/days
**Escalation:** ...

## Risk Description       <- what it is, and what it costs
### Business Impact       <- consequence in business terms

## Detection Methods      <- tools, then working commands
## Qualifying Criteria    <- checkboxes; when does this apply
## Remediation            <- ordered; fastest exposure reduction first
## Verification           <- the test that proves closure
## Exception Handling     <- when it cannot be done in time
## Monitoring Requirements
## References             <- primary sources only
## Related Findings
```

### House style

**Order remediation by exposure reduction, not by completeness.** The first step
should be the one that most reduces exposure fastest — frequently "remove the
ingress rule" rather than "harden the service". Say so explicitly when the
fastest step is not the complete fix.

**State the boundary conditions.** Every entry should say what it is *not*, and
where the finding would belong instead. Misclassification between adjacent
findings is the most common failure mode in practice.

**Verification must be a test, not an assertion.** "Encryption enabled" is a
setting. "An unauthenticated request from an external host returns 403" is a
test. Write the test.

**No unsourced numbers.** See [SOURCES.md](SOURCES.md). If you cannot trace a
figure to a public report, either cut it or label it explicitly as first-party
experience.

**Commands should be runnable.** Specify the provider and note where output
needs interpretation. Prefer commands that reveal the *effective* state over
those that report the *intended* configuration — the gap between the two is
usually where the finding lives.

---

## Pull request checklist

- [ ] Follows the entry structure above
- [ ] Detection commands tested against a real environment
- [ ] Framework control references verified against the current framework version
- [ ] Any new quantitative claim has a `SOURCES.md` entry
- [ ] Related findings cross-linked in both directions
- [ ] `beacon-catalog.json` updated if a finding was added or a mapping changed
- [ ] Catalog validates (see below)
- [ ] No identifier reused, renumbered, or removed

### Validating the catalog

```bash
node -e '
const c = require("./beacon-catalog.json");
const fs = require("fs");
const ids = c.findings.map(f => f.id);

if (new Set(ids).size !== ids.length) throw new Error("duplicate identifiers");

const bad = c.findings.filter(f =>
  !/^BCN-T[123]-(NET|IAM|DAT|PRC)-\d{3}$/.test(f.id));
if (bad.length) throw new Error("malformed: " + bad.map(f => f.id));

const missing = c.findings.filter(f => !fs.existsSync(f.documentation));
if (missing.length) throw new Error("missing docs: " + missing.map(f => f.documentation));

console.log("OK -", c.findings.length, "findings");
'
```

---

## Challenging a tier assignment

This is welcomed, and there is a right way to do it.

Open an issue containing:

1. The finding identifier
2. Your walkthrough of the [four questions](CLASSIFICATION.md)
3. Where your answer diverges from the entry's stated rationale
4. The environmental context that drives the difference

Remember that **tier depends on context** — the same condition can legitimately
be Tier 1 in one environment and Tier 3 in another. The catalog assigns the tier
for the *typical* case and documents the boundary conditions.

If your context is the atypical one, the right outcome is usually a clarified
boundary condition in the entry rather than a tier change. If the catalog has
the typical case wrong, that is a tier change and a
[major version](VERSIONING.md).

---

## What will be declined

- **Vendor-specific findings** that only apply to one commercial product, unless
  the product is near-ubiquitous
- **New tiers or domains.** Three and four respectively. Categorisation schemes
  fail by growing, and every addition creates boundary cases that cost more than
  the remediation would have.
- **Findings without a remediation** — if there is nothing to do about it, it is
  an observation, not a finding
- **Unsourced statistics**, however widely repeated
- **Severity ratings imported wholesale** from another tool as if they were
  Beacon tiers

---

## Code of conduct

Assume competence and good faith. Practitioners disagree about risk because
their environments genuinely differ — argue from the environment and the
evidence, not from seniority.

---

## Licence

Contributions are accepted under [GPL-3.0](LICENSE). By submitting, you confirm
you have the right to contribute the material.

---

*Beacon Security Standards is published by Penti.ai, building on work originated
at Securily.*
