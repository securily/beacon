# Versioning and Stability Policy

**Current version: 1.1.0**

This standard is consumed programmatically. This document defines what consumers
can rely on and what may change.

---

## Why this matters

Beacon identifiers appear in penetration test reports, customer-facing
remediation plans, ticketing systems, and third-party tooling. Several of these
outlive the systems that produced them.

A standard whose identifiers shift is not a standard — it is a moving target
that quietly invalidates every document that ever cited it.

### Known consumers

| Consumer | Uses |
|----------|------|
| Beacon Analyzer (Lambda) | Finding classification and tier assignment |
| Backend API | Categorisation endpoints |
| Dashboard | Tier and domain display |
| Third parties | `beacon-catalog.json` under GPL-3.0 |

---

## The stability guarantee

### Permanent — will never change

| Element | Guarantee |
|---------|-----------|
| **Finding identifiers** | Never reused, never renumbered. `BCN-T1-NET-001` denotes the same finding class forever. |
| **Identifier format** | `BCN-T{tier}-{DOMAIN}-{sequence}` |
| **Tier numbers** | `1`, `2`, `3` — meaning fixed |
| **Domain codes** | `NET`, `IAM`, `DAT`, `PRC` |

**A finding is never deleted.** If a class becomes obsolete it is marked
`deprecated` with a `supersededBy` pointer, and remains in the catalog
permanently so that historical citations still resolve.

### Stable — changes only in a major version

- The four-question classification procedure and its ordering
- Tier SLA values (24–72h / 30d / 90d)
- The set of domains
- Required fields in `beacon-catalog.json`

### May change in a minor version

- New finding classes (new identifiers, appended)
- New framework mappings on existing findings
- New optional fields in the JSON schema
- Scanner lists
- Documentation prose, detection commands, remediation guidance

### May change in a patch version

- Typos, formatting, broken links
- Clarifications that do not alter meaning

---

## Semantic versioning

```
MAJOR . MINOR . PATCH
  │       │       └── Corrections; no semantic change
  │       └────────── Additive; existing consumers unaffected
  └────────────────── Breaking; consumers must review
```

### What triggers a MAJOR version

- A tier's SLA changes
- The classification procedure changes in a way that reassigns existing findings
- A domain is added or removed
- A required field is removed from the JSON schema
- An existing finding moves tier

> A finding moving tier is a **breaking change**, because downstream systems
> derive due dates from tier. It is handled by deprecating the old identifier and
> issuing a new one, never by editing the tier in place.

### What triggers a MINOR version

- New finding classes
- New framework mappings
- New optional JSON fields
- Substantive documentation expansion

---

## Consumer contract

### Required behaviour

**Ignore unknown fields.** New optional fields are added in minor versions.
Consumers that reject unrecognised fields will break on routine updates.

```python
# Correct — tolerant of additive change
finding = catalog["findings"][0]
tier = finding["tier"]
sla  = finding["sla"]
# unknown fields ignored

# Incorrect — breaks on any minor version
assert set(finding.keys()) == EXPECTED_KEYS
```

**Pin the major version.** Check `version` at load and fail loudly on an
unexpected major:

```python
major = int(catalog["version"].split(".")[0])
if major != SUPPORTED_MAJOR:
    raise IncompatibleCatalogVersion(
        f"Catalog major {major}, this consumer supports {SUPPORTED_MAJOR}"
    )
```

**Treat identifiers as opaque strings.** Do not parse them to derive tier or
domain — read the `tier` and `domain` fields instead. The format is stable, but
reading the explicit fields is correct and survives any future format extension.

```python
# Correct
tier = finding["tier"]

# Fragile
tier = int(finding["id"][5])
```

**Handle deprecated findings.** A finding may carry `deprecated: true` and
`supersededBy`. Resolve historical identifiers rather than failing on them:

```python
def resolve(finding_id, catalog):
    f = index[finding_id]
    while f.get("supersededBy"):
        f = index[f["supersededBy"]]
    return f
```

### Recommended behaviour

- Cache the catalog; do not fetch per-finding
- Log the catalog version alongside classification results, so historical
  results remain interpretable
- Re-validate against the schema after each update

---

## Deprecation process

1. **Announce** in the release notes with rationale
2. **Mark** the finding `deprecated: true`, add `supersededBy` and
   `deprecatedIn`
3. **Retain** the entry in the catalog permanently
4. **Update** documentation to point at the successor

```json
{
  "id": "BCN-T1-NET-004",
  "deprecated": true,
  "deprecatedIn": "2.0.0",
  "supersededBy": "BCN-T1-NET-001",
  "deprecationReason": "Merged into BCN-T1-NET-001; the distinction did not change remediation."
}
```

Deprecated findings are **never removed**. A report citing `BCN-T1-NET-004` in
2027 must still resolve.

---

## Version history

| Version | Date | Summary |
|---------|------|---------|
| **1.1.0** | 2026-07 | Canonical identifiers and `beacon-catalog.json` introduced. Classification procedure documented. Seven stub findings expanded to full entries. `BCN-T1-PRC-001` (known-exploited vulnerabilities) added. Unsourced statistics replaced with cited figures. Glossary, sources, versioning, and contribution guidance added. |
| **1.0.0** | 2026-04 | Initial public standard: three tiers, four domains, scanner and framework mappings. |

### 1.1.0 compatibility notes

Additive. No identifier changed, no tier moved, no SLA changed.

Consumers on 1.0.0 continue to work unchanged. To adopt the new capability:

- Read `beacon-catalog.json` rather than parsing the Markdown
- Use finding identifiers where previously you matched on file paths or titles
- `BCN-T1-PRC-001` is a new class — existing KEV findings previously classified
  under a generic patching category should be re-mapped

---

## Requesting a change

Changes that would affect the stability guarantee need discussion **before**
implementation. Open an issue describing:

- The change and which guarantee it touches
- Why it cannot be handled additively
- The migration path for existing consumers
- Which documents and identifiers are affected

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

*Beacon Security Standards is published by Penti.ai under
[GPL-3.0](LICENSE), building on work originated at Securily.*
