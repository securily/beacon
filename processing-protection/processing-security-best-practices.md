# Processing Security Best Practices

## Tier: 3 - Best Practices
**Beacon IDs:** `BCN-T3-PRC-001`, `BCN-T3-PRC-002`, `BCN-T3-PRC-003`
**MITRE ATT&CK:** [T1610 - Deploy Container](https://attack.mitre.org/techniques/T1610/), [T1611 - Escape to Host](https://attack.mitre.org/techniques/T1611/), [T1195.002 - Compromise Software Supply Chain](https://attack.mitre.org/techniques/T1195/002/)
**Remediation SLA:** 90 days
**Escalation:** Quarterly planning review

---

## Risk Description

Hardening the compute layer: constraining what an application compromise yields,
and protecting the integrity of the pipeline that produces the compute in the
first place.

These controls do not prevent initial compromise. They determine what happens
**next** — whether code execution in a container becomes host access, whether a
build compromise reaches production, whether a misconfiguration ever gets
deployed at all.

### Scope of this finding

| ID | Finding | What it prevents |
|----|---------|------------------|
| `BCN-T3-PRC-001` | Container and image hardening | Code execution becoming host compromise |
| `BCN-T3-PRC-002` | CI/CD pipeline hardening | A build compromise reaching every downstream consumer |
| `BCN-T3-PRC-003` | Infrastructure-as-code security gaps | Misconfigurations being deployed at all |

`BCN-T3-PRC-003` deserves particular attention: **it is the highest-leverage
preventive control available for cloud misconfiguration.** A policy gate in the
pipeline prevents the entire class of findings that otherwise arrives as Tier 1
public storage and open security groups. Its value is measured in the Tier 1
findings that never get created.

---

## `BCN-T3-PRC-001` — Container and Image Hardening

### Detection

```bash
# Containers running as root — the single highest-value fix
kubectl get pods -A -o json | jq -r '
  .items[] |
  select(.spec.securityContext.runAsNonRoot != true) |
  select(.spec.containers[].securityContext.runAsNonRoot != true) |
  "\(.metadata.namespace)/\(.metadata.name)"'

# Privileged containers and dangerous capabilities
kubectl get pods -A -o json | jq -r '
  .items[] |
  select(.spec.containers[].securityContext.privileged == true or
         (.spec.containers[].securityContext.capabilities.add // [] |
          any(. == "SYS_ADMIN" or . == "NET_ADMIN"))) |
  "\(.metadata.namespace)/\(.metadata.name)"'

# Missing resource limits — a container without limits can starve the node
kubectl get pods -A -o json | jq -r '
  .items[] | select(.spec.containers[].resources.limits == null) |
  "\(.metadata.namespace)/\(.metadata.name)"'
```

```bash
# Cluster benchmark
kube-bench run --targets master,node,etcd,policies

# Image surface — package count is a proxy for attack surface and scan noise
trivy image --severity HIGH,CRITICAL --format json myapp:latest | \
  jq '{packages: (.Results[].Packages | length),
       vulns: ([.Results[].Vulnerabilities // []] | flatten | length)}'
```

### Qualifying Criteria

- [ ] Containers running as root
- [ ] Built on full OS base images where minimal or distroless would serve
- [ ] No resource limits set
- [ ] Unnecessary Linux capabilities retained
- [ ] Writable root filesystem
- [ ] Pod Security Standards not enforced at the namespace level
- [ ] Images unsigned, or signature verification available but not enforced at admission

### Remediation

**Non-root is the highest-value single change:**

```dockerfile
FROM gcr.io/distroless/static-debian12:nonroot
COPY --chown=nonroot:nonroot app /app
USER nonroot:nonroot
ENTRYPOINT ["/app"]
```

Distroless and minimal bases reduce both attack surface **and** vulnerability
scan noise — fewer packages means fewer CVEs to triage that were never reachable
from your code.

```yaml
# Workload constraints
securityContext:
  runAsNonRoot: true
  runAsUser: 10001
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  seccompProfile:
    type: RuntimeDefault
  capabilities:
    drop: ["ALL"]                # drop everything, re-add only what is required
resources:
  limits:   { cpu: "1000m", memory: "512Mi" }
  requests: { cpu: "100m",  memory: "128Mi" }
```

**Enforce at the namespace so new workloads inherit the constraints** rather
than relying on every author remembering:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/warn: restricted
```

**Verify signatures at admission** — signing without verification provides no
assurance:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-image-signature
spec:
  validationFailureAction: Enforce
  rules:
    - name: verify-signature
      match:
        any:
          - resources: { kinds: [Pod] }
      verifyImages:
        - imageReferences: ["registry.example.com/*"]
          attestors:
            - entries:
                - keyless:
                    issuer: https://token.actions.githubusercontent.com
                    subject: https://github.com/my-org/*
```

---

## `BCN-T3-PRC-002` — CI/CD Pipeline Hardening

### Why the pipeline is a high-value target

The pipeline holds production write access. Compromising a build reaches every
downstream consumer at once — which is what makes supply chain attacks
efficient.

These controls are Tier 3 rather than Tier 1 because the pipeline should already
be protected by access controls. Where those have failed, the finding is higher:

| Condition | Correct tier |
|-----------|--------------|
| Pipeline console reachable from the internet | **Tier 1** — [BCN-T1-PRC-002](unprotected-external-exposure.md) |
| Pipeline credentials exposed in a repository | **Tier 1** — [BCN-T1-IAM-003](../identity-and-access-management/secure-password-policies.md) |
| Unpinned dependencies, unsigned artifacts, shared runners | **Tier 3** — this finding |

### Detection

```bash
# Actions pinned to mutable tags rather than immutable digests
grep -rEn 'uses:\s+[^@]+@(v[0-9]+|main|master)$' .github/workflows/ \
  && echo "Mutable references — a tag can be repointed at any time"

# Workflows triggered by forks that can access secrets
grep -rln 'pull_request_target' .github/workflows/

# Are artifacts signed?
cosign verify --certificate-identity-regexp '.*' \
  --certificate-oidc-issuer-regexp '.*' \
  registry.example.com/myapp:latest 2>&1 | head -5
```

### Qualifying Criteria

- [ ] Third-party actions or dependencies pinned to mutable tags
- [ ] Lockfiles not enforced in CI
- [ ] Build artifacts unsigned, or signatures not verified at deployment
- [ ] Shared runners without isolation between jobs
- [ ] Repository secrets accessible to fork-triggered workflows
- [ ] No SBOM generated or retained
- [ ] Pipeline holds standing production credentials rather than federated, short-lived ones

### Remediation

```yaml
name: build
on: push

permissions:
  contents: read
  id-token: write        # OIDC — no stored cloud credentials
  packages: write

jobs:
  build:
    runs-on: ubuntu-latest      # ephemeral runner
    steps:
      # Pin to an immutable digest, not a tag
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2

      - name: Install with lockfile enforcement
        run: npm ci             # fails if lockfile and manifest disagree

      - name: Generate SBOM
        uses: anchore/sbom-action@v0
        with: { format: spdx-json, output-file: sbom.spdx.json }

      - name: Sign artifact
        run: cosign sign --yes ${IMAGE}@${DIGEST}
```

**Deny secrets to fork-triggered workflows.** `pull_request_target` runs with
repository secrets in the context of the *base* repository — an attacker's pull
request can exfiltrate them. Use `pull_request` for untrusted contributions.

---

## `BCN-T3-PRC-003` — Infrastructure-as-Code Security

### Detection

```bash
# Does IaC scanning run — and does it block, or merely report?
checkov -d . --compact --quiet
tfsec . --minimum-severity HIGH

# Drift — infrastructure changed outside the code path
terraform plan -detailed-exitcode
# exit 0 = no drift, 2 = drift detected
```

### Qualifying Criteria

- [ ] No IaC scanning in the pipeline
- [ ] Scanning runs in reporting mode only, never blocking
- [ ] No policy-as-code gate for high-risk resource configurations
- [ ] No drift detection
- [ ] Production infrastructure not defined in code at all
- [ ] No preventive guardrail for when the pipeline is bypassed

### Remediation

**Enable in reporting mode, clear the backlog, then switch to blocking.**
Starting in blocking mode against an existing backlog stalls every pull request
on day one and the gate gets disabled.

```yaml
- name: IaC policy gate
  run: |
    checkov -d . \
      --check CKV_AWS_20,CKV_AWS_57 \   # S3 public read / write
      --check CKV_AWS_23 \              # security group descriptions
      --check CKV_AWS_24,CKV_AWS_25 \   # unrestricted ingress 22 / 3389
      --check CKV_AWS_16,CKV_AWS_17 \   # RDS encryption, public accessibility
      --hard-fail-on HIGH
```

**Write policy for the configurations that actually produce Tier 1 findings** —
public storage, unrestricted ingress, unencrypted volumes:

```rego
package terraform.s3

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket_public_access_block"
  not resource.change.after.block_public_acls
  msg := sprintf("Bucket %v does not block public ACLs", [resource.address])
}
```

**Add preventive guardrails so the control holds even when the pipeline is
bypassed.** A pipeline gate protects only changes that go through the pipeline;
a service control policy protects everything.

```json
{
  "Sid": "DenyPublicBucketPolicies",
  "Effect": "Deny",
  "Action": ["s3:PutBucketPublicAccessBlock", "s3:PutAccountPublicAccessBlock"],
  "Resource": "*",
  "Condition": {
    "StringNotEquals": { "aws:PrincipalArn": "arn:aws:iam::*:role/security-admin" }
  }
}
```

> Existing misconfigurations surfaced by newly-enabled scanning are **separate
> findings at their own tiers**. Enabling the control and clearing its backlog
> are distinct pieces of work — do not fold a Tier 1 public bucket into this
> 90-day item.

---

## Verification

| Finding | Check | Evidence |
|---------|-------|----------|
| `BCN-T3-PRC-001` | Workloads run non-root with dropped capabilities | `kubectl` output across production namespaces |
| `BCN-T3-PRC-001` | Non-conforming manifest rejected | Admission test with a privileged pod |
| `BCN-T3-PRC-002` | Unpinned dependency fails the build | Test PR with a mutable reference |
| `BCN-T3-PRC-002` | Fork workflow cannot reach secrets | Test fork PR |
| `BCN-T3-PRC-002` | Runners are ephemeral | Runner configuration showing per-job lifecycle |
| `BCN-T3-PRC-003` | Public bucket PR blocked | Test pull request rejected by the gate |
| `BCN-T3-PRC-003` | Console bypass also denied | Same change attempted directly, denied by SCP |
| `BCN-T3-PRC-003` | Drift detected | Deliberate manual change surfaced by drift detection |

---

## Exception Handling

Where a workload genuinely requires elevated privilege (CNI plugins, storage
drivers, monitoring agents):

1. Record the specific capability required and why
2. Isolate to a dedicated namespace with its own policy exemption — never
   relax the cluster-wide baseline
3. Restrict which service accounts may schedule into that namespace
4. Apply enhanced runtime monitoring to the exempted workloads
5. Review at each upgrade, since requirements change between versions

---

## Monitoring Requirements

| Event | Action |
|-------|--------|
| Privileged container scheduled | Alert platform team |
| Pod Security Standard label changed | Alert; require change justification |
| Image deployed without a valid signature | Block at admission; alert |
| Workflow permissions broadened | Review at pull request |
| New repository secret created | Verify federation was unavailable |
| IaC scan bypassed or gate disabled | Immediate alert |
| Infrastructure drift detected | Ticket to the owning team within 24 hours |
| SCP or guardrail modified | Critical alert |

---

## References

- [NIST SP 800-190 — Application Container Security Guide](https://csrc.nist.gov/publications/detail/sp/800-190/final)
- [SLSA — Supply-chain Levels for Software Artifacts](https://slsa.dev/)
- [NIST SSDF SP 800-218](https://csrc.nist.gov/publications/detail/sp/800-218/final)
- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)

---

## Related Findings

- [Unprotected External Exposure](unprotected-external-exposure.md) — `BCN-T1-PRC-002`, Tier 1
- [DDoS Protection](ddos-protection.md) — `BCN-T1-PRC-003`, Tier 1
- [Regulatory Processing Compliance](regulatory-processing-compliance.md) — `BCN-T2-PRC-001`, Tier 2
- [Hardening of Cloud Resources](../network/hardening-of-cloud-resources.md) — `BCN-T3-NET-002`, Tier 3

---

*For classification guidance, see [Classification Procedure](../CLASSIFICATION.md).
For scanner details, see [Scanners and Frameworks](../scanners-and-frameworks.md).*
