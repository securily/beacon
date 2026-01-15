# Role-Based Access Control (RBAC)

## Tier: 3 - Best Practices
**CIS Controls:** 6.8 - Define and Maintain Role-Based Access Control  
**Remediation SLA:** 90 days  
**Risk Level:** Defense-in-depth improvement

---

## Overview

Role-Based Access Control (RBAC) is a foundational security model that restricts system access based on users' roles within an organization. Properly implemented RBAC reduces the attack surface by ensuring users only have access to resources required for their job functions.

### Benefits of RBAC
- **Reduced blast radius:** Compromised accounts have limited scope
- **Simplified management:** Add/remove access by role, not individual
- **Audit clarity:** Clear mapping of who can access what
- **Compliance support:** Demonstrates access control for auditors

---

## RBAC Design Principles

### Principle of Least Privilege
```
User needs → Minimum required permissions → Specific resources only
```

### Role Hierarchy Example
```
┌─────────────────────────────────────────────────────────────┐
│                    RBAC Hierarchy Model                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   [Super Admin] ─── Break-glass only, heavily audited      │
│        │                                                    │
│        ▼                                                    │
│   [Platform Admin] ─── Infrastructure management           │
│        │                                                    │
│   ┌────┴────┐                                              │
│   ▼         ▼                                              │
│ [DB Admin] [Network Admin] ─── Specialized roles           │
│                                                             │
│   ─────────────────────────────────────────────            │
│                                                             │
│   [Developer] ─── Application deployment, logs             │
│        │                                                    │
│        ▼                                                    │
│   [Read-Only] ─── Monitoring, dashboards                   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Detection Methods

### Tools
- **[PROWLER](https://prowler.cloud/):** IAM policy analysis for cloud environments
- **[Cloudsploit](https://cloudsploit.com/):** Permission evaluation and drift detection

### Analysis Commands

**AWS IAM Analysis:**
```bash
# Find overly permissive policies
aws iam get-account-authorization-details | \
  jq '.Policies[] | select(.PolicyDocument.Statement[].Action == "*")'

# List users with direct (non-role) policies
aws iam list-users --query 'Users[*].UserName' --output text | \
  xargs -I{} aws iam list-attached-user-policies --user-name {}

# PROWLER RBAC checks
prowler aws -c iam_policy_no_full_admin_access -c iam_policy_no_star_permissions
```

**Kubernetes RBAC:**
```bash
# Review cluster role bindings
kubectl get clusterrolebindings -o wide

# Check for overly permissive roles
kubectl auth can-i --list --as=system:anonymous

# Audit who can create pods (potential escape)
kubectl auth can-i create pods --all-namespaces -A
```

---

## Qualifying Criteria

A finding qualifies as Tier 3 RBAC issue if:

- [ ] Users assigned permissions directly instead of via roles
- [ ] Roles with permissions beyond job function requirements
- [ ] No documented RBAC model or permission matrix
- [ ] Missing role lifecycle management process
- [ ] Roles not reviewed for least privilege in 6+ months
- [ ] Service accounts using user roles
- [ ] No separation between admin and user roles

---

## Implementation Guide

### Step 1: Role Definition

```yaml
# Example role definitions
roles:
  platform-admin:
    description: "Full infrastructure management"
    permissions:
      - compute:*
      - network:*
      - storage:*
    restrictions:
      - Cannot modify billing
      - Cannot access customer data directly
      
  developer:
    description: "Application deployment and debugging"
    permissions:
      - compute:read
      - logs:read
      - deployments:write
    restrictions:
      - No infrastructure modification
      - No production data access
      
  analyst:
    description: "Read-only dashboards and reports"
    permissions:
      - dashboards:read
      - reports:read
      - logs:read (non-sensitive only)
```

### Step 2: AWS IAM Implementation

```hcl
# Terraform - AWS IAM roles
resource "aws_iam_role" "developer" {
  name = "developer-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        AWS = "arn:aws:iam::${var.account_id}:root"
      }
      Condition = {
        Bool = { "aws:MultiFactorAuthPresent" = "true" }
      }
    }]
  })
}

resource "aws_iam_role_policy" "developer" {
  name = "developer-policy"
  role = aws_iam_role.developer.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:Get*", "logs:Describe*", "logs:FilterLogEvents"]
        Resource = "arn:aws:logs:*:${var.account_id}:*"
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:ListBucket"]
        Resource = [
          "arn:aws:s3:::${var.deployment_bucket}",
          "arn:aws:s3:::${var.deployment_bucket}/*"
        ]
      }
    ]
  })
}
```

### Step 3: Kubernetes RBAC

```yaml
# Developer role - limited namespace access
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: development
  name: developer
rules:
  - apiGroups: [""]
    resources: ["pods", "pods/log", "services", "configmaps"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["get", "list", "watch", "create", "update"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: developer-binding
  namespace: development
subjects:
  - kind: Group
    name: developers
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: developer
  apiGroup: rbac.authorization.k8s.io
```

---

## Role Review Process

### Semi-Annual Review
1. Export current role assignments
2. Verify role-to-job function alignment
3. Identify excessive permissions
4. Remove unnecessary access
5. Document changes and approvals
6. Update role definitions as needed

### Review Checklist
- [ ] All users assigned to appropriate roles?
- [ ] Any users with direct permissions (should be roles)?
- [ ] Roles follow least privilege principle?
- [ ] Service accounts have dedicated roles?
- [ ] Terminated users removed from all roles?
- [ ] Role permissions match current job requirements?

---

## Anti-Patterns to Avoid

| Anti-Pattern | Issue | Solution |
|--------------|-------|----------|
| Role explosion | Too many granular roles | Consolidate to job functions |
| Permission creep | Roles accumulate permissions | Regular reviews |
| Shared admin accounts | No individual accountability | Individual admin roles |
| Static roles | Don't adapt to org changes | Tie to HR systems |
| Bypass mechanisms | Users request direct access | Enforce role-only access |

---

## Monitoring and Automation

```python
# Example: Automated role assignment from HR system
def sync_user_roles(user_data):
    role_mapping = {
        'Engineering': 'developer',
        'SRE': 'platform-admin', 
        'Security': 'security-analyst',
        'Support': 'read-only'
    }
    
    current_role = get_user_role(user_data['email'])
    expected_role = role_mapping.get(user_data['department'], 'read-only')
    
    if current_role != expected_role:
        update_user_role(user_data['email'], expected_role)
        log_role_change(user_data['email'], current_role, expected_role)
```

---

## References

- [NIST RBAC Model](https://csrc.nist.gov/projects/role-based-access-control)
- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [Kubernetes RBAC Documentation](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)

---

*For scanner details, see [Scanners and Frameworks](../scanners-and-frameworks.md)*
