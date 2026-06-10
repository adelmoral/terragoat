# Identity, IAM & Secrets Findings — terragoat/terraform/aws

Scanned: 2026-06-09

---

## CRITICAL — Hardcoded Credentials

**1. AWS access keys hardcoded in EC2 user_data**
File: `terraform/aws/ec2.tf:15-16` | Resource: `aws_instance.web_host`
```hcl
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMAAA
export AWS_SECRET_ACCESS_KEY=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
```
Rendered in instance startup script — visible in AWS console and EC2 instance metadata endpoint without authentication.

---

**2. AWS access keys hardcoded in Lambda environment variables**
File: `terraform/aws/lambda.tf:45-46` | Resource: `aws_lambda_function.analysis_lambda`
```hcl
access_key = "AKIAIOSFODNN7EXAMPLE"
secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
```
Retrievable by anyone with `lambda:GetFunctionConfiguration`. Also stored in plaintext in Terraform state.

---

**3. AWS access keys hardcoded in provider block**
File: `terraform/aws/providers.tf:9-11` | Resource: `provider "aws" (plain_text_access_keys_provider)`
```hcl
access_key = "AKIAIOSFODNN7EXAMPLE"
secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
```
Credentials committed to source control in plaintext. Any repo read access equals full credential exposure.

---

**4. Database password hardcoded as variable default**
File: `terraform/aws/consts.tf:39-43` | Resource: `variable "password"`
```hcl
variable "password" {
  default = "Aa1234321Bb"
}
```
Weak password ships to production unless explicitly overridden. Stored in source control and Terraform state.

---

**5. DB password injected into EC2 user_data in plaintext**
File: `terraform/aws/db-app.tf:265` | Resource: `aws_instance.db_app`
```hcl
define('DB_PASSWORD', '${var.password}');
```
Resolved password embedded in EC2 startup script — exposed in AWS console, instance metadata, and Terraform state.

---

## HIGH — Overly Permissive IAM Policies

**6. IAM user policy grants wildcard actions on wildcard resources**
File: `terraform/aws/iam.tf:29-45` | Resource: `aws_iam_user_policy.userpolicy`
```json
"Action": ["ec2:*", "s3:*", "lambda:*", "cloudwatch:*"],
"Resource": "*"
```
Full control over EC2, S3, Lambda, and CloudWatch for the entire account. Violates least privilege.

---

**7. EC2 instance role grants full S3, EC2, and RDS access**
File: `terraform/aws/db-app.tf:210-226` | Resource: `aws_iam_role_policy.ec2policy`
```json
"Action": ["s3:*", "ec2:*", "rds:*"],
"Resource": "*"
```
An EC2 instance with this role can delete all S3 buckets, terminate all EC2 instances, and drop all RDS databases. Instance metadata SSRF would yield these credentials.

---

**8. Elasticsearch domain policy allows any AWS principal (`*`) full access**
File: `terraform/aws/es.tf:30-43` | Resource: `aws_elasticsearch_domain_policy.monitoring-framework-policy`
```hcl
principals {
  type        = "AWS"
  identifiers = ["*"]
}
actions   = ["es:*"]
resources = ["*"]
```
Any authenticated AWS identity can perform any Elasticsearch action. Effectively publicly accessible to all AWS account holders.

---

## HIGH — Long-Lived Credentials

**9. Programmatic access key created for IAM user, exported as Terraform output**
File: `terraform/aws/iam.tf:21-23, 52-54` | Resource: `aws_iam_access_key.user`
```hcl
resource "aws_iam_access_key" "user" { ... }
output "secret" { value = aws_iam_access_key.user.encrypted_secret }
```
Long-term access keys stored in Terraform state. Compounded by the overprivileged user policy (finding #6).

---

## MEDIUM — IAM Authentication Disabled

**10. Neptune cluster not using IAM database authentication**
File: `terraform/aws/neptune.tf:7` | Resource: `aws_neptune_cluster.default`
```hcl
iam_database_authentication_enabled = false
```
Relies on password-based auth instead of short-lived IAM tokens. No token expiry, no CloudTrail-tied identity.

---

**11. EKS API server public endpoint not explicitly disabled**
File: `terraform/aws/eks.tf:122-125` | Resource: `aws_eks_cluster.eks_cluster`
```hcl
vpc_config {
  endpoint_private_access = true
  # endpoint_public_access not set → defaults to true
}
```
Private access enabled but public access not explicitly disabled — Kubernetes API server reachable from the internet.

---

## MEDIUM — Cryptographic Key Management

**12. KMS key has no automatic key rotation**
File: `terraform/aws/kms.tf:1-16` | Resource: `aws_kms_key.logs_key`
`enable_key_rotation = true` is absent. AWS recommends annual rotation to reduce key compromise blast radius.

---

## Summary Table

| # | Severity | File | Resource | Issue |
|---|----------|------|----------|-------|
| 1 | CRITICAL | ec2.tf:15 | `aws_instance.web_host` | AWS keys in user_data |
| 2 | CRITICAL | lambda.tf:45 | `aws_lambda_function` | AWS keys in env vars |
| 3 | CRITICAL | providers.tf:9 | `provider "aws"` | AWS keys in provider block |
| 4 | CRITICAL | consts.tf:42 | `variable "password"` | DB password hardcoded as default |
| 5 | CRITICAL | db-app.tf:265 | `aws_instance.db_app` | DB password in user_data |
| 6 | HIGH | iam.tf:29 | `aws_iam_user_policy` | Wildcard actions/resources |
| 7 | HIGH | db-app.tf:210 | `aws_iam_role_policy.ec2policy` | Wildcard actions/resources on EC2 role |
| 8 | HIGH | es.tf:30 | `aws_elasticsearch_domain_policy` | Public `*` principal |
| 9 | HIGH | iam.tf:21 | `aws_iam_access_key` | Long-lived keys + overprivileged user |
| 10 | MEDIUM | neptune.tf:7 | `aws_neptune_cluster` | IAM auth disabled |
| 11 | MEDIUM | eks.tf:124 | `aws_eks_cluster` | Public API endpoint not disabled |
| 12 | MEDIUM | kms.tf:1 | `aws_kms_key` | Key rotation not enabled |

---

## Exploitability Verification — Critical Findings

Verified: 2026-06-09

### Finding 1 — AWS keys in EC2 user_data ([ec2.tf:15-16](terraform/aws/ec2.tf))

**Credential format check:**
- `AKIAIOSFODNN7EXAMAAA` — valid AKIA prefix (long-term IAM key format), 20 characters
- This is a modified variant of the canonical AWS documentation example key `AKIAIOSFODNN7EXAMPLE`

**Verdict: Exploitable pattern; these specific values are documentation/example keys (not real credentials).**

The attack path is fully formed: user_data is rendered verbatim at deploy time and stored in AWS. Any principal who can run `aws ec2 describe-instance-attribute --attribute userData` or access the instance metadata endpoint at `http://169.254.169.254/latest/user-data` (no auth required from inside the instance) retrieves the credentials in plaintext. If real keys were substituted, exploitation requires zero additional access beyond reaching the instance.

**Git persistence:** Credentials present since commit `d68d289` — across 7 commits to ec2.tf. Removal from HEAD does not scrub them from history; rotation is required regardless.

**Mitigations in place:** None. No `.gitignore` exclusion applies to `.tf` files. No secret management (Secrets Manager, Vault) is used.

---

### Finding 2 — AWS keys in Lambda env vars ([lambda.tf:45-46](terraform/aws/lambda.tf))

**Credential format check:**
- `AKIAIOSFODNN7EXAMPLE` — this IS the canonical AWS documentation example key, used verbatim in official AWS docs. Not a real credential.

**Verdict: Exploitable pattern; specific values are known fake example keys.**

Attack path: `aws lambda get-function-configuration --function-name <name>` returns env vars in plaintext to anyone with that IAM permission. The env vars are also stored unencrypted in the Terraform state file (in the `environment.variables` map). If real keys were present, any IAM principal or state file reader would have them immediately.

**Mitigations in place:** None.

---

### Finding 3 — AWS keys in provider block ([providers.tf:9-11](terraform/aws/providers.tf))

**Credential format check:**
- Same `AKIAIOSFODNN7EXAMPLE` / `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` pair — canonical AWS documentation example values.

**Verdict: Exploitable pattern; specific values are known fake example keys.**

Attack path requires only source code read access. Provider credentials are used by Terraform at `plan`/`apply` time, meaning anyone who can clone the repo and run `terraform apply` would authenticate as this identity. These are also stored in `.terraform/` state cache locally.

**Mitigations in place:** None. `.tfvars` is gitignored but `.tf` files are not.

---

### Finding 4 — DB password hardcoded as variable default ([consts.tf:42](terraform/aws/consts.tf))

**No-override confirmation:**
- Zero `.tfvars` files exist anywhere in the repository — confirmed by `find`.
- The `*.tfvars` glob is in `.gitignore`, meaning any override would never be committed. There is no evidence one exists locally either.

**Lifecycle block makes this permanent at first deploy:**
```hcl
lifecycle {
  ignore_changes = ["password"]   # db-app.tf:40
}
```
This tells Terraform to never reconcile password drift after initial creation. The hardcoded default `Aa1234321Bb` is the password set on first `terraform apply` and it stays unless manually rotated out-of-band.

**Compounding factor — RDS is internet-facing:**
```hcl
publicly_accessible = true   # db-app.tf:22
multi_az            = false
storage_encrypted   = false
```
The instance is directly reachable from the internet with no Multi-AZ failover and unencrypted storage.

**Verdict: FULLY EXPLOITABLE pattern.** Attack path: connect to the public RDS endpoint on port 3306 with username `admin` / password `Aa1234321Bb`. No internal network access required.

**Mitigations in place:** None. Password weak, default, unrotated, and the instance is public.

---

### Finding 5 — DB password in EC2 user_data ([db-app.tf:265](terraform/aws/db-app.tf))

**Variable resolution confirmed:**
- `${var.password}` resolves to `Aa1234321Bb` (the default from finding #4, with no override in place).
- The rendered user_data contains the literal string `define('DB_PASSWORD', 'Aa1234321Bb');` written to `/var/www/inc/dbinfo.inc` on disk.

**Verdict: FULLY EXPLOITABLE pattern.** Two separate extraction paths exist:

1. **From inside the instance (no auth):** `curl http://169.254.169.254/latest/user-data` returns the full startup script including the DB password.
2. **From AWS console/CLI:** `aws ec2 describe-instance-attribute --attribute userData --instance-id <id>` returns base64-encoded user_data; decode it to retrieve the password. Requires `ec2:DescribeInstanceAttribute` permission.

The password is also written to `/var/www/inc/dbinfo.inc` on disk — readable by any process running on the host or any attacker who achieves code execution on the web server.

**Mitigations in place:** None. `sudo chown root:root` on the file limits OS-level read, but the credential is already exposed in user_data before that command runs.

---

### Critical Findings Exploitability Summary

| # | Finding | Credentials Real? | Attack Path Complete? | Mitigations |
|---|---------|------------------|----------------------|-------------|
| 1 | AWS keys in EC2 user_data | No (example keys) | Yes — instance metadata, no auth required | None |
| 2 | AWS keys in Lambda env vars | No (example keys) | Yes — `GetFunctionConfiguration` + state file | None |
| 3 | AWS keys in provider block | No (example keys) | Yes — source code read access only | None |
| 4 | DB password hardcoded default | **Yes — real default used** | **Yes — public RDS port 3306, no override exists** | None |
| 5 | DB password in user_data | **Yes — resolves to real default** | **Yes — instance metadata + on-disk file** | None |

Findings 1–3 use the canonical AWS documentation example keys and are not live credentials. The vulnerability class is real and the attack paths are complete — substituting real keys would result in immediate exploitation. Findings 4 and 5 involve an actual deployable password with no override, against a publicly accessible RDS instance, and are exploitable as-written.

---

## Defense in Depth — Positive Examples

Reviewed: 2026-06-09

Several resources in the configuration demonstrate good identity/IAM/secrets practices worth preserving.

---

### Runners-Up

**Service-scoped trust policies on all execution roles**
Files: [lambda.tf:5-19](terraform/aws/lambda.tf), [db-app.tf:175-189](terraform/aws/db-app.tf)
Every IAM execution role uses a `Principal.Service` trust policy scoped to a single AWS service (`lambda.amazonaws.com`, `ec2.amazonaws.com`). The role cannot be assumed by a human user, another AWS account, or a different service — only the intended compute service can obtain credentials via `sts:AssumeRole`.

**IAM instance profile on db_app EC2 instance**
File: [db-app.tf:156-168](terraform/aws/db-app.tf)
`aws_instance.db_app` uses an IAM instance profile rather than embedding static keys. Credentials delivered via the instance metadata service are short-lived STS tokens rotated automatically — they cannot be permanently copied the way the static keys in `ec2.tf` can.

**Terraform backend state encryption**
File: [providers.tf:14-18](terraform/aws/providers.tf)
```hcl
terraform {
  backend "s3" {
    encrypt = true
  }
}
```
The S3 backend enforces server-side encryption for the state file, which otherwise contains plaintext secrets (RDS passwords, access key IDs, Terraform outputs).

---

### Top Example — EKS IAM Role ([eks.tf:7-42](terraform/aws/eks.tf))

```hcl
data "aws_iam_policy_document" "iam_policy_eks" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["eks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "iam_for_eks" {
  name               = "${local.resource_prefix.value}-iam-for-eks"
  assume_role_policy = data.aws_iam_policy_document.iam_policy_eks.json
}

resource "aws_iam_role_policy_attachment" "policy_attachment-AmazonEKSClusterPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.iam_for_eks.name
}

resource "aws_iam_role_policy_attachment" "policy_attachment-AmazonEKSServicePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSServicePolicy"
  role       = aws_iam_role.iam_for_eks.name
}
```

This is the strongest IAM pattern in the configuration for four cumulative reasons:

1. **Structured trust policy via data source** — Uses `aws_iam_policy_document` instead of a heredoc JSON string. The HCL data source is type-checked by Terraform and prevents malformed JSON or accidental wildcard principals that are easy to introduce in raw strings.

2. **Tightly scoped principal** — Trust is limited to `eks.amazonaws.com` only. No `"AWS": "*"`, no account-level principal, no cross-service assumption. If this role were compromised, the blast radius is limited to what EKS can do with it, not the entire account.

3. **AWS-managed policies via specific ARNs, not inline wildcards** — Permissions are attached as `aws_iam_role_policy_attachment` resources referencing named managed policy ARNs (`AmazonEKSClusterPolicy`, `AmazonEKSServicePolicy`). Compare to `ec2policy` in `db-app.tf` which grants `s3:*`, `ec2:*`, `rds:*` on `Resource: "*"` via inline JSON — the EKS approach provides a clear audit trail of exactly what is permitted.

4. **Explicit `depends_on` for policy attachment ordering** — The `aws_eks_cluster` resource declares `depends_on` on both policy attachments, ensuring the role is fully configured before the cluster assumes it. This prevents a privilege escalation window where a cluster is created before its permissions are in place.

**Why this is defense in depth:** No single layer is perfect, but the combination — structured policy source, narrow trust boundary, vendor-managed permission sets, and ordered provisioning — means an attacker would need to compromise EKS itself to abuse this role, rather than exploiting a misconfigured trust or overly broad permission. This pattern should be the template for the other roles in this configuration.
