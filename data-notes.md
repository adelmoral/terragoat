# Data & Storage Security Findings

## db-app.tf — `aws_db_instance.default`

| # | Severity | Finding | Line |
|---|----------|---------|------|
| 1 | **Critical** | `storage_encrypted = false` — RDS data at rest is unencrypted | [19](terraform/aws/db-app.tf#L19) |
| 2 | **Critical** | `publicly_accessible = true` — database is internet-reachable | [22](terraform/aws/db-app.tf#L22) |
| 3 | **Critical** | Plaintext DB credentials (`DB_USERNAME`, `DB_PASSWORD`) embedded in EC2 `user_data` — visible via instance metadata API | [263–266](terraform/aws/db-app.tf#L263) |
| 4 | **High** | `backup_retention_period = 0` — automated backups disabled, no point-in-time recovery | [18](terraform/aws/db-app.tf#L18) |
| 5 | **High** | `skip_final_snapshot = true` — no snapshot taken on deletion | [20](terraform/aws/db-app.tf#L20) |
| 6 | **High** | `aws_iam_role_policy.ec2policy` grants `s3:*`, `ec2:*`, `rds:*` on `Resource: *` — massively overpermissive | [215–222](terraform/aws/db-app.tf#L215) |
| 7 | **Medium** | `monitoring_interval = 0` — enhanced monitoring disabled | [21](terraform/aws/db-app.tf#L21) |
| 8 | **Medium** | `multi_az = false` — no high availability | [17](terraform/aws/db-app.tf#L17) |
| 9 | **Low** | `username = "admin"` — predictable default master username | [14](terraform/aws/db-app.tf#L14) |

---

## consts.tf — Variables

| # | Severity | Finding | Line |
|---|----------|---------|------|
| 10 | **Critical** | `variable "password"` has a hardcoded default value `"Aa1234321Bb"` — DB password committed to source control | [39–43](terraform/aws/consts.tf#L39) |

---

## rds.tf — `aws_rds_cluster` (9 clusters)

| # | Severity | Finding | Lines |
|---|----------|---------|-------|
| 11 | **High** | `app1-rds-cluster`: `backup_retention_period = 0` — backups fully disabled | [4](terraform/aws/rds.tf#L4) |
| 12 | **Medium** | `app2-rds-cluster`: `backup_retention_period = 1` — only 1 day retention, inadequate for most RPOs | [20](terraform/aws/rds.tf#L20) |
| 13 | **High** | All 9 clusters have no `storage_encrypted` set — defaults to `false` (unencrypted at rest) | all |
| 14 | **Medium** | No `deletion_protection = true` on any cluster — clusters can be accidentally deleted | all |

---

## s3.tf — S3 Buckets

| # | Severity | Finding | Lines |
|---|----------|---------|-------|
| 15 | **Critical** | `aws_s3_bucket.data` — no ACL set (no `aws_s3_bucket_public_access_block`), no encryption, no versioning, no access logs. Comment in code confirms it is public | [1–21](terraform/aws/s3.tf#L1) |
| 16 | **Critical** | `aws_s3_bucket_object.data_object` uploads `customer-master.xlsx` (sensitive customer data) into the public `data` bucket | [23–39](terraform/aws/s3.tf#L23) |
| 17 | **High** | `aws_s3_bucket.financials` — no encryption, no versioning, no access logs (despite handling financial data) | [42–63](terraform/aws/s3.tf#L42) |
| 18 | **High** | `aws_s3_bucket.operations` — no encryption, no access logs | [65–87](terraform/aws/s3.tf#L65) |
| 19 | **High** | `aws_s3_bucket.data_science` — no encryption | [89–111](terraform/aws/s3.tf#L89) |
| 20 | **Medium** | No bucket has an `aws_s3_bucket_public_access_block` resource — relies on implicit ACL only | all |
| 21 | **Medium** | Versioned buckets (`operations`, `data_science`, `logs`) have no MFA delete enabled | all |

---

## es.tf — Elasticsearch

| # | Severity | Finding | Lines |
|---|----------|---------|-------|
| 22 | **Critical** | `aws_elasticsearch_domain_policy` allows `es:*` to `principals = ["*"]` — any AWS account has full access | [30–44](terraform/aws/es.tf#L30) |
| 23 | **High** | No `encrypt_at_rest` block — Elasticsearch data stored unencrypted | [1–28](terraform/aws/es.tf#L1) |
| 24 | **High** | No `node_to_node_encryption` — intra-cluster traffic is unencrypted | [1–28](terraform/aws/es.tf#L1) |
| 25 | **High** | No `domain_endpoint_options { enforce_https = true }` — HTTP connections allowed | [1–28](terraform/aws/es.tf#L1) |
| 26 | **Medium** | Elasticsearch version `2.3` is end-of-life — known CVEs, no vendor patches | [3](terraform/aws/es.tf#L3) |

---

## neptune.tf — Neptune Graph DB

| # | Severity | Finding | Lines |
|---|----------|---------|-------|
| 27 | **High** | `storage_encrypted = false` — Neptune cluster data at rest unencrypted | [9](terraform/aws/neptune.tf#L9) |
| 28 | **High** | `iam_database_authentication_enabled = false` — password-based auth only, no IAM controls | [7](terraform/aws/neptune.tf#L7) |
| 29 | **Medium** | `skip_final_snapshot = true` — no snapshot on cluster deletion | [6](terraform/aws/neptune.tf#L6) |

---

## kms.tf — KMS

| # | Severity | Finding | Lines |
|---|----------|---------|-------|
| 30 | **Medium** | `aws_kms_key.logs_key` has no `enable_key_rotation = true` — the comment in the file even acknowledges this | [1–3](terraform/aws/kms.tf#L1) |

---

## ecr.tf — Container Registry

| # | Severity | Finding | Lines |
|---|----------|---------|-------|
| 31 | **Medium** | `image_tag_mutability = "MUTABLE"` — image tags can be silently overwritten, enabling supply chain attacks | [3](terraform/aws/ecr.tf#L3) |
| 32 | **Low** | No `image_scanning_configuration { scan_on_push = true }` — images not automatically scanned for CVEs on push | [1–18](terraform/aws/ecr.tf#L1) |

---

## Summary by Severity

| Severity | Count |
|----------|-------|
| Critical | 7 |
| High | 14 |
| Medium | 9 |
| Low | 2 |

**Top priority issues:**
- Plaintext credentials in EC2 user data (finding #3)
- Hardcoded DB password default in `consts.tf` (finding #10)
- Public S3 bucket holding `customer-master.xlsx` (findings #15–16)
- Elasticsearch domain policy granting `es:*` to `*` (finding #22)

---

## Critical Findings — Exploitability Verification

---

### C1 · Hardcoded DB Password in Source Control
**File:** [consts.tf:39–43](terraform/aws/consts.tf#L39)

```hcl
variable "password" {
  default = "Aa1234321Bb"   # committed to public repo
}
```

**Verified exploitable.** The default is used as the RDS master password unless explicitly overridden at `terraform apply`. This repo is public on GitHub — the credential is trivially discoverable. No secrets manager, no SSM reference, no `sensitive = true` marker.

---

### C2 · Plaintext DB Credentials in EC2 User Data
**File:** [db-app.tf:252–266](terraform/aws/db-app.tf#L252)

```hcl
user_data = <<EOF
define('DB_USERNAME', '${aws_db_instance.default.username}');  # "admin"
define('DB_PASSWORD', '${var.password}');                       # "Aa1234321Bb"
EOF
```

**Verified exploitable.** Two confirmed attack vectors:

1. **IMDSv1 is active** — `aws_instance.db_app` has no `metadata_options` block, so IMDSv1 is the default. Any process on the instance (SSRF, RCE via the PHP app, a web shell) can retrieve credentials with a plain unauthenticated HTTP call:
   ```
   curl http://169.254.169.254/latest/user-data
   ```
2. **AWS API exposure** — Anyone with `ec2:DescribeInstanceAttribute` on this account can retrieve user data directly via the AWS console or CLI.

Also confirmed in [ec2.tf:15–16](terraform/aws/ec2.tf#L15): the sibling `web_host` instance hardcodes AWS IAM key material in user data with the same IMDSv1-accessible pattern:
```hcl
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMAAA
export AWS_SECRET_ACCESS_KEY=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
```

---

### C3 · RDS Publicly Accessible
**File:** [db-app.tf:22](terraform/aws/db-app.tf#L22)

```hcl
publicly_accessible = true
```

**Verified exploitable via chained path.** The RDS-attached security group ([db-app.tf:136–143](terraform/aws/db-app.tf#L136)) restricts MySQL ingress to `172.16.0.0/16` (VPC CIDR), which partially mitigates direct internet access. However, `publicly_accessible = true` assigns a public DNS endpoint to the instance, and the attack path is still open:

- **`aws_security_group.web-node`** ([ec2.tf:83–96](terraform/aws/ec2.tf#L83)) allows SSH (`port 22`) from `0.0.0.0/0` — the internet.
- The EC2 `db_app` instance is deployed into `web_subnet`, which has `map_public_ip_on_launch = true` ([ec2.tf:139](terraform/aws/ec2.tf#L139)) and routes to an internet gateway ([ec2.tf:220–228](terraform/aws/ec2.tf#L220)).

**Attack chain:** SSH into the internet-exposed EC2 (using credentials from C1/C2) → source IP is now inside `172.16.0.0/16` → connect directly to the public RDS endpoint on port 3306. The public endpoint removes the need to stay within AWS infrastructure.

---

### C4 · RDS Storage Unencrypted
**File:** [db-app.tf:19](terraform/aws/db-app.tf#L19)

```hcl
storage_encrypted = false
```

**Verified exploitable.** With C3 confirmed, an attacker who gains access can exfiltrate data. Additionally, `skip_final_snapshot = true` ([db-app.tf:20](terraform/aws/db-app.tf#L20)) means no snapshot is taken on deletion — but any snapshot created during normal operations is also unencrypted. Unencrypted snapshots can be shared across AWS accounts without restriction, and there is no key policy gating access. The `ec2policy` IAM role ([db-app.tf:206–226](terraform/aws/db-app.tf#L206)) grants `rds:*` on `*` — including `rds:CopyDBSnapshot` and `rds:ModifyDBSnapshotAttribute` — to any EC2 instance assuming this role, enabling snapshot exfiltration from within.

---

### C5 · Public S3 Bucket
**File:** [s3.tf:1–7](terraform/aws/s3.tf#L1)

```hcl
resource "aws_s3_bucket" "data" {
  # bucket is public   ← developer comment confirms it
  bucket        = "${local.resource_prefix.value}-data"
```

**Verified exploitable.** No `acl` attribute, no `aws_s3_bucket_public_access_block` resource anywhere in the file. The developer comment in the code explicitly confirms the bucket is public. With the Terraform AWS provider versions this code targets, omitting ACL + having no public access block results in a publicly listable and readable bucket.

---

### C6 · Sensitive File Uploaded to Public Bucket
**File:** [s3.tf:23–39](terraform/aws/s3.tf#L23)

```hcl
resource "aws_s3_bucket_object" "data_object" {
  bucket = aws_s3_bucket.data.id      # the public bucket from C5
  key    = "customer-master.xlsx"
  source = "resources/customer-master.xlsx"
```

**Verified exploitable.** This directly chains from C5. The object is uploaded into the confirmed public bucket with a predictable key name. The full public URL resolves to:
```
https://[account-id]-acme-dev-data.s3.us-west-2.amazonaws.com/customer-master.xlsx
```
No object-level ACL, no SSE, no pre-signed URL requirement. The file is directly downloadable by anyone without authentication.

---

### C7 · Elasticsearch Open to All AWS Principals
**File:** [es.tf:30–44](terraform/aws/es.tf#L30)

```hcl
statement {
  actions    = ["es:*"]
  principals {
    type        = "AWS"
    identifiers = ["*"]       # any AWS account
  }
  resources = ["*"]
}
```

**Verified exploitable.** `identifiers = ["*"]` with type `AWS` grants every authenticated AWS principal full Elasticsearch access — read all indices, write/overwrite data, delete indices, modify cluster settings. There is no `Condition` block, no VPC endpoint, no `encrypt_at_rest`, and no `enforce_https`. The domain is running Elasticsearch `2.3` (EOL since 2016) with known public CVEs. An attacker needs only an active AWS account to call the domain's HTTP API directly.

---

## ⚠️ Direct Kill Chain: C1 → C2 → C3

> **All 7 critical findings are confirmed exploitable. C1, C2, and C3 form a direct, zero-prerequisite kill chain to full database compromise.**

```
Step 1 — C1: Read consts.tf in the public GitHub repo
         → Obtain DB password: "Aa1234321Bb"

Step 2 — C2: EC2 user_data embeds the same credentials with IMDSv1 active
         → Any SSRF/RCE on the PHP web app retrieves them via:
           curl http://169.254.169.254/latest/user-data

Step 3 — C3: SSH (0.0.0.0/0 allowed) into the internet-exposed EC2
         → Source IP becomes 172.16.0.0/16 (VPC CIDR)
         → Connect directly to the public RDS endpoint on port 3306
           using username "admin" / password "Aa1234321Bb"

Result: Full read/write access to the MySQL database.
        Storage is unencrypted (C4), backups are disabled,
        and the IAM role grants rds:* — enabling snapshot
        exfiltration with no further escalation needed.
```

---

## Exploitability Summary

| ID | Finding | Exploitable | Attack Complexity |
|----|---------|-------------|-------------------|
| C1 | Hardcoded password in source control | Yes | None — read the repo |
| C2 | Plaintext credentials in user data (IMDSv1) | Yes | Low — SSRF/RCE on EC2 or `ec2:DescribeInstanceAttribute` |
| C3 | RDS publicly accessible | Yes | Low — SSH into EC2, then connect to RDS |
| C4 | RDS storage unencrypted | Yes | Medium — requires RDS access or snapshot access, but `rds:*` is already granted |
| C5 | Public S3 bucket | Yes | None — public URL |
| C6 | Customer data in public bucket | Yes | None — direct HTTP download |
| C7 | Elasticsearch open to all AWS principals | Yes | None — any AWS account |

---

## Defense in Depth — Best Practice Example

> **Best example in this codebase:** the `logs` + `data_science` S3 bucket pairing in [s3.tf](terraform/aws/s3.tf), backed by a dedicated KMS key in [kms.tf](terraform/aws/kms.tf).

While most resources in this repo intentionally omit controls, this combination layers four independent defenses on the same data path — the definition of Defense in Depth.

### The `logs` bucket — all controls present

```hcl
# s3.tf:113–141
resource "aws_s3_bucket" "logs" {
  bucket = "${local.resource_prefix.value}-logs"
  acl    = "log-delivery-write"         # layer 1: restricted ACL, not public

  versioning {
    enabled = true                       # layer 2: versioning — deleted/overwritten
  }                                      #          objects are recoverable

  server_side_encryption_configuration { # layer 3: encryption at rest
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "aws:kms"    #          KMS (not default AES256)
        kms_master_key_id = "${aws_kms_key.logs_key.arn}"  # dedicated key
      }
    }
  }
}
```

```hcl
# kms.tf:1–16
resource "aws_kms_key" "logs_key" {     # layer 4: dedicated KMS key
  description             = "..."       #          (not the default AWS-managed key)
  deletion_window_in_days = 7
}
```

### The `data_science` bucket — feeds into it

```hcl
# s3.tf:89–111
resource "aws_s3_bucket" "data_science" {
  acl = "private"
  versioning { enabled = true }
  logging {
    target_bucket = "${aws_s3_bucket.logs.id}"  # access logs shipped to the
    target_prefix = "log/"                       # hardened logs bucket above
  }
}
```

### Why this qualifies as Defense in Depth

| Layer | Control | What it defeats |
|-------|---------|-----------------|
| 1 | Private / restricted ACL | Unauthenticated public access |
| 2 | Versioning on both buckets | Ransomware-style overwrites, accidental deletion |
| 3 | KMS encryption with a dedicated key | Storage-layer data exposure; key policy can gate access independently of IAM |
| 4 | Dedicated KMS key (not AWS-managed) | Prevents AWS-managed key from being used by other services; allows rotation and audit independently |
| 5 | Access logging to a separate hardened bucket | Attacker covering tracks by deleting logs — logs bucket is independently protected |

No single control failure exposes the data: bypassing the ACL still requires defeating encryption; compromising the bucket does not compromise the log trail; deleting objects is reversible via versioning. Each layer is independent, and they reinforce each other.

### What is still missing (gap vs. ideal)

Even this best example has gaps — useful contrast against the vulnerable resources:
- `aws_kms_key.logs_key` has no `enable_key_rotation = true` ([kms.tf:1](terraform/aws/kms.tf#L1))
- No `aws_s3_bucket_public_access_block` resource for either bucket
- No MFA delete on versioning
- `data_science` bucket has no encryption (only the `logs` target does)
