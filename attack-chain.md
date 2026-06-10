# Attack Chains — MITRE ATT&CK Mapping

## Chain 1 — Full Database Compromise via Public Repository

**Prerequisites:** None. Internet access + an AWS account (free tier suffices).

| Step | MITRE Tactic | Technique | Finding |
|------|-------------|-----------|---------|
| 1 | **Initial Access** | T1078.004 — Valid Accounts: Cloud | Read `consts.tf` in the public GitHub repo; obtain `password = "Aa1234321Bb"` and `username = "admin"` |
| 2 | **Credential Access** | T1552.001 — Credentials in Files | Same commit history also exposes AWS access keys in `ec2.tf:15-16` and `providers.tf:9-11` |
| 3 | **Initial Access** | T1190 — Exploit Public-Facing Application | SSH to EC2 (`web-node` SG, port 22, `0.0.0.0/0`); both `web_host` and `db_app` are in a public subnet with IGW routing and `map_public_ip_on_launch = true` |
| 4 | **Credential Access** | T1552.005 — Cloud Instance Metadata API | From inside the instance, `curl http://169.254.169.254/latest/user-data` (IMDSv1, no auth required) returns the full startup script including `DB_PASSWORD=Aa1234321Bb` and `DB_USERNAME=admin` in plaintext |
| 5 | **Lateral Movement** | T1021.007 — Remote Services: Cloud Services | Source IP is now `172.16.0.0/16` (VPC CIDR); connect directly to the publicly-addressable RDS endpoint on port 3306 using the recovered credentials — the SG ingress rule restricts to VPC CIDR, which the attacker now satisfies |
| 6 | **Collection** | T1005 — Data from Local System | Full read/write on the MySQL database; `storage_encrypted = false` means data is in plaintext |
| 7 | **Exfiltration** | T1537 — Transfer Data to Cloud Account | EC2 role policy (`db-app.tf:215`) grants `rds:*` on `*` — including `rds:CopyDBSnapshot` and `rds:ModifyDBSnapshotAttribute`; attacker copies unencrypted snapshot and shares it to their own AWS account |
| 8 | **Impact** | T1485 — Data Destruction | `backup_retention_period = 0` and `skip_final_snapshot = true`; no automated backups, no final snapshot — database can be dropped with no recovery path |
| 9 | **Defense Evasion** | T1562.008 — Disable Cloud Logs | No CloudTrail configured anywhere; no RDS CloudWatch log exports; all actions from steps 1–8 are unlogged |

**Tactics covered:** Initial Access → Credential Access → Lateral Movement → Collection → Exfiltration → Impact → Defense Evasion (passive — logging never existed)

**Exploitability:** Fully confirmed. Real credentials (`Aa1234321Bb`) with no `.tfvars` override in the repo, a `lifecycle { ignore_changes = ["password"] }` block that locks the hardcoded default in forever, and a public RDS DNS endpoint. Zero-click from the open internet.

---

## Chain 2 — Account-Wide Destruction via Hardcoded Provider Credentials

**Prerequisites:** None. Read access to the public GitHub repository.

| Step | MITRE Tactic | Technique | Finding |
|------|-------------|-----------|---------|
| 1 | **Initial Access** | T1078.004 — Valid Accounts: Cloud | Clone repo; read `providers.tf:9-11` — AWS access key and secret key committed in the provider block in plaintext |
| 2 | **Credential Access** | T1552.001 — Credentials in Files | Same key pair also in `lambda.tf:45-46` (Lambda env vars) and `ec2.tf:15-16` (EC2 user_data); also retrievable from Terraform state file via `aws lambda get-function-configuration` |
| 3 | **Discovery** | T1580 — Cloud Infrastructure Discovery | `aws ec2 describe-instances`, `aws s3 ls`, `aws rds describe-db-instances` — full account enumeration with these keys |
| 4 | **Privilege Escalation** | T1078.004 — Valid Accounts: Cloud | IAM user policy (`iam.tf:29-45`) grants `ec2:*`, `s3:*`, `lambda:*`, `cloudwatch:*` on `Resource: *`; EC2 instance role (`db-app.tf:210-226`) grants `s3:*`, `ec2:*`, `rds:*` on `Resource: *`; long-lived access key created and output in state (`iam.tf:21-23, 52-54`) |
| 5 | **Impact** | T1485 — Data Destruction | `s3:DeleteBucket` on `*` — all S3 buckets wiped; `ec2:TerminateInstances` — all instances terminated; `rds:DeleteDBInstance` on `*` — all databases dropped; most resources have no backup retention or final snapshot |
| 6 | **Impact** | T1531 — Account Access Removal | `ec2:*` + `lambda:*` — modify security groups, delete functions; `cloudwatch:*` — delete alarms and dashboards |
| 7 | **Defense Evasion** | T1562.008 — Disable Cloud Logs | No CloudTrail in any file; `cloudwatch:*` permission allows the attacker to also delete any manually created alarms or log groups; every action in steps 1–6 is completely unaudited |

**Tactics covered:** Initial Access → Credential Access → Discovery → Privilege Escalation → Impact → Defense Evasion

**Exploitability:** The specific key values (`AKIAIOSFODNN7EXAMPLE`) are canonical AWS documentation example keys — not live credentials. However the attack pattern is fully formed: the `.tf` files are committed, the provider block is in source control, there is no `.gitignore` exclusion for `.tf` files, and no secrets management (Secrets Manager, Vault, environment variable injection) is used anywhere. Substituting real keys — which is the entire point of this misconfiguration — yields immediate account-level access with no further steps.

---

## Chain 3 — Unauthenticated Customer Data Exfiltration + Index Destruction

**Prerequisites:** None for S3 (any browser). Active AWS account (free tier) for Elasticsearch.

| Step | MITRE Tactic | Technique | Finding |
|------|-------------|-----------|---------|
| 1a | **Initial Access** | T1190 — Exploit Public-Facing Application | `aws_s3_bucket.data` has no ACL, no `aws_s3_bucket_public_access_block`, and a developer comment in the code that reads `# bucket is public`; with the Terraform AWS provider versions targeted, omitting both results in a publicly listable, publicly readable bucket |
| 1b | **Initial Access** | T1190 — Exploit Public-Facing Application | `aws_elasticsearch_domain.monitoring-framework` has no `vpc_options` block — domain gets a public HTTP endpoint; domain policy sets `Principal: "*"`, `Action: "es:*"`, `Resource: "*"` with no `Condition`; any AWS account holder can call the API directly |
| 2a | **Collection** | T1530 — Data from Cloud Storage | `aws_s3_bucket_object.data_object` uploads `customer-master.xlsx` into the public bucket with a predictable key; direct HTTP GET to `https://[prefix]-data.s3.us-west-2.amazonaws.com/customer-master.xlsx` — no auth, no pre-signed URL, no SSE |
| 2b | **Collection** | T1530 — Data from Cloud Storage | `GET /_search` on the public ES endpoint returns all indexed documents; ES 2.3 (EOL since 2016) has no `encrypt_at_rest`, no `enforce_https`, no `node_to_node_encryption` — data is in plaintext over HTTP |
| 3 | **Exfiltration** | T1537 — Transfer Data to Cloud Account | Both paths deliver data directly to the attacker with zero friction — S3 via public HTTP, ES via unauthenticated REST API |
| 4 | **Impact** | T1485 — Data Destruction | ES domain policy allows `es:DeleteIndex` and `es:*` to any AWS principal — all indices can be permanently deleted; no index snapshots configured; no ES log publishing means deletions are unrecorded |
| 5 | **Defense Evasion** | T1562.008 — Disable Cloud Logs | No CloudTrail; S3 `data` bucket has no access logging; ES has no `log_publishing_options`; VPC flow logs exist but the S3 and ES endpoints are accessed directly over the internet, not through the VPC |

**Tactics covered:** Initial Access → Collection → Exfiltration → Impact → Defense Evasion

**Exploitability:** Fully confirmed on both branches. The S3 branch requires only a browser and knowledge of the bucket name convention (`${local.resource_prefix.value}-data`). The ES branch requires any active AWS account. Neither path requires credentials, exploits, or prior access. The developer comment in `s3.tf` explicitly confirms the bucket is public.

---

## Comparative Summary

| | Chain 1 — DB Compromise | Chain 2 — Account Takeover | Chain 3 — Data Exfiltration |
|---|---|---|---|
| **Prerequisites** | None | None (real keys) / source code read | None |
| **Tactics** | 7 | 6 | 5 |
| **Credentials real?** | Yes (`Aa1234321Bb`) | No (example keys) | N/A — no creds needed |
| **Recovery possible?** | No (backups disabled) | No (CloudTrail absent) | No (no index snapshots, no S3 versioning on data bucket) |
| **Detection possible?** | No | No | No |
| **Business impact** | Database + PII exfiltration + deletion | Account-wide wipe | Customer PII + search data destroyed |

Chain 1 is the most severe: real credentials, confirmed exploitable end-to-end, and reaches the database through a zero-prerequisite path.
