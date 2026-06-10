# Telemetry, Observability & Auditing Findings

## CRITICAL

**No CloudTrail configured (entire inventory)**
Zero `aws_cloudtrail` resources exist across all files. There is no account-level API audit trail — all control plane actions (IAM changes, resource creation/deletion, policy modifications) go unlogged.

---

## HIGH

**RDS Enhanced Monitoring disabled** — `terraform/aws/db-app.tf:21`
`monitoring_interval = 0` disables Enhanced Monitoring for the MySQL RDS instance. No OS-level metrics (CPU, memory, disk I/O) are collected.

**EKS control plane logging not enabled** — `terraform/aws/eks.tf:118`
The `aws_eks_cluster` block has no `enabled_cluster_log_types`. API server, audit, authenticator, controller manager, and scheduler logs are all off by default.

**No ELB access logging** — `terraform/aws/elb.tf:2`
The `aws_elb.weblb` resource has no `access_logs` block. HTTP request/response metadata (client IPs, latencies, request paths) is not captured.

**Lambda X-Ray tracing not configured** — `terraform/aws/lambda.tf:32`
The `aws_lambda_function.analysis_lambda` has no `tracing_config { mode = "Active" }`. Distributed tracing across downstream calls is unavailable.

**Elasticsearch log publishing absent** — `terraform/aws/es.tf:1`
`aws_elasticsearch_domain.monitoring-framework` has no `log_publishing_options`. Search slow logs, index slow logs, and error logs are not forwarded to CloudWatch Logs.

---

## MEDIUM

**No CloudWatch log exports for RDS instance** — `terraform/aws/db-app.tf:1`
The `aws_db_instance.default` has no `enabled_cloudwatch_logs_exports`. MySQL error, general query, slow query, and audit logs are not streamed to CloudWatch.

**No CloudWatch log exports for any RDS cluster** — `terraform/aws/rds.tf`
All 9 `aws_rds_cluster` resources (app1–app9) lack `enabled_cloudwatch_logs_exports`. Additionally, `app1-rds-cluster` has `backup_retention_period = 0`, disabling automated backups entirely.

**Neptune CloudWatch log exports missing** — `terraform/aws/neptune.tf:1`
`aws_neptune_cluster.default` has no `enable_cloudwatch_logs_exports`. Neptune audit and slowquery logs are not captured.

**KMS key rotation disabled** — `terraform/aws/kms.tf:1`
`aws_kms_key.logs_key` does not set `enable_key_rotation = true`. The file's own comment acknowledges this. Without rotation, a compromised key provides indefinite access to encrypted log data.

**ECR image scanning on push not enabled** — `terraform/aws/ecr.tf:1`
`aws_ecr_repository.repository` has no `image_scanning_configuration { scan_on_push = true }` block. Vulnerability findings for pushed container images are not generated automatically.

**EC2 instances lack detailed monitoring** — `terraform/aws/ec2.tf:1`, `terraform/aws/db-app.tf:243`
Neither `aws_instance.web_host` nor `aws_instance.db_app` sets `monitoring = true`. Only basic (5-minute) CloudWatch metrics are collected rather than detailed (1-minute) metrics.

---

## LOW

**S3 access logging missing on 4 buckets** — `terraform/aws/s3.tf`, `terraform/aws/ec2.tf:271`

| Bucket resource | File | Missing |
|---|---|---|
| `aws_s3_bucket.data` | s3.tf:1 | No `logging {}` block |
| `aws_s3_bucket.financials` | s3.tf:42 | No `logging {}` block |
| `aws_s3_bucket.operations` | s3.tf:65 | No `logging {}` block |
| `aws_s3_bucket.flowbucket` | ec2.tf:271 | No `logging {}` block |

The flow logs bucket is particularly notable — it is the destination for VPC flow records but has no access logging of its own.

---

## Positive (in place)

- **VPC Flow Logs** are configured and ship to S3 — `terraform/aws/ec2.tf:250`
- **`aws_s3_bucket.data_science`** has server-side logging enabled targeting the `logs` bucket — `terraform/aws/s3.tf:96`
- **`aws_s3_bucket.logs`** is KMS-encrypted and versioned — `terraform/aws/s3.tf:113`
- **Neptune** has `backup_retention_period = 5` — `terraform/aws/neptune.tf:4`
