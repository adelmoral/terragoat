# Submission Template

## Table of Contents

- [Executive Summary](#executive-summary)
- [Terraform Inventory](#terraform-inventory)
- [Perimeter Assessment](#perimeter-assessment)
  - [Verified Exploitable Findings](#verified-exploitable-findings)
  - [Controls Hygiene Findings](#controls-hygiene-findings)
  - [Defense in Depth Observations](#defense-in-depth-observations)
- [IAM & Identity Assessment](#iam--identity-assessment)
  - [Verified Exploitable Findings](#verified-exploitable-findings-1)
  - [Controls Hygiene Findings](#controls-hygiene-findings-1)
  - [Defense in Depth Observations](#defense-in-depth-observations-1)
- [Data & Storage Assessment](#data--storage-assessment)
  - [Verified Exploitable Findings](#verified-exploitable-findings-2)
  - [Controls Hygiene Findings](#controls-hygiene-findings-2)
  - [Defense in Depth Observations](#defense-in-depth-observations-2)
- [Telemetry, Observability & Auditing Assessment](#telemetry-observability--auditing-assessment)
  - [Controls Hygiene Findings](#controls-hygiene-findings-3)
- [Top 3 Attack Chains](#top-3-attack-chains)
  - [Chain 1 — Internet → Elasticsearch Full Data Exfiltration](#chain-1)
  - [Chain 2 — Internet SSH Brute Force → EC2 Compromise → Account-Wide Lateral Movement](#chain-2)
  - [Chain 3 — Terraform State Credential Leak → Persistent Near-Admin Account Takeover](#chain-3)

---

## Executive Summary

This submission presents a comprehensive security assessment of the TerraGoat AWS Terraform infrastructure across four domains: network perimeter, IAM and identity, data and storage, and telemetry and observability. The assessment identified three Critical-severity exploitable findings — a wildcard Elasticsearch IAM policy granting `es:*` to any AWS identity worldwide, plaintext AWS credentials hardcoded in EC2 user data and Lambda environment variables, and a publicly exposed S3 bucket storing sensitive customer data without encryption. These findings are compounded by systemic IAM hygiene failures, including a near-administrator inline user policy (`ec2:*`, `s3:*`, `lambda:*`) attached to a long-lived, non-rotating access key, and multiple service roles with overly broad `Resource: "*"` permissions. Six High-severity and over a dozen Controls Hygiene findings round out a posture that reflects a near-complete absence of security controls at every layer of the stack.

The three top-priority attack chains — Elasticsearch data exfiltration, SSH brute-force to account-wide lateral movement, and Terraform state credential leak to persistent takeover — each require two to four steps to execute and share a critical common thread: the total absence of AWS CloudTrail across the entire account makes every chain forensically invisible. Without CloudTrail, no detective control in the architecture — not VPC Flow Logs, not KMS key monitoring, not ELB access logs — can produce actionable evidence, because all depend on CloudTrail as their upstream event source. Defense-in-depth pairs do exist (the RDS security group compensating for `publicly_accessible = true`, the ELB absorbing connection-state attacks, and the KMS CMK adding a second authorization layer over the log bucket), but each is fragile and explicitly bounded by the gaps identified here. Immediate remediation priority should be: (1) enable CloudTrail multi-region with log file validation, (2) rotate or remove all hardcoded credentials (I-01, I-02, T-14), and (3) restrict the Elasticsearch domain policy and add VPC placement to eliminate the globally-exploitable entry point.

---

## Terraform Inventory

- consts.tf
- db-app.tf
- ec2.tf
- ecr.tf
- eks.tf
- elb.tf
- es.tf
- iam.tf
- kms.tf
- lambda.tf
- neptune.tf
- providers.tf
- rds.tf
- s3.tf

## Perimeter Assessment

### Verified Exploitable Findings

| ID | Risk Level | Resource | File / Line | Why It Is Exploitable | Mitigation / Proposed Fix |
|----|------------|----------|-------------|----------------------|---------------------------|
| F-11 | Critical | `aws_elasticsearch_domain_policy.monitoring-framework-policy` | [es.tf:41–44](terraform/aws/es.tf#L41-L44) | IAM policy grants `es:*` to `Principal: AWS: "*"` — any authenticated AWS identity from any account worldwide can read, write, or delete data. The domain has no VPC, so there is no network layer to compensate. | Restrict the principal to specific trusted IAM roles/accounts and add a `condition` block limiting source IPs or VPC. At minimum replace `"*"` with the account-specific ARN. Also add `vpc_options` to place the domain inside a private subnet. |
| F-09 | High | `aws_eks_cluster.eks_cluster` | [eks.tf:122–125](terraform/aws/eks.tf#L122-L125) | `endpoint_public_access` is not set and defaults to `true` with `public_access_cidrs = ["0.0.0.0/0"]`. The Kubernetes API server is reachable from any IP on the internet. A leaked kubeconfig or IAM credential directly enables cluster takeover. | Add `endpoint_public_access = false` to the `vpc_config` block, or if public access is required, restrict it: `public_access_cidrs = ["<trusted-cidr>"]`. |
| F-01 | High | `aws_security_group.web-node` | [ec2.tf:90–96](terraform/aws/ec2.tf#L90-L96) | Security group allows inbound TCP port 22 from `0.0.0.0/0` with no IP restriction. Any host on the internet can attempt SSH — enabling brute-force, credential-spray, or exploitation of SSH vulnerabilities. | Remove the SSH ingress rule entirely if not needed. If required, restrict `cidr_blocks` to a known management CIDR (e.g., a bastion or VPN range). Consider replacing with AWS Systems Manager Session Manager to eliminate inbound SSH entirely. |

---

### Controls Hygiene Findings

| ID | Resource | File / Line | Why It Is Not Currently Exploitable | Mitigation / Proposed Fix |
|----|----------|-------------|-------------------------------------|---------------------------|
| F-02 | `aws_security_group.web-node` | [ec2.tf:83–89](terraform/aws/ec2.tf#L83-L89) | Port 80 open to the internet is intended for a web server. The hygiene gap is cleartext HTTP — exploiting it requires a privileged MitM network position. | Add an HTTPS listener and redirect HTTP to HTTPS. Use ACM for certificate management. |
| F-03 | `aws_security_group.web-node` | [ec2.tf:97–103](terraform/aws/ec2.tf#L97-L103) | Unrestricted egress has no standalone attack vector. It becomes a risk only after a separate instance compromise. | Restrict egress to known destination CIDRs and ports required by the application (e.g., port 443 to specific endpoints). |
| F-04 | `aws_subnet.web_subnet` / `aws_subnet.web_subnet2` | [ec2.tf:139](terraform/aws/ec2.tf#L139), [ec2.tf:159](terraform/aws/ec2.tf#L159) | Auto-assigned public IPs widen the reachable surface but do not open any port or bypass security group rules on their own. | Set `map_public_ip_on_launch = false`. Use a NAT gateway for outbound internet access from private subnets. |
| F-05 | `aws_route.public_internet_gateway` | [ec2.tf:220–228](terraform/aws/ec2.tf#L220-L228) | The IGW route is required for internet connectivity but security group rules are still enforced. The route alone permits no traffic beyond what the SGs allow. | Move application resources to private subnets and route outbound traffic through a NAT gateway instead of an IGW. |
| F-06 | `aws_elb.weblb` | [elb.tf:5–10](terraform/aws/elb.tf#L5-L10) | Traffic interception requires a network position on the path between clients and the load balancer — non-trivial on the public internet. | Replace the HTTP listener with HTTPS (port 443) using an SSL certificate. Add a second listener to redirect port 80 → 443. |
| F-07 | `aws_db_instance.default` | [db-app.tf:22](terraform/aws/db-app.tf#L22) | Despite `publicly_accessible = true`, the RDS security group ingress is restricted to the VPC CIDR (`172.16.0.0/16`). AWS enforces security groups before traffic reaches the instance, blocking all internet-sourced connections. | Set `publicly_accessible = false`. RDS instances should never have a publicly routable endpoint regardless of compensating SG rules. |
| F-08 | `aws_security_group_rule.egress` | [db-app.tf:145–152](terraform/aws/db-app.tf#L145-L152) | Unrestricted outbound is a post-compromise amplifier, not an entry vector. | Restrict egress to the minimum required — e.g., outbound to the application tier only on specific ports. |
| F-10 | `aws_subnet.eks_subnet1` / `aws_subnet.eks_subnet2` | [eks.tf:66](terraform/aws/eks.tf#L66), [eks.tf:93](terraform/aws/eks.tf#L93) | Auto-assigned public IPs amplify F-09 but do not independently constitute an exploit path. | Set `map_public_ip_on_launch = false` on both EKS subnets. Worker nodes should use private subnets with NAT for outbound access. |
| F-12 | `aws_elasticsearch_domain.monitoring-framework` | [es.tf:1–28](terraform/aws/es.tf#L1-L28) | Without F-11, a scoped IAM policy could fully protect a public-endpoint domain. Missing VPC placement is a defense-in-depth gap, not a standalone exploit. | Add a `vpc_options` block specifying a private subnet and a dedicated security group. This eliminates the public endpoint entirely. |
| F-13 | `aws_neptune_cluster.default` | [neptune.tf:1–20](terraform/aws/neptune.tf#L1-L20) | Neptune is always VPC-bound and cannot be made publicly accessible. Without explicit `vpc_security_group_ids`, the default security group applies, which restricts inbound to resources sharing that same group. | Define explicit `vpc_security_group_ids` with a dedicated security group that allows access only from known application tier security groups on the Neptune port (8182). |
| F-14 | `aws_rds_cluster.*` (app1–app9) | [rds.tf:1–144](terraform/aws/rds.tf#L1-L144) | No `db_subnet_group_name` or `vpc_security_group_ids` defined — clusters use AWS defaults which do not enable public internet access. The gap is the absence of explicit controls, not active exposure. | Add `db_subnet_group_name` pointing to private subnets and `vpc_security_group_ids` with a least-privilege security group restricting access to the application tier only. |

---

### Defense in Depth Observations

The following configurations represent cases where two independent control layers are simultaneously active on the same perimeter asset. Each is noted because the presence of a second layer partially compensates for a weakness in the first — though neither pair constitutes a complete mitigation on its own.

**DiD-1 — VPC Security Group as a compensating control for `publicly_accessible = true` on RDS**
`aws_db_instance.default` ([db-app.tf:22](terraform/aws/db-app.tf#L22)) sets `publicly_accessible = true`, which instructs AWS to publish a publicly routable DNS endpoint for the instance. However, `vpc_security_group_ids = [aws_security_group.default.id]` ([db-app.tf:8](terraform/aws/db-app.tf#L8)) constrains inbound connections to the VPC CIDR (`172.16.0.0/16`). AWS enforces security group rules at the hypervisor level before any packet reaches the instance, so the SG acts as a hard boundary that the public endpoint alone cannot override. The result is two independent enforcement points — endpoint routing (AWS control plane) and packet filtering (data plane SG) — protecting the database simultaneously. This pairing is fragile: it survives only as long as the SG rule is correct and the VPC CIDR is not compromised. The recommended remediation (F-07) is to set `publicly_accessible = false` so the defence does not rely on the SG as a sole compensating control.

**DiD-2 — ELB as a protocol-layer boundary in front of `aws_instance.web_host`**
`aws_elb.weblb` ([elb.tf:2–40](terraform/aws/elb.tf#L2-L40)) sits between the internet and `aws_instance.web_host`, terminating TCP connections at the load balancer before forwarding traffic to port 8000 on the backend. The health check (`HTTP:8000/`) gates backend availability, so the instance is not sent traffic unless it is responding correctly. Even though the ELB and the EC2 instance share the same `aws_security_group.web-node`, the ELB absorbs connection-state attacks (SYN floods, HTTP connection exhaustion) at the perimeter before they propagate to the application layer — providing an L4/L7 separation that is absent when a client addresses the instance directly. This separation layer partially compensates for the lack of a WAF and the absence of ELB access logs (T-04), though it does not restrict any traffic beyond what the shared SG already allows.

**DiD-3 — VPC Flow Logs as a detective layer over the web perimeter**
`aws_flow_log.vpcflowlogs` ([ec2.tf:250–268](terraform/aws/ec2.tf#L250-L268)) is configured with `traffic_type = "ALL"` and delivers records to `aws_s3_bucket.flowbucket`. This captures every accepted and rejected flow entering or leaving `aws_vpc.web_vpc` — including the SSH connections permitted by F-01 and all HTTP flows through the ELB. Because Flow Logs operate at the VPC boundary independently of any application or OS control, they remain active even if the EC2 instance is compromised. This detective layer compensates for the absence of CloudTrail (T-01) and host-based IDS by preserving network-level evidence of lateral movement, port scanning, or data exfiltration across the perimeter. The value is limited by the weaknesses in the log destination identified in T-03 (`flowbucket` is unencrypted and `force_destroy = true`), and by the absence of an equivalent Flow Log on `aws_vpc.eks_vpc` (T-02).

---

## IAM & Identity Assessment

### Verified Exploitable Findings

| ID | Risk Level | Resource | File / Line | Why It Is Exploitable | Mitigation / Proposed Fix |
|----|------------|----------|-------------|----------------------|---------------------------|
| I-01 | Critical | `aws_lambda_function.analysis_lambda` | [lambda.tf:44–47](terraform/aws/lambda.tf#L44-L47) | AWS access key (`AKIAIOSFODNN7EXAMPLE`) and secret stored in plaintext Lambda environment variables. Environment variables are visible to anyone with `lambda:GetFunction` or `lambda:GetFunctionConfiguration` — no KMS encryption is applied. Any identity with read access to this Lambda retrieves working credentials. | Remove credentials from environment variables. Use IAM execution role permissions directly. If cross-account access is required, reference secrets via AWS Secrets Manager or SSM Parameter Store with KMS encryption. |
| I-02 | Critical | `aws_instance.web_host` | [ec2.tf:15–17](terraform/aws/ec2.tf#L15-L17) | AWS static credentials (`AKIAIOSFODNN7EXAMAAA`) hardcoded in EC2 `user_data`. EC2 user_data is accessible via the instance metadata service (`169.254.169.254/latest/user-data`) by any process on the instance and is stored in plaintext in the AWS API — visible to anyone with `ec2:DescribeInstanceAttribute`. | Remove all credentials from user_data. Attach an IAM instance profile with scoped permissions instead. |
| I-03 | Critical | `aws_elasticsearch_domain_policy.monitoring-framework-policy` | [es.tf:41–44](terraform/aws/es.tf#L41-L44) | IAM resource policy grants `es:*` to `Principal: AWS: "*"` — any authenticated AWS identity from any account can read, write, or delete index data with no conditions. | Restrict `identifiers` to specific trusted role ARNs. Add an `aws:SourceIp` or `aws:SourceVpc` condition block. |
| I-04 | High | `aws_iam_user_policy.userpolicy` | [iam.tf:25–46](terraform/aws/iam.tf#L25-L46) | Inline user policy grants `ec2:*`, `s3:*`, `lambda:*`, `cloudwatch:*` on `Resource: "*"`. Combined with the static access key (I-05), a leaked key provides near-administrator access across compute, storage, and serverless services. | Replace with a customer-managed policy scoped to specific actions and resource ARNs required by the user's job function. |
| I-05 | High | `aws_iam_access_key.user` | [iam.tf:21–23](terraform/aws/iam.tf#L21-L23) | A programmatic IAM access key is provisioned with no rotation policy, no MFA requirement, and no `pgp_key` for credential encryption at rest in the state file. The `output "secret"` block at line 53 additionally surfaces the encrypted secret as a Terraform output, making it available to anyone with state file access. | Use IAM roles with `sts:AssumeRole` instead of long-lived user keys. If a user key is required, encrypt via a PGP key and never output credentials as Terraform outputs. |
| I-06 | High | `aws_iam_role_policy.ec2policy` | [db-app.tf:206–226](terraform/aws/db-app.tf#L206-L226) | Inline policy on the EC2 instance role grants `s3:*`, `ec2:*`, `rds:*` on `Resource: "*"`. Any process running on `aws_instance.db_app` can read/delete any S3 bucket in the account, reboot or terminate any EC2 instance, and modify any RDS cluster — trivial post-exploit lateral movement. | Scope the policy to the minimum required actions and exact resource ARNs (the specific S3 bucket, the specific RDS instance). |

---

### Controls Hygiene Findings

| ID | Resource | File / Line | Why It Is Not Currently Exploitable | Mitigation / Proposed Fix |
|----|----------|-------------|-------------------------------------|---------------------------|
| I-07 | `aws_instance.db_app` | [db-app.tf:263–266](terraform/aws/db-app.tf#L263-L266) | DB credentials (`DB_USERNAME`, `DB_PASSWORD`) written as plaintext into EC2 `user_data`. The instance is in a private subnet and user_data access requires IAM `ec2:DescribeInstanceAttribute` on the account. Not directly internet-reachable, but any compromised IAM identity in the account can retrieve them. | Write credentials via Secrets Manager at boot using the instance role, rather than baking them into user_data at provisioning time. |
| I-08 | `aws_kms_key.logs_key` | [kms.tf:1–16](terraform/aws/kms.tf#L1-L16) | `enable_key_rotation` is not set (defaults to `false`). Key material never rotates, increasing the blast radius of a key compromise over time. No explicit key policy is defined — the key inherits the default KMS policy, which grants full access to IAM principals with `kms:*` via identity policies. | Add `enable_key_rotation = true`. Define an explicit `policy` document restricting key use to the specific service principals (S3, CloudWatch) rather than relying on the permissive default. |
| I-09 | `aws_ecr_repository.repository` | [ecr.tf:1–18](terraform/aws/ecr.tf#L1-L18) | `image_tag_mutability = "MUTABLE"` and no repository policy defined. Any IAM identity with `ecr:PutImage` can silently overwrite an existing tagged image, enabling supply-chain injection without a tag change. No `image_scanning_configuration` means pushed images are not scanned for CVEs. | Set `image_tag_mutability = "IMMUTABLE"`. Add a repository policy restricting push to specific CI/CD role ARNs. Enable `scan_on_push = true`. |
| I-10 | `aws_iam_role_policy_attachment.policy_attachment-AmazonEKSServicePolicy` | [eks.tf:39–42](terraform/aws/eks.tf#L39-L42) | `AmazonEKSServicePolicy` is deprecated; AWS has merged its permissions into `AmazonEKSClusterPolicy`. The deprecated policy may include broader or stale permissions no longer required by the EKS control plane. Not currently exploitable since the EKS service principal is constrained. | Remove the `AmazonEKSServicePolicy` attachment; it is no longer required for EKS clusters using the current API. |
| I-11 | `aws_s3_bucket.data` | [s3.tf:1–21](terraform/aws/s3.tf#L1-L21) | No `acl`, no `aws_s3_bucket_public_access_block`, and no bucket policy defined. The bucket defaults to account-level public access block settings. If those account-level controls are absent or misconfigured, the bucket becomes publicly readable. All access control relies solely on identity policies with no resource-based enforcement. | Attach an `aws_s3_bucket_public_access_block` resource with all four block settings enabled. Add a bucket policy explicitly denying non-HTTPS access and restricting `s3:GetObject` to known IAM principals or VPC endpoints. |

---

### Defense in Depth Observations

The following configurations represent cases where two independent identity or authorization control layers are simultaneously active on the same resource. Each is noted because the presence of a second layer provides a meaningful constraint that operates independently of the first — though none of the pairs constitutes a complete mitigation on its own.

**DiD-IAM-1 — Service-scoped trust policies as an identity boundary on all three service roles**
All three IAM service roles — `aws_iam_role.iam_for_lambda` ([lambda.tf:5–18](terraform/aws/lambda.tf#L5-L18)), `aws_iam_role.ec2role` ([db-app.tf:175–189](terraform/aws/db-app.tf#L175-L189)), and `aws_iam_role.iam_for_eks` ([eks.tf:7–16](terraform/aws/eks.tf#L7-L16)) — correctly restrict `sts:AssumeRole` to their respective AWS service principals (`lambda.amazonaws.com`, `ec2.amazonaws.com`, `eks.amazonaws.com`). This creates two independent authorization requirements before any access is granted: the caller must be the matching AWS service (enforced by the STS control plane), and the attached permissions must allow the specific action (enforced by IAM). A key compromise from I-01, I-02, or I-05 grants the leaked key's own permissions but cannot be used to assume any of these roles — the trust policy restriction is enforced by a distinct AWS subsystem, completely separate from IAM permission evaluation. The boundary is fragile only if an attacker also gains the ability to invoke the service directly (e.g., invoke the Lambda or launch an EC2 instance with the profile); it does not protect against privilege escalation via `iam:PassRole`.

**DiD-IAM-2 — IAM Instance Profile as an ephemeral credential layer over the EC2 instance**
`aws_iam_instance_profile.ec2profile` ([db-app.tf:155–169](terraform/aws/db-app.tf#L155-L169)) wraps `aws_iam_role.ec2role` and attaches it to `aws_instance.db_app`. This implements the correct IAM role-for-EC2 pattern: STS-issued credentials are delivered via IMDSv1 with a maximum validity of one hour and rotate automatically. Even though I-06 identifies the attached inline policy as overly broad (`s3:*`, `ec2:*`, `rds:*`), the credential mechanism itself is correct — the instance never holds permanent credentials for these permissions. Two credential types coexist on this host: the static `user_data` credentials (I-07, permanent lifetime) and the IMDS-delivered role credentials (one-hour maximum TTL). The instance profile mechanism is the stronger layer and provides the temporal boundary that static credentials lack entirely. The pairing is fragile because the static user_data credentials remain a permanent fallback path that the ephemeral credential TTL does not protect.

**DiD-IAM-3 — KMS Customer-Managed Key as a second authorization checkpoint over the logs bucket**
`aws_kms_key.logs_key` ([kms.tf:1–16](terraform/aws/kms.tf#L1-L16)) provisions a dedicated CMK for the logs bucket. Decrypting any object in that bucket requires satisfying two independent authorization decisions: (1) `s3:GetObject` must be permitted by S3 access controls and identity policies; (2) `kms:Decrypt` must be permitted on this specific CMK, governed by its own key policy. An IAM identity with only `s3:*` permissions cannot read the encrypted objects without a separate, explicit `kms:Decrypt` grant — meaning S3 bucket policy misconfiguration alone is insufficient to expose log data. The CMK also creates an auditable, account-specific access control principal: key usage is attributable to this CMK and can in principle be alarmed on (see T-13). The value is bounded by I-08 (`enable_key_rotation = false` and no explicit key policy restricting usage to specific service principals) and by T-01 (no CloudTrail means KMS API events never reach CloudWatch, making the alarm path in T-13 inert until T-01 is remediated).

---

## Data & Storage Assessment

### Verified Exploitable Findings

| ID | Risk Level | Resource | File / Line | Why It Is Exploitable | Mitigation / Proposed Fix |
|----|------------|----------|-------------|----------------------|---------------------------|
| D-01 | Critical | `aws_s3_bucket.data` / `aws_s3_bucket_object.data_object` | [s3.tf:1–40](terraform/aws/s3.tf#L1-L40) | The bucket has no `acl` attribute and no `aws_s3_bucket_public_access_block` resource anywhere in the file — the in-code comment explicitly states `# bucket is public`. A sensitive file `customer-master.xlsx` is uploaded to this bucket without server-side encryption. Any unauthenticated HTTP client can `GET` the object directly from the public endpoint. Even if account-level public-access blocks are later set, data at rest is unencrypted — a leaked EBS snapshot also reveals the file in plaintext. | Add `aws_s3_bucket_public_access_block` with all four `block_*` flags set to `true`. Add `aws_s3_bucket_server_side_encryption_configuration` using `aws:kms`. Enable versioning. Move sensitive files out of any public bucket. |
| D-02 | High | `aws_elasticsearch_domain.monitoring-framework` | [es.tf:1–28](terraform/aws/es.tf#L1-L28) | No `encrypt_at_rest` block — index data is stored unencrypted on the underlying EBS volumes. No `node_to_node_encryption` block — inter-node replication traffic is plaintext. No `domain_endpoint_options` with `enforce_https = true` — the domain accepts unencrypted HTTP connections. `elasticsearch_version = "2.3"` is end-of-life (2015); multiple disclosed RCE and authentication-bypass CVEs exist for this version series. Combined with the wildcard IAM domain policy (F-11 / I-03), an attacker with any AWS identity can exfiltrate the full unencrypted index data over plaintext HTTP. | Add `encrypt_at_rest { enabled = true }`, `node_to_node_encryption { enabled = true }`, and `domain_endpoint_options { enforce_https = true; tls_security_policy = "Policy-Min-TLS-1-2-2019-07" }`. Upgrade `elasticsearch_version` to a supported release (OpenSearch 2.x or ES 8.x). |

---

### Controls Hygiene Findings

| ID | Resource | File / Line | Why It Is Not Currently Exploitable | Mitigation / Proposed Fix |
|----|----------|-------------|-------------------------------------|---------------------------|
| D-03 | `aws_db_instance.default` | [db-app.tf:17–22](terraform/aws/db-app.tf#L17-L22) | `storage_encrypted = false` requires AWS storage-layer access to exploit. `backup_retention_period = 0` eliminates automated recovery but is not a standalone attack vector. `skip_final_snapshot = true` makes deletion irreversible. `multi_az = false` is a single point of failure. `monitoring_interval = 0` means no Enhanced Monitoring, so anomalous query patterns go undetected. | Set `storage_encrypted = true`. Set `backup_retention_period` ≥ 7. Set `skip_final_snapshot = false` and `deletion_protection = true`. Enable `multi_az = true` for production. Set `monitoring_interval = 60` and add `enabled_cloudwatch_logs_exports`. |
| D-04 | `aws_neptune_cluster.default` | [neptune.tf:1–20](terraform/aws/neptune.tf#L1-L20) | `storage_encrypted = false` requires AWS storage-layer access. `iam_database_authentication_enabled = false` weakens authentication but Neptune is VPC-only and not internet-reachable. `skip_final_snapshot = true` means the cluster can be deleted without a recoverable snapshot. | Set `storage_encrypted = true`. Enable `iam_database_authentication_enabled = true`. Add `deletion_protection = true`. Set `skip_final_snapshot = false`. Define explicit `vpc_security_group_ids` (see also F-13). |
| D-05 | `aws_rds_cluster.*` (app1–app9) | [rds.tf:1–144](terraform/aws/rds.tf#L1-L144) | Nine Aurora clusters define no `storage_encrypted`, no `vpc_security_group_ids`, and no `db_subnet_group_name` — all fall back to AWS defaults which do not enable public internet access. `app1-rds-cluster` has `backup_retention_period = 0` (backups entirely disabled); app2 has a 1-day window, insufficient for most DR requirements. None define `deletion_protection`. Not directly exploitable due to default network isolation, but the absence of explicit controls is a configuration gap. | Add `storage_encrypted = true` to all clusters. Define `vpc_security_group_ids` with a least-privilege security group. Define `db_subnet_group_name` referencing private subnets. Set `backup_retention_period` ≥ 7 for all. Add `deletion_protection = true`. |
| D-06 | `aws_s3_bucket.financials` / `aws_s3_bucket.operations` / `aws_s3_bucket.data_science` | [s3.tf:42–111](terraform/aws/s3.tf#L42-L111) | All three buckets use `acl = "private"` and require authenticated access, so public read is blocked. The gap is encryption at rest: a leaked snapshot or cross-account policy misconfiguration reveals plaintext financial, operational, and ML data. `financials` and `operations` also lack versioning — object overwrites or accidental deletes are unrecoverable. | Add `aws_s3_bucket_server_side_encryption_configuration` with `aws:kms` to all three. Enable versioning on `financials` and `operations`. Add `aws_s3_bucket_public_access_block` with all four settings enabled on each as a defence-in-depth measure. |
| D-07 | All `aws_s3_bucket` resources | [s3.tf:7](terraform/aws/s3.tf#L7), [s3.tf:48](terraform/aws/s3.tf#L48), [s3.tf:73](terraform/aws/s3.tf#L73), [s3.tf:100](terraform/aws/s3.tf#L100), [s3.tf:127](terraform/aws/s3.tf#L127) | `force_destroy = true` on every S3 bucket means `terraform destroy` permanently and silently deletes all objects with no emptying step or confirmation. This is not an external attack vector but a supply-chain or insider threat against the Terraform runner could wipe all five buckets instantly. | Set `force_destroy = false` on all buckets in non-ephemeral environments. Combine with versioning and MFA-delete enabled on buckets holding sensitive or regulated data. |

---

### Defense in Depth Observations

The following configurations represent cases where two or more independent protective control layers are simultaneously active on the same storage resource. Each is noted because the layers address distinct threat vectors and operate independently — a weakness or bypass of one layer does not neutralise the others.

**DiD-D-1 — `aws_s3_bucket.logs`: KMS encryption + versioning + scoped ACL as three concurrent protective layers**
`aws_s3_bucket.logs` ([s3.tf:113–141](terraform/aws/s3.tf#L113-L141)) is the only bucket in the inventory with three independent protective controls active simultaneously. First, `server_side_encryption_configuration` using `aws:kms` with `aws_kms_key.logs_key` means reading any object requires satisfying two authorization decisions independently — `s3:GetObject` and `kms:Decrypt` — as established in DiD-IAM-3. Second, `versioning { enabled = true }` means that a deletion creates a delete marker rather than removing the object; prior versions of every log record remain recoverable by an account administrator. Third, `acl = "log-delivery-write"` restricts write access to the S3 log-delivery service principal, so arbitrary IAM identities cannot inject or tamper with log entries directly. Each layer addresses a distinct threat: encryption protects confidentiality, versioning protects integrity and recoverability, and the ACL restricts write authority. The value is bounded by `force_destroy = true` — a Terraform-level destroy bypasses the versioning layer entirely — and by T-03 (no server access logging on the bucket itself, so tampering via bucket-level API calls would be undetected).

**DiD-D-2 — `aws_s3_bucket.data_science`: private ACL + versioning + access logging as a prevention-recovery-detection stack**
`aws_s3_bucket.data_science` ([s3.tf:89–111](terraform/aws/s3.tf#L89-L111)) is the only non-logs bucket that combines all three control types. `acl = "private"` is a preventive control, blocking public unauthenticated access. `versioning { enabled = true }` is a recovery control, preserving prior object versions after any overwrite or delete — an attacker with `s3:DeleteObject` creates a delete marker but cannot destroy the data permanently without additionally calling `s3:DeleteObjectVersion` on each prior version. The `logging` block targeting `aws_s3_bucket.logs` is a detective control, recording every API operation (GET, PUT, DELETE, HEAD) to the central encrypted log bucket. These three layers are genuinely independent: access logging remains active even if the ACL is widened; versioning remains active even if the logging destination is unavailable. The combination means unauthorized access is recorded, data destruction requires two separate API call types, and public exposure requires an explicit ACL change. The value is bounded by the absence of encryption at rest (D-06) — the logging and versioning layers protect availability, auditability, and recoverability, but not the confidentiality of the stored data itself.

**DiD-D-3 — `aws_s3_bucket.operations`: private ACL + versioning as orthogonal access-control and data-integrity layers**
`aws_s3_bucket.operations` ([s3.tf:65–87](terraform/aws/s3.tf#L65-L87)) combines `acl = "private"` with `versioning { enabled = true }`. While simpler than the `data_science` configuration, these two controls address entirely different threat vectors and operate independently. The ACL protects against unauthorized reads — a preventive boundary enforced at the S3 API layer before any data is returned. Versioning protects against unauthorized or accidental writes and deletes — a data integrity mechanism enforced by the S3 storage layer after a write or delete is accepted. An attacker who bypasses the ACL (e.g., via a misconfigured bucket policy) still faces the versioning layer: every overwrite creates a new version and the prior version is preserved, enabling detection of tampering and recovery by an administrator. Conversely, disabling versioning does not affect the ACL. The pairing is bounded by the absence of access logging (T-11) and encryption at rest (D-06), and by `force_destroy = true`, which allows a Terraform destroy to wipe all versions in a single operation.

---

## Telemetry, Observability & Auditing Assessment

> All findings below are Controls Hygiene — none are independently exploitable from the internet. Their primary impact is compliance failure (SOC 2, PCI-DSS, CIS AWS Foundations, HIPAA) and loss of forensic/operational visibility. Several findings also act as force-multipliers for the exploitable findings above: without an audit trail, confirmed intrusions (I-01, I-02, F-11) leave no evidence.

### Controls Hygiene Findings

| ID | Resource | File / Line | Gap Description | Mitigation / Proposed Fix |
|----|----------|-------------|-----------------|---------------------------|
| T-01 | *(no resource)* | *(none of the 14 files)* | **No AWS CloudTrail defined.** Zero `aws_cloudtrail` resources exist across the entire inventory. Every AWS API call — IAM changes, S3 reads/writes, KMS decrypt operations, EC2 start/stop, RDS modifications — goes unrecorded. Without CloudTrail, there is no audit trail for any of the critical findings (I-01 through I-06, F-11) if they are exploited. This is the single most impactful observability gap: it makes all other detective controls ineffective. Relevant compliance frameworks (CIS AWS Foundations 2.1–2.4, PCI-DSS 10.1, SOC 2 CC7) mandate CloudTrail as a baseline control. | Add `aws_cloudtrail` with `is_multi_region_trail = true`, `include_global_service_events = true`, `enable_log_file_validation = true`, and delivery to `aws_s3_bucket.logs` (the one bucket with SSE-KMS). Add a CloudWatch Logs target and wire metric filters for root account usage, IAM policy changes, and unauthorized API calls. |
| T-02 | `aws_vpc.eks_vpc` | [eks.tf:44–60](terraform/aws/eks.tf#L44-L60) | **EKS VPC has no VPC Flow Logs.** `aws_flow_log.vpcflowlogs` in ec2.tf covers only `aws_vpc.web_vpc`. `aws_vpc.eks_vpc` has no corresponding `aws_flow_log` resource. All TCP/UDP traffic to and from EKS worker nodes and the control plane is invisible — no baseline for anomaly detection, no network forensics after an incident. This is particularly acute given that the EKS API endpoint is publicly accessible (F-09). | Add a second `aws_flow_log` resource targeting `aws_vpc.eks_vpc.id`. Deliver to the same S3 log bucket (`aws_s3_bucket.logs`) or a dedicated CloudWatch log group. Set `traffic_type = "ALL"` to capture both accepted and rejected flows. |
| T-03 | `aws_s3_bucket.flowbucket` | [ec2.tf:271–288](terraform/aws/ec2.tf#L271-L288) | **VPC Flow Log destination bucket is unencrypted, unversioned, and unlogged.** The bucket that holds the sole network audit record has `force_destroy = true`, no `server_side_encryption_configuration`, no versioning, and no `logging` block. Any tampering with the flow log data (deletion, overwrite) is itself undetectable, and the logs are stored in plaintext on AWS-managed storage. | Add `server_side_encryption_configuration` (aws:kms with `aws_kms_key.logs_key`). Add `versioning { enabled = true }`. Add a `logging` block targeting `aws_s3_bucket.logs`. Remove or gate `force_destroy` behind a variable. |
| T-04 | `aws_elb.weblb` | [elb.tf:2–40](terraform/aws/elb.tf#L2-L40) | **Classic ELB has no access logs.** No `access_logs` block is defined. Every HTTP request processed by the load balancer — client IP, request URI, HTTP method, response code, backend processing time — is permanently lost. Without ELB access logs it is impossible to detect volumetric abuse, scraping, or credential-stuffing against the web application. | Add `access_logs { bucket = aws_s3_bucket.logs.id; bucket_prefix = "elb"; enabled = true }` to the `aws_elb` resource. |
| T-05 | `aws_eks_cluster.eks_cluster` | [eks.tf:118–141](terraform/aws/eks.tf#L118-L141) | **EKS control plane logging is entirely disabled.** No `enabled_cluster_log_types` attribute is set (defaults to none). All five control plane log streams — `api`, `audit`, `authenticator`, `controllerManager`, `scheduler` — are off. The `audit` stream in particular records every Kubernetes API call: `kubectl exec`, `kubectl get secrets`, RBAC binding changes, and service account token use. Without it, post-incident investigation of cluster activity is impossible. | Add `enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]` to `aws_eks_cluster.eks_cluster`. Logs are delivered to CloudWatch Logs automatically; ensure the log group is retained for ≥ 90 days. |
| T-06 | `aws_lambda_function.analysis_lambda` | [lambda.tf:32–58](terraform/aws/lambda.tf#L32-L58) | **Lambda has no X-Ray tracing and no dead-letter queue.** `tracing_config` is absent (defaults to `PassThrough`) so no distributed traces are generated. `dead_letter_config` is absent — failed asynchronous invocations are silently discarded with no record in any queue or topic. Combined with T-07 (no CloudWatch Logs policy), the function is a complete observability black box. | Add `tracing_config { mode = "Active" }`. Add `dead_letter_config { target_arn = <aws_sqs_queue or aws_sns_topic arn> }`. Ensure X-Ray sampling rules are configured to avoid unexpected cost. |
| T-07 | `aws_iam_role.iam_for_lambda` | [lambda.tf:1–30](terraform/aws/lambda.tf#L1-L30) | **Lambda execution role has no CloudWatch Logs policy — all runtime logs are silently dropped.** The role defines only an `assume_role_policy` with no policy attachment whatsoever. Without `logs:CreateLogGroup`, `logs:CreateLogStream`, and `logs:PutLogEvents` the Lambda runtime cannot write to CloudWatch Logs; every `console.log`, error stack trace, and execution record is permanently lost. This means that exploitation of I-01 (plaintext credentials in the same function's env vars) would generate no observable log evidence. | Attach `arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole` to the role, or add an inline policy granting the three `logs:*` actions on the function's specific log group ARN pattern (`arn:aws:logs:*:*:log-group:/aws/lambda/<function-name>:*`). |
| T-08 | `aws_db_instance.default` | [db-app.tf:17–22](terraform/aws/db-app.tf#L17-L22) | **RDS instance has Enhanced Monitoring disabled and no CloudWatch log exports.** `monitoring_interval = 0` (noted in D-03) disables OS-level metrics. Additionally, no `enabled_cloudwatch_logs_exports` is configured, so MySQL error, general, audit, and slow-query logs are never forwarded to CloudWatch Logs. There is no record of failed login attempts, long-running queries, or database engine errors. Audit log absence is a PCI-DSS 10.2 and SOC 2 CC7 deficiency. | Set `monitoring_interval = 60` and add a `monitoring_role_arn` pointing to an IAM role with `AmazonRDSEnhancedMonitoringRole`. Set `enabled_cloudwatch_logs_exports = ["audit", "error", "general", "slowquery"]`. |
| T-09 | `aws_rds_cluster.*` (app1–app9) | [rds.tf:1–144](terraform/aws/rds.tf#L1-L144) | **All nine Aurora clusters export no logs to CloudWatch.** None of the cluster resources define `enabled_cloudwatch_logs_exports`. Database-level errors, authentication failures, and slow queries across all nine clusters are invisible. No performance baseline exists from which to detect anomalous load or credential-stuffing against the database layer. | Add `enabled_cloudwatch_logs_exports = ["audit", "error", "general", "slowquery"]` to all nine `aws_rds_cluster` resources. For Aurora MySQL, these map to specific log files; confirm the engine family supports each export type. |
| T-10 | `aws_neptune_cluster.default` | [neptune.tf:1–20](terraform/aws/neptune.tf#L1-L20) | **Neptune cluster exports no audit logs.** No `enable_cloudwatch_logs_exports` attribute is set. Neptune supports exporting `audit` logs (all queries executed against the graph database) to CloudWatch Logs. Without these, graph traversals, data reads, and authentication events from the Neptune endpoint are unrecorded. | Add `enable_cloudwatch_logs_exports = ["audit"]`. Create a corresponding CloudWatch log group with a retention policy ≥ 90 days and ensure the Neptune service role has `logs:CreateLogGroup`, `logs:CreateLogStream`, and `logs:PutLogEvents`. |
| T-11 | `aws_s3_bucket.data`, `.financials`, `.operations`, `.flowbucket` | [s3.tf:1–21](terraform/aws/s3.tf#L1-L21), [s3.tf:42–63](terraform/aws/s3.tf#L42-L63), [s3.tf:65–87](terraform/aws/s3.tf#L65-L87), [ec2.tf:271–288](terraform/aws/ec2.tf#L271-L288) | **Four of five data buckets and the flow-log bucket have no S3 server access logging.** Only `aws_s3_bucket.data_science` has a `logging` block. The `data` bucket (public, containing `customer-master.xlsx`) generates no record of who accessed or downloaded sensitive files. The `flowbucket` audit bucket is itself unlogged — any deletion or modification of network audit records is undetectable. PCI-DSS 10.2.1 requires logging of access to sensitive data. | Add a `logging { target_bucket = aws_s3_bucket.logs.id; target_prefix = "log/<bucket-name>/" }` block to each unlogged bucket. For the `flowbucket`, log to the central `logs` bucket rather than itself to avoid circular dependency. |
| T-12 | `aws_elasticsearch_domain.monitoring-framework` | [es.tf:1–28](terraform/aws/es.tf#L1-L28) | **The domain named "monitoring-framework" publishes no logs.** No `log_publishing_options` blocks are defined. Elasticsearch supports four log types: `INDEX_SLOW_LOGS`, `SEARCH_SLOW_LOGS`, `ES_APPLICATION_LOGS`, and `AUDIT_LOGS`. Without these, there is no record of index access patterns, authentication events, or application errors from the service that is presumably used for centralised observability. This is a self-referential gap: the monitoring system is itself unmonitored. | Add `log_publishing_options` blocks for at minimum `ES_APPLICATION_LOGS` and `AUDIT_LOGS`, pointing to a dedicated CloudWatch log group with a resource policy granting `es.amazonaws.com` the `logs:PutLogEvents` and `logs:CreateLogStream` permissions. Note: `AUDIT_LOGS` requires Fine-Grained Access Control (Advanced Security Options) to be enabled first. |
| T-13 | `aws_kms_key.logs_key` | [kms.tf:1–16](terraform/aws/kms.tf#L1-L16) | **KMS key has no usage monitoring or alerting.** No explicit key policy is defined (inherits the permissive default, noted in I-08), and no CloudWatch alarm is wired to KMS API events. An unexpected spike in `kms:Decrypt` calls — a common signal of data exfiltration using a stolen key — would go undetected. This gap is compounded by T-01 (no CloudTrail): without CloudTrail, KMS usage events never reach CloudWatch in the first place, making even a correctly configured alarm inert. | First address T-01 to ensure KMS events appear in CloudTrail. Then create a CloudWatch metric filter on the CloudTrail log group for `eventSource = kms.amazonaws.com` and add alarms on `kms:Decrypt` call volume. Define an explicit key policy restricting `kms:Decrypt` and `kms:GenerateDataKey` to the specific service principals (S3, CloudWatch Logs) that legitimately use the key. |
| T-14 | `provider "aws" { alias = "plain_text_access_keys_provider" }` | [providers.tf:7–12](terraform/aws/providers.tf#L7-L12) | **Hardcoded provider credentials cannot be attributed in audit logs.** The static access key / secret defined in the provider alias acts as a shared, non-expiring identity. Any CloudTrail events (once T-01 is remediated) generated via this provider will show the same IAM user regardless of which human operator ran `terraform apply`, making it impossible to attribute API calls to an individual, satisfy separation-of-duties requirements, or detect key misuse by a specific actor. Additionally, a default `password` value (`Aa1234321Bb`) is hardcoded in `consts.tf:41` and used for the RDS instance — visible in state files and Terraform plan output. | Remove static credentials from the provider block entirely; use IAM roles via `aws_assume_role` or environment-variable injection in CI/CD. Move the database password to AWS Secrets Manager and reference it with a `data "aws_secretsmanager_secret_version"` lookup, removing the variable default. |

---

## Top 3 Attack Chains

The following chains demonstrate how individual misconfigurations compose into end-to-end exploits. Each step is supported by a verified finding from the assessments above. MITRE ATT&CK technique IDs are provided at each stage.

| # | Chain | Entry Point | Blast Radius | Detection Likelihood |
|---|-------|-------------|--------------|----------------------|
| 1 | [Internet → Elasticsearch Full Data Exfiltration](#chain-1) | Any AWS account — no internet exposure required | Full ES index data read/write/delete | **None** — T-01 + T-12 |
| 2 | [SSH Brute Force → EC2 Compromise → Account-Wide Lateral Movement](#chain-2) | Public internet, TCP/22 | Entire AWS account across compute, storage, serverless | **None** — T-01 + T-03 + T-04 |
| 3 | [Terraform State Credential Leak → Persistent Near-Admin Takeover](#chain-3) | Terraform state file access | Entire AWS account + container supply chain | **None** — T-01 + T-07 + T-14 |

> **Common thread:** The absence of CloudTrail (T-01) renders all three chains forensically invisible. Every other detective control in the architecture depends on CloudTrail as its upstream event source.

---

<a id="chain-1"></a>
### Chain 1 — Internet → Elasticsearch Full Data Exfiltration

**Overall Severity: Critical | Steps to exploit: 2 | Findings: I-03, F-11, D-02, T-12, T-01**

#### Attack Flow

```
[Any authenticated AWS identity worldwide]
  ATT&CK: T1078.004 — Valid Accounts: Cloud Accounts
        │
        │  es:* granted to Principal: AWS: "*"  (I-03 / F-11)
        ▼
[aws_elasticsearch_domain.monitoring-framework]
  ATT&CK: T1526 — Cloud Service Discovery
        │
        │  No enforce_https → plaintext HTTP accepted  (D-02)
        │  No encryption at rest / node-to-node         (D-02)
        │  Elasticsearch 2.3 EOL — known RCEs active    (D-02)
        ▼
[Full index read / write / delete over cleartext HTTP]
  ATT&CK: T1213 — Data from Information Repositories
  ATT&CK: T1565.001 — Stored Data Manipulation
  ATT&CK: T1537 — Transfer Data to Cloud Account
        │
        │  No log_publishing_options on domain  (T-12)
        │  No CloudTrail                         (T-01)
        ▼
[Silent, unattributable exfiltration — zero forensic evidence]
  ATT&CK: T1562.008 — Impair Defenses: Disable Cloud Logs
```

#### Findings Detail

| Finding | File / Line | MITRE ATT&CK | Role in Chain |
|---------|-------------|--------------|---------------|
| I-03 / F-11 Critical | [es.tf:41–44](terraform/aws/es.tf#L41-L44) | T1078.004 Valid Accounts: Cloud Accounts | Wildcard `Principal: AWS: "*"` on `es:*` — any AWS identity worldwide is a valid credential; no brute force or phishing required |
| D-02 High | [es.tf:1–28](terraform/aws/es.tf#L1-L28) | T1040 Network Sniffing; T1190 Exploit Public-Facing Application | No HTTPS enforcement means traffic is sniffable in transit; Elasticsearch 2.3 is EOL with disclosed RCEs providing an additional code-execution path |
| T-12 Controls Hygiene | [es.tf:1–28](terraform/aws/es.tf#L1-L28) | T1562.008 Impair Defenses: Disable Cloud Logs | Zero `log_publishing_options` — no INDEX, SEARCH, APPLICATION, or AUDIT logs; the domain named "monitoring-framework" is itself unmonitored |
| T-01 Controls Hygiene | *(no resource)* | T1562.008 Impair Defenses: Disable Cloud Logs | No CloudTrail — no API call record, no attribution, no forensics at any layer |

#### Why This Is the Highest-Priority Chain

The IAM principal barrier is global — any AWS free-tier account satisfies `Principal: "*"`. There is no network compensating control (no VPC placement, no `aws:SourceIp` condition). Data is plaintext on disk and in transit. The domain aggregates telemetry from other services, meaning compromise likely extends beyond its own index data. No log of the attack is ever written anywhere in the account.

---

<a id="chain-2"></a>
### Chain 2 — Internet SSH Brute Force → EC2 Compromise → Account-Wide Lateral Movement

**Overall Severity: Critical | Steps to exploit: 4 | Findings: F-01, I-02, I-05, I-04, I-01, D-01, F-03, I-07, T-01, T-03, T-04**

#### Attack Flow

```
[Internet attacker]
  ATT&CK: T1110.001 — Brute Force: Password Guessing
        │
        │  TCP/22 open to 0.0.0.0/0  (F-01)
        ▼
[Shell on aws_instance.web_host]
  ATT&CK: T1021.004 — Remote Services: SSH
        │
        │  AWS key AKIAIOSFODNN7EXAMAAA in plaintext user_data  (I-02)
        │  Readable via IMDS (169.254.169.254/latest/user-data)
        │  or via ec2:DescribeInstanceAttribute from any IAM identity
        ▼
[Static IAM credentials exfiltrated — permanent, non-rotating  (I-05)]
  ATT&CK: T1552.001 — Unsecured Credentials: Credentials in Files
  ATT&CK: T1552.005 — Unsecured Credentials: Cloud Instance Metadata API
        │
        │  ec2:*, s3:*, lambda:*, cloudwatch:* on Resource: "*"  (I-04)
        ▼
[Account-wide lateral movement]
  ATT&CK: T1078.004 — Valid Accounts: Cloud Accounts
  ATT&CK: T1580 — Cloud Infrastructure Discovery
   │
   ├─► s3:GetObject → aws_s3_bucket.data → customer-master.xlsx (D-01)
   │     ATT&CK: T1530 — Data from Cloud Storage Object
   │
   ├─► lambda:GetFunction → analysis_lambda → second key AKIAIOSFODNN7EXAMPLE (I-01)
   │     ATT&CK: T1552.001 — Unsecured Credentials: Credentials in Files
   │
   ├─► ec2:DescribeInstanceAttribute → db_app user_data → DB_USERNAME / DB_PASSWORD (I-07)
   │     ATT&CK: T1552.005 — Cloud Instance Metadata API
   │
   └─► Unrestricted egress for exfiltration (F-03)
         ATT&CK: T1048 — Exfiltration Over Alternative Protocol
        │
        │  No CloudTrail (T-01)
        │  flow log bucket unencrypted + force_destroy=true (T-03)
        │  No ELB access logs (T-04)
        ▼
[Persistent, undetected account compromise — two live long-lived keys]
  ATT&CK: T1562.008 — Impair Defenses: Disable Cloud Logs
```

#### Findings Detail

| Finding | File / Line | MITRE ATT&CK | Role in Chain |
|---------|-------------|--------------|---------------|
| F-01 High | [ec2.tf:90–96](terraform/aws/ec2.tf#L90-L96) | T1110.001 Brute Force: Password Guessing; T1021.004 Remote Services: SSH | Initial access — SSH exposed to the entire internet with no IP restriction |
| I-02 Critical | [ec2.tf:15–17](terraform/aws/ec2.tf#L15-L17) | T1552.001 Credentials in Files; T1552.005 Cloud Instance Metadata API | Plaintext AWS key in `user_data`, readable post-shell via IMDS or remotely via `ec2:DescribeInstanceAttribute` |
| I-05 High | [iam.tf:21–23](terraform/aws/iam.tf#L21-L23) | T1078.004 Valid Accounts: Cloud Accounts | Long-lived key with no rotation and no MFA — permanent credential after a single exfiltration event |
| I-04 High | [iam.tf:25–46](terraform/aws/iam.tf#L25-L46) | T1580 Cloud Infrastructure Discovery | Near-admin scope (`ec2:*`, `s3:*`, `lambda:*`, `cloudwatch:*` on `*`) turns a single key into account-wide access |
| I-01 Critical | [lambda.tf:44–47](terraform/aws/lambda.tf#L44-L47) | T1552.001 Credentials in Files | `lambda:GetFunction` (within I-04 scope) yields a second live credential set — attacker exits with two independent permanent keys |
| D-01 Critical | [s3.tf:1–40](terraform/aws/s3.tf#L1-L40) | T1530 Data from Cloud Storage Object | Public bucket with `customer-master.xlsx` unencrypted — unauthenticated HTTP GET suffices; no additional privilege needed |
| F-03 / I-07 | [ec2.tf:97–103](terraform/aws/ec2.tf#L97-L103), [db-app.tf:263–266](terraform/aws/db-app.tf#L263-L266) | T1048 Exfiltration Over Alternative Protocol | Unrestricted egress provides the exfiltration channel; plaintext DB credentials in a second instance's `user_data` extend reach to the database tier |
| T-01 / T-03 / T-04 | multiple | T1562.008 Impair Defenses: Disable Cloud Logs | No CloudTrail, unprotected flow log bucket, no ELB logs — no audit trail at any layer of the stack |

#### Why This Is the #2 Chain

A single open SSH port cascades into account-wide access via two hardcoded credential sets and a near-admin IAM policy. The static key recovered from I-02 is permanent: even after the EC2 instance is terminated, the credential remains valid and usable. The attacker exits the chain holding two independent long-lived keys (I-02 + I-01) with no audit record of either recovery.

---

<a id="chain-3"></a>
### Chain 3 — Terraform State Credential Leak → Persistent Near-Admin Account Takeover

**Overall Severity: Critical | Steps to exploit: 2 | Findings: I-05, T-14, I-04, I-01, I-09, T-07, T-01**

#### Attack Flow

```
[Attacker with access to Terraform state file]
  (CI/CD pipeline, misconfigured state bucket, insider, leaked output)
  ATT&CK: T1552.001 — Unsecured Credentials: Credentials in Files
        │
        │  aws_iam_access_key.user secret in Terraform output  (I-05)
        │  provider alias plaintext key in providers.tf         (T-14)
        │  No PGP encryption on state — secrets in cleartext
        ▼
[Long-lived IAM access key — no rotation, no MFA  (I-05)]
  ATT&CK: T1078.004 — Valid Accounts: Cloud Accounts
        │
        │  ec2:*, s3:*, lambda:*, cloudwatch:* on Resource: "*"  (I-04)
        ▼
[Near-admin access to all compute, storage, and serverless resources]
  ATT&CK: T1580 — Cloud Infrastructure Discovery
        │
        ├─► lambda:GetFunction → AKIAIOSFODNN7EXAMPLE extracted  (I-01)
        │     ATT&CK: T1552.001 — Unsecured Credentials: Credentials in Files
        │     → Attacker now holds two permanent, independent keys
        │
        ├─► ec2:DescribeInstanceAttribute → user_data keys + DB creds  (I-02, I-07)
        │     ATT&CK: T1552.005 — Cloud Instance Metadata API
        │
        ├─► s3:GetObject → customer-master.xlsx  (D-01)
        │     ATT&CK: T1530 — Data from Cloud Storage Object
        │
        └─► ecr:PutImage → silent overwrite of mutable image tag  (I-09)
              ATT&CK: T1195.002 — Supply Chain Compromise: Compromise Software Supply Chain
        │
        │  No CloudTrail (T-01) — zero API call attribution
        │  Provider credentials non-attributable even once T-01 is fixed  (T-14)
        │  Lambda has no CloudWatch Logs → lambda:GetFunction call unrecorded  (T-07)
        ▼
[Durable, unattributable compromise — key never expires, supply chain injected]
  ATT&CK: T1562.008 — Impair Defenses: Disable Cloud Logs
  ATT&CK: T1078.004 — Valid Accounts: Cloud Accounts (persistence)
```

#### Findings Detail

| Finding | File / Line | MITRE ATT&CK | Role in Chain |
|---------|-------------|--------------|---------------|
| I-05 High | [iam.tf:21–23](terraform/aws/iam.tf#L21-L23) | T1552.001 Unsecured Credentials: Credentials in Files | Terraform `output "secret"` surfaces key in state without PGP encryption — reading the state file once yields a permanent, working credential |
| T-14 Controls Hygiene | [providers.tf:7–12](terraform/aws/providers.tf#L7-L12) | T1552.001 Unsecured Credentials: Credentials in Files | Hardcoded provider credentials in source-controlled file — shared, non-expiring, non-attributable identity |
| I-04 High | [iam.tf:25–46](terraform/aws/iam.tf#L25-L46) | T1078.004 Valid Accounts: Cloud Accounts; T1580 Cloud Infrastructure Discovery | The scope of the leaked key: near-admin access across EC2, S3, Lambda, CloudWatch |
| I-01 Critical | [lambda.tf:44–47](terraform/aws/lambda.tf#L44-L47) | T1552.001 Unsecured Credentials: Credentials in Files | `lambda:GetFunction` (within I-04 scope) yields a second independent key set — attacker achieves credential redundancy without touching any running workload |
| I-09 Controls Hygiene | [ecr.tf:1–18](terraform/aws/ecr.tf#L1-L18) | T1195.002 Supply Chain Compromise: Compromise Software Supply Chain | Mutable image tags allow silent overwrite of a tagged container image via `ecr:PutImage`; any workload pulling that tag is compromised on next deploy |
| T-07 Controls Hygiene | [lambda.tf:1–30](terraform/aws/lambda.tf#L1-L30) | T1562.008 Impair Defenses: Disable Cloud Logs | Lambda execution role has no CloudWatch Logs policy — `lambda:GetFunction` call and credential extraction leave no log evidence |
| T-01 Controls Hygiene | *(no resource)* | T1562.008 Impair Defenses: Disable Cloud Logs | No CloudTrail — all AWS API calls (including state bucket reads and ECR pushes) are entirely unrecorded |

#### Why This Is the #3 Chain

This chain requires no direct exploitation of an internet-facing service. The entry point is the Terraform state file — commonly stored in an S3 bucket that may itself be publicly accessible (consistent with the D-01 pattern in this repository) or reachable by CI/CD pipelines. All activity consists of legitimate AWS API calls using a valid credential. Because the key never rotates (I-05), the provider credentials are non-attributable (T-14), and Lambda activity is unlogged (T-07), the compromise can persist indefinitely without generating any observable signal even after CloudTrail is enabled — T-14 credentials will still produce non-attributable events.
