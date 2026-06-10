# Terragoat Network / Perimeter Security Findings

Scanned files from the [Terraform Inventory](Submission-Template.md) for ingress/egress vulnerabilities and misconfigurations.

---

## CRITICAL

### [F-01] SSH open to the entire internet
**File:** `terraform/aws/ec2.tf` lines 90–96
**Resource:** `aws_security_group.web-node`
`web-node` allows TCP/22 ingress from `0.0.0.0/0`. Any host on the internet can attempt SSH connections to every EC2 instance in this security group.

### [F-02] Elasticsearch domain policy grants unrestricted public access
**File:** `terraform/aws/es.tf` lines 30–43
**Resource:** `aws_elasticsearch_domain_policy.monitoring-framework-policy`
The domain policy uses `Principal: "*"` with `Action: "es:*"` and `Resource: "*"`. Any unauthenticated caller on the internet can read, write, or delete all Elasticsearch data.

### [F-03] RDS instance publicly accessible
**File:** `terraform/aws/db-app.tf` line 22
**Resource:** `aws_db_instance.default`
`publicly_accessible = true` — the MySQL instance is reachable directly from the public internet via its endpoint.

---

## HIGH

### [F-04] Unrestricted egress (`0.0.0.0/0`) on all security groups
**Files:**
- `terraform/aws/ec2.tf` lines 97–103 — `web-node` SG allows all protocols/ports outbound to anywhere.
- `terraform/aws/db-app.tf` lines 145–152 — RDS SG egress rule also allows all traffic to `0.0.0.0/0`.

Unrestricted egress enables exfiltration, C2 call-home, and lateral movement if an instance is compromised.

### [F-05] EKS API server endpoint public access not disabled
**File:** `terraform/aws/eks.tf` lines 122–125
**Resource:** `aws_eks_cluster.eks_cluster`
`endpoint_private_access = true` is set, but `endpoint_public_access` is not explicitly set to `false`, so it defaults to `true`. The Kubernetes API server is reachable from the public internet.

### [F-06] ELB listener uses HTTP only — no TLS
**File:** `terraform/aws/elb.tf` lines 5–10
**Resource:** `aws_elb.weblb`
Both `lb_protocol = "http"` and `instance_protocol = "http"`. Traffic between clients, the load balancer, and backend instances is unencrypted in transit.

### [F-07] Public subnets auto-assign public IPs to all instances
**Files:**
- `terraform/aws/ec2.tf` line 139 — `web_subnet`: `map_public_ip_on_launch = true`
- `terraform/aws/ec2.tf` line 159 — `web_subnet2`: `map_public_ip_on_launch = true`
- `terraform/aws/eks.tf` line 66 — `eks_subnet1`: `map_public_ip_on_launch = true`
- `terraform/aws/eks.tf` line 94 — `eks_subnet2`: `map_public_ip_on_launch = true`

Every instance or node launched in these subnets gets a public IP by default, exposing them to direct internet-initiated connections.

---

## MEDIUM

### [F-08] Elasticsearch domain not placed inside a VPC
**File:** `terraform/aws/es.tf` lines 1–28
**Resource:** `aws_elasticsearch_domain.monitoring-framework`
No `vpc_options` block is configured. Combined with F-02, the domain is fully internet-exposed with no network-layer perimeter at all.

### [F-09] RDS Aurora clusters have no VPC security groups or subnet groups
**File:** `terraform/aws/rds.tf` lines 1–144
**Resources:** `app1-rds-cluster` through `app9-rds-cluster`
None of the nine `aws_rds_cluster` resources specify `vpc_security_group_ids` or `db_subnet_group_name`. They fall back to the default VPC and default security group, which is typically over-permissive.

### [F-10] Neptune cluster has no VPC security groups configured
**File:** `terraform/aws/neptune.tf` lines 1–19
**Resource:** `aws_neptune_cluster.default`
Omits `vpc_security_group_ids` and `neptune_subnet_group_name`, leaving network access controlled only by default VPC rules.

### [F-11] IAM authentication disabled on Neptune
**File:** `terraform/aws/neptune.tf` line 7
**Resource:** `aws_neptune_cluster.default`
`iam_database_authentication_enabled = false` — graph DB connections are not required to present IAM credentials, weakening the authentication perimeter.

---

## Summary Table

| ID   | File                        | Resource                  | Issue                                      | Severity |
|------|-----------------------------|---------------------------|--------------------------------------------|----------|
| F-01 | `ec2.tf:90`                 | `web-node` SG             | SSH/22 open to `0.0.0.0/0`                | Critical |
| F-02 | `es.tf:30`                  | ES domain policy          | Principal `*` with `es:*`                 | Critical |
| F-03 | `db-app.tf:22`              | RDS instance              | `publicly_accessible = true`              | Critical |
| F-04 | `ec2.tf:97`, `db-app.tf:145`| Multiple SGs              | Unrestricted egress to `0.0.0.0/0`        | High     |
| F-05 | `eks.tf:122`                | EKS cluster               | API server public endpoint not disabled   | High     |
| F-06 | `elb.tf:5`                  | ELB                       | HTTP-only, no TLS                         | High     |
| F-07 | `ec2.tf:139`, `eks.tf:66`   | Subnets                   | `map_public_ip_on_launch = true`          | High     |
| F-08 | `es.tf:1`                   | Elasticsearch domain      | No VPC placement                          | Medium   |
| F-09 | `rds.tf:1`                  | 9× RDS clusters           | No VPC SGs or subnet group                | Medium   |
| F-10 | `neptune.tf:1`              | Neptune cluster           | No VPC SGs or subnet group                | Medium   |
| F-11 | `neptune.tf:7`              | Neptune cluster           | IAM auth disabled                         | Medium   |

---

## Critical Findings — Exploitability Verification

### F-01 — SSH/22 open to `0.0.0.0/0`

Full network path traced:
- `ec2.tf:135-152` — `web_subnet` and `web_subnet2` both have `map_public_ip_on_launch = true` → every launched instance gets a public IP
- `ec2.tf:176-191` — `aws_internet_gateway.web_igw` attached to `web_vpc`
- `ec2.tf:220-228` — route table entry: `0.0.0.0/0 → web_igw` — internet routing is live
- `ec2.tf:90-96` — SG `web-node` allows TCP/22 ingress from `0.0.0.0/0`
- `ec2.tf:6-7` — `web_host` uses `web-node` SG, placed in `web_subnet`
- `db-app.tf:249-251` — `db_app` also uses `web-node` SG, also in `web_subnet`

**Verdict: Fully exploitable.** Complete chain confirmed — Internet → IGW → public subnet → public IP → port 22 unrestricted. Both EC2 instances are directly reachable. The `db_app` instance also has DB credentials interpolated in plaintext `user_data` (`db-app.tf:264-265`), so SSH access directly yields database credentials.

---

### F-02 — Elasticsearch unrestricted public access

Full path traced:
- `es.tf:1-28` — `aws_elasticsearch_domain.monitoring-framework` has no `vpc_options` block → domain gets a public endpoint, not a VPC-internal one
- `es.tf:30-38` — IAM policy document: `Principal = "*"`, `Action = "es:*"`, `Resource = "*"`
- `es.tf:41-44` — This policy is applied directly to the domain

No VPC, no IP-based restriction, no Cognito/SAML auth, no signed request requirement. The `*` principal bypasses all IAM identity checks.

**Verdict: Fully exploitable.** Any internet client can hit the public ES endpoint and perform any operation (read, write, delete indices, snapshot exfiltration) with zero authentication.

---

### F-03 — RDS `publicly_accessible = true`

Full path traced:
- `db-app.tf:22` — `publicly_accessible = true` → AWS assigns a public DNS endpoint and routes internet traffic to the instance
- `db-app.tf:97-99` — DB subnet group uses `web_subnet` and `web_subnet2` — both are public subnets with IGW routing
- `db-app.tf:136-143` — SG ingress for port 3306 restricts source to `aws_vpc.web_vpc.cidr_block` (`172.16.0.0/16`) — blocks direct internet access to MySQL

The SG ingress rule restricts MySQL to the VPC CIDR, blocking direct internet exploitation of port 3306. However:
- The public DNS endpoint is still resolvable and routable from the internet — SG is the only defense
- `db-app.tf:14` — `username = "admin"` hardcoded
- `consts.tf:39-43` — `password` defaults to `"Aa1234321Bb"` in plaintext
- `db-app.tf:264-265` — Both credentials are interpolated into EC2 `user_data` in cleartext — readable after F-01 SSH access

**Verdict: Not directly exploitable from the internet on its own** — SG blocks port 3306 from non-VPC IPs. However it is **one SG rule change away** from full internet exposure, and **fully exploitable via chain**: exploit F-01 (SSH) → read `user_data` or `/var/www/inc/dbinfo.inc` → obtain plaintext credentials → connect to MySQL from inside the VPC.

---

## Exploitability Summary

| ID   | Finding                          | Directly Exploitable | Notes |
|------|----------------------------------|----------------------|-------|
| F-01 | SSH/22 to `0.0.0.0/0`           | **Yes**              | Full internet path confirmed; exposes both EC2 instances including DB credentials |
| F-02 | Elasticsearch open policy        | **Yes**              | No VPC, no auth; any internet client has full ES access |
| F-03 | RDS `publicly_accessible = true` | **Partial**          | SG restricts port 3306 to VPC CIDR; exploitable via F-01 chain, one SG change away from full exposure |

---

## Defense in Depth — Top Finding (Network/Perimeter)

### RDS Network Perimeter — `db-app.tf`

This is the strongest DiD example in the codebase. It is also the reason F-03 landed as "Partial" rather than "Fully Exploitable" — three independent network layers stacked correctly and held even after the outer one failed.

**Layer 1 — VPC boundary**
`ec2.tf:117-133` — The RDS is deployed inside `aws_vpc.web_vpc` (`172.16.0.0/16`), a private address space with its own routing domain. Traffic to/from the database must cross the VPC boundary, which is enforced at the hypervisor level and is not bypassable by application-layer misconfiguration.

**Layer 2 — Dedicated, scoped security group**
`db-app.tf:117-134` — The RDS gets its own SG (`web_vpc-rds-sg`), separate from the web-tier `web-node` SG. A misconfiguration in the web-tier SG does not automatically propagate to the database tier. Blast radius is contained by separation.

**Layer 3 — Ingress scoped to VPC CIDR, not `0.0.0.0/0`**
`db-app.tf:136-143` — The ingress rule for MySQL/3306 is bound to `aws_vpc.web_vpc.cidr_block` (`172.16.0.0/16`). An attacker hitting the public DNS endpoint from the internet sources from a non-RFC-1918 address — the SG drops the connection before it reaches the DB engine.

**Why this matters — the DiD argument:**

`publicly_accessible = true` (`db-app.tf:22`) bypassed Layer 1 by giving the RDS a public DNS endpoint routable from the internet. In a single-layer security model that would be game over. Because Layers 2 and 3 were independently configured and correctly scoped, the attack still failed at the SG — exactly what DiD is designed to do. One broken control did not collapse the whole perimeter.

**The contrast that makes it instructive:**

Compare to F-02 (Elasticsearch): the ES domain also has no VPC (`es.tf:1-28`), but there is no equivalent of Layer 2 or Layer 3 — the IAM policy is `Principal: "*"` with zero compensating controls. One missing layer = full exposure. The RDS shows what having backup layers buys you even when the outer one fails.

**What is still missing — gaps in the DiD stack:**

- No private subnet — RDS sits in a public subnet with IGW routing (`db-app.tf:99`, `ec2.tf:220-228`)
- No Network ACL at the subnet level — NACLs would be a second independent enforcement point for the CIDR restriction
- Credentials in plaintext `user_data` (`db-app.tf:264-265`) — Layers 2 and 3 can be bypassed entirely via the F-01 SSH chain

**Ideal stack for comparison:**

| Layer | What exists | What's missing |
|-------|-------------|----------------|
| Subnet | Public subnet with IGW route | Private subnet, no public IP, no IGW |
| NACL | Default (none configured) | NACL restricting port 3306 to app-tier CIDR |
| Security Group | Ingress scoped to VPC CIDR — **present** | Scope to app-tier SG ID instead of CIDR |
| RDS flag | `publicly_accessible = true` | `publicly_accessible = false` |

Layers 2 and 3 exist and held. Layers 1 and 4 are missing or broken.
