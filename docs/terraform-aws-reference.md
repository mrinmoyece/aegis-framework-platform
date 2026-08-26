# AWS Terraform reference

`deployment/terraform/aws` is a no-secret, no-apply reference validated with Terraform
`1.13.3`, AWS provider `6.10.0`, and a credential-free mocked plan. No external module
is used, avoiding unpinned module code. `.terraform.lock.hcl` pins provider hashes.

## Included

- three-AZ VPC with public ingress/NAT subnets, private EKS subnets, isolated data
  subnets, S3 gateway endpoint, and interface endpoints for ECR, KMS, logs, Secrets
  Manager, STS, and Temporal Cloud PrivateLink with a private hosted-zone CNAME that
  preserves the verified Temporal TLS server name;
- private-endpoint EKS `1.32`, KMS secrets, all control-plane logs, API access mode,
  exact-pinned CoreDNS/kube-proxy/VPC CNI/Pod Identity add-ons, three-node minimum
  system pool, and dedicated three-node minimum sandbox pool using a required
  organization-qualified AL2023/Kata AMI with node label/taint;
- Multi-AZ RDS PostgreSQL `17.6`, gp3 autoscaling, forced TLS, managed master secret,
  KMS, 35-day automated backups, deletion protection, no automatic minor/major upgrade,
  and `prevent_destroy`;
- immutable KMS-encrypted ECR, versioned/KMS S3 ledger/evidence/trust buckets,
  object-lock ledger archive, Secrets Manager references, AWS Backup vault lock/plan,
  ACM/Route53, encrypted CloudWatch logs, and AMP;
- partial S3 backend configuration using native `use_lockfile`; the state bucket/KMS
  key are precreated in a separate bootstrap account/stack.

## Deliberate boundaries

The VPC reference includes one NAT gateway per AZ for availability, which is costly.
Private endpoints reduce but do not remove NAT use. The reference does not estimate
price or establish capacity. Instance classes and storage are starting assumptions
that must be replaced by measured queue, connection, IOPS, storage-growth, and
retention data.

Temporal Cloud account/namespace, PrivateLink service acceptance, API key/mTLS,
retention, regions, DPA, export, support, and failover are managed outside Terraform
because no Temporal provider is selected. Kubernetes policy accepts only a private
endpoint boundary; direct public Temporal egress is not opened.

The reference creates one region. A standby is a separate state/backend and separate
apply, never a second writer in the same state. Database replication, backup copy,
DNS/routing, key policy, and failover approvals must be qualified independently.

Run:

```bash
terraform -chdir=deployment/terraform/aws fmt -check -recursive
terraform -chdir=deployment/terraform/aws init -backend=false -input=false
terraform -chdir=deployment/terraform/aws validate
terraform -chdir=deployment/terraform/aws test
```

Do not run `apply` from CI or this repository. An organization-owned account vending,
policy-as-code, drift, change, break-glass, cost, and evidence system must wrap a real
apply.
