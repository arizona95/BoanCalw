# BoanClaw Terraform Infrastructure

GCP infrastructure provisioning for BoanClaw security platform.

## Modules

| Module | Description |
|--------|-------------|
| `modules/kms` | GCP KMS key ring, policy-signing and credential-encryption keys |
| `modules/network` | VPC, subnet, firewall rules (proxy-only external egress) |
| `modules/policy-server` | Cloud Run deployment for boan-policy-server + GCS bucket |
| `modules/admin-console` | Firebase Hosting + Cloud Run admin API proxy |
| `modules/logging` | Audit log bucket with 1-year retention + Cloud Logging sink |

## Usage

```bash
cd envs/gcp
cp terraform.tfvars.example terraform.tfvars

terraform init
terraform plan -var="org_id=my-org"
terraform apply -var="org_id=my-org"
```

## Required Variables

| Variable | Description |
|----------|-------------|
| `project_id` | GCP project ID |
| `region` | GCP region (default: asia-northeast3) |
| `org_id` | BoanClaw organization identifier |

## Outputs

| Output | Description |
|--------|-------------|
| `vpc_id` | VPC network ID |
| `policy_server_url` | Cloud Run URL for policy server |
| `admin_console_url` | Firebase Hosting URL for admin console |
| `audit_bucket` | GCS bucket for audit logs |
| `kms_keyring` | KMS keyring ID |
