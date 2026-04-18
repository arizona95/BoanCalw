# BoanClaw Terraform Infrastructure

GCP infrastructure provisioning for BoanClaw security platform.

## Modules

| Module | Description |
|--------|-------------|
| `modules/kms` | GCP KMS key ring, policy-signing and credential-encryption keys (reserved for future use) |
| `modules/network` | VPC, subnet, firewall rules (proxy-only external egress) |
| `modules/policy-server` | Cloud Run deployment for boan-policy-server + GCS bucket |
| `modules/boan-org-llm-proxy` | Cloud Run deployment for org-level LLM egress broker (single egress point for all external LLM calls; org-per-service) |
| `modules/boan-org-credential-gate` | Cloud Run + Secret Manager credential vault. `boan-org-llm-proxy` calls `/v1/resolve` to turn `{{CREDENTIAL:role}}` placeholders into plaintext right before upstream call. |
| `modules/admin-console` | Firebase Hosting + Cloud Run admin API proxy |
| `modules/logging` | Audit log bucket with 1-year retention + Cloud Logging sink |

## Usage

```bash
cd envs/gcp
cp terraform.tfvars.example terraform.tfvars

# shared bearer tokens — never commit, inject via TF_VAR_*
export TF_VAR_org_llm_proxy_auth_token=$(openssl rand -hex 32)
export TF_VAR_credential_gate_auth_token=$(openssl rand -hex 32)

terraform init
terraform plan
terraform apply
```

Save the generated tokens — the local `docker-compose.dev.yml` (boan-proxy, boan-credential-filter) needs them as `BOAN_ORG_LLM_PROXY_AUTH_TOKEN` and `BOAN_ORG_CREDENTIAL_GATE_AUTH_TOKEN` env vars.

## Required Variables

| Variable | Description |
|----------|-------------|
| `project_id` | GCP project ID |
| `region` | GCP region (default: asia-northeast3) |
| `org_id` | BoanClaw organization identifier |
| `org_llm_proxy_auth_token` | (TF_VAR) Bearer token for `boan-org-llm-proxy`. Rotate periodically. |
| `credential_gate_auth_token` | (TF_VAR) Bearer token for `boan-org-credential-gate`. |

## Outputs

| Output | Description |
|--------|-------------|
| `vpc_id` | VPC network ID |
| `policy_server_url` | Cloud Run URL for policy server |
| `admin_console_url` | Firebase Hosting URL for admin console |
| `audit_bucket` | GCS bucket for audit logs |
| `kms_keyring` | KMS keyring ID |

`module.org_llm_proxy.org_llm_proxy_url` and `module.credential_gate.credential_gate_url` are declared at the module level — read them via `terraform state show`.

## Gotchas

- **Cloud Run `/healthz` 404** — Cloud Run Gen2 frontend intercepts `/healthz`. Use `/v1/health` instead.
- **`terraform apply -replace=...service` drops IAM binding** — after replacing a Cloud Run service, re-apply the `google_cloud_run_service_iam_member` target. IAM propagation ~30s.
- **Service account for credential-gate needs `roles/secretmanager.admin`** on the project (set by the module). Without it, CreateSecret fails with `PERMISSION_DENIED`.
