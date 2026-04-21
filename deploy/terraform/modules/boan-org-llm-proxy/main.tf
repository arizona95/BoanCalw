variable "project_id" {}
variable "region" { default = "asia-northeast3" }
variable "org_id" {}
variable "image" { default = "boanclaw/boan-org-llm-proxy:latest" }
variable "auth_token" {
  description = "Shared bearer token that boan-proxy uses to call this service. Should rotate periodically."
  sensitive   = true
}
variable "allowed_hosts" {
  description = "Comma-separated upstream host allowlist. Only these external LLM providers may receive egress."
  default     = "ollama.com,api.anthropic.com,api.openai.com,generativelanguage.googleapis.com"
}

variable "credential_gate_url" {
  description = "URL of boan-org-credential-gate Cloud Run. If set, the proxy resolves {{CREDENTIAL:*}} placeholders via this gate instead of relying on the caller to pre-substitute."
  default     = ""
}

variable "credential_gate_auth_token" {
  description = "Bearer token for credential-gate calls."
  sensitive   = true
  default     = ""
}

variable "device_pubkeys" {
  description = "Comma-separated base64 Ed25519 public keys of trusted local devices. Empty disables device-JWT gate (bearer-only)."
  default     = ""
}

variable "revoked_devices" {
  description = "Comma-separated device IDs that are blocked even if their pubkey is still in device_pubkeys. Use for emergency revoke without redeploying pubkeys."
  default     = ""
}

variable "rate_limit_rpm" {
  description = "Per-device rate limit in requests per minute."
  default     = "120"
}

variable "ingress" {
  description = "Cloud Run ingress mode: INGRESS_TRAFFIC_ALL | INGRESS_TRAFFIC_INTERNAL_ONLY | INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER_AND_CLOUD_RUN"
  default     = "INGRESS_TRAFFIC_ALL"
}

resource "google_service_account" "org_llm_proxy" {
  account_id   = "boan-org-llm-proxy"
  display_name = "BoanClaw Org LLM Proxy"
  project      = var.project_id
}

resource "google_cloud_run_v2_service" "org_llm_proxy" {
  name     = "boan-org-llm-proxy-${var.org_id}"
  location = var.region
  project  = var.project_id
  ingress  = var.ingress

  template {
    service_account = google_service_account.org_llm_proxy.email
    scaling {
      # min=1 : 항상 warm — G2/G3 가드레일 cold-start 제거.
      # 비용: 1 인스턴스 × 1 vCPU × 730h × $0.000024/s ≈ $8-10/월.
      # prod 에서 cold-start 로 인한 G2 타임아웃 경험 후 기본값을 1 로 올림.
      min_instance_count = 1
      max_instance_count = 5
    }
    containers {
      image = var.image
      ports {
        container_port = 8091
      }
      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
      }
      env {
        name  = "BOAN_LISTEN"
        value = ":8091"
      }
      env {
        name  = "BOAN_ORG_LLM_PROXY_AUTH_TOKEN"
        value = var.auth_token
      }
      env {
        name  = "BOAN_ORG_LLM_PROXY_ALLOWED_HOSTS"
        value = var.allowed_hosts
      }
      env {
        name  = "BOAN_ORG_LLM_PROXY_DENY_HOSTS"
        value = "169.254.169.254,metadata.google.internal,localhost,127.0.0.1"
      }
      env {
        name  = "BOAN_ORG_CREDENTIAL_GATE_URL"
        value = var.credential_gate_url
      }
      env {
        name  = "BOAN_ORG_CREDENTIAL_GATE_AUTH_TOKEN"
        value = var.credential_gate_auth_token
      }
      env {
        name  = "BOAN_DEVICE_PUBKEYS"
        value = var.device_pubkeys
      }
      env {
        name  = "BOAN_REVOKED_DEVICES"
        value = var.revoked_devices
      }
      env {
        name  = "BOAN_ORG_LLM_PROXY_RPM"
        value = var.rate_limit_rpm
      }
    }
  }
}

# The service itself is publicly reachable (Cloud Run ingress), but the bearer
# token gates every POST /v1/forward call. boan-proxy holds the token and
# presents it. For tighter isolation, swap public invoker with per-service-account
# IAM binding in a hardened deployment.
resource "google_cloud_run_service_iam_member" "public_invoker" {
  project  = var.project_id
  location = var.region
  service  = google_cloud_run_v2_service.org_llm_proxy.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

output "org_llm_proxy_url" { value = google_cloud_run_v2_service.org_llm_proxy.uri }
output "service_account_email" { value = google_service_account.org_llm_proxy.email }
