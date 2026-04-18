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

resource "google_service_account" "org_llm_proxy" {
  account_id   = "boan-org-llm-proxy"
  display_name = "BoanClaw Org LLM Proxy"
  project      = var.project_id
}

resource "google_cloud_run_v2_service" "org_llm_proxy" {
  name     = "boan-org-llm-proxy-${var.org_id}"
  location = var.region
  project  = var.project_id
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = google_service_account.org_llm_proxy.email
    scaling {
      min_instance_count = 0
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
