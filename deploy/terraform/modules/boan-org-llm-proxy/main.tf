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
