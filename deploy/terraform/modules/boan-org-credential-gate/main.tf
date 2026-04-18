variable "project_id" {}
variable "region" { default = "asia-northeast3" }
variable "org_id" {}
variable "image" { default = "boanclaw/boan-org-credential-gate:latest" }
variable "auth_token" {
  description = "Bearer token accepted by credential-gate. The org-llm-proxy and local credential-filter present this."
  sensitive   = true
}

resource "google_service_account" "credential_gate" {
  account_id   = "boan-org-cred-gate"
  display_name = "BoanClaw Org Credential Gate"
  project      = var.project_id
}

# credential-gate needs full Secret Manager admin on the project so it can
# create/list/read secrets scoped to org labels.
resource "google_project_iam_member" "credential_gate_sm" {
  project = var.project_id
  role    = "roles/secretmanager.admin"
  member  = "serviceAccount:${google_service_account.credential_gate.email}"
}

resource "google_cloud_run_v2_service" "credential_gate" {
  name     = "boan-org-credential-gate-${var.org_id}"
  location = var.region
  project  = var.project_id
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = google_service_account.credential_gate.email
    scaling {
      min_instance_count = 0
      max_instance_count = 3
    }
    containers {
      image = var.image
      ports {
        container_port = 8092
      }
      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
      }
      env {
        name  = "BOAN_LISTEN"
        value = ":8092"
      }
      env {
        name  = "BOAN_GCP_PROJECT_ID"
        value = var.project_id
      }
      env {
        name  = "BOAN_ORG_CREDENTIAL_GATE_AUTH_TOKEN"
        value = var.auth_token
      }
    }
  }
}

resource "google_cloud_run_service_iam_member" "public_invoker" {
  project  = var.project_id
  location = var.region
  service  = google_cloud_run_v2_service.credential_gate.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

output "credential_gate_url" { value = google_cloud_run_v2_service.credential_gate.uri }
output "service_account_email" { value = google_service_account.credential_gate.email }
