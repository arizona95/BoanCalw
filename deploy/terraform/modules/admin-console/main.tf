variable "project_id"        {}
variable "region"            { default = "asia-northeast3" }
variable "org_id"            {}
variable "policy_server_url" {}

resource "google_firebase_hosting_site" "admin" {
  provider = google-beta
  project  = var.project_id
  site_id  = "boanclaw-admin-${var.org_id}"
}

resource "google_firebase_hosting_channel" "production" {
  provider    = google-beta
  site_id     = google_firebase_hosting_site.admin.site_id
  channel_id  = "live"
}

# Cloud Run for SSO callback + API proxy
resource "google_cloud_run_v2_service" "admin_api" {
  name     = "boan-admin-api"
  location = var.region
  project  = var.project_id

  template {
    containers {
      image = "boanclaw/boan-admin-api:latest"
      env {
        name  = "POLICY_SERVER_URL"
        value = var.policy_server_url
      }
      env {
        name  = "BOAN_ORG_ID"
        value = var.org_id
      }
    }
  }
}

resource "google_cloud_run_service_iam_member" "public_admin_api" {
  project  = var.project_id
  location = var.region
  service  = google_cloud_run_v2_service.admin_api.name
  role     = "roles/run.invoker"
  member   = "allAuthenticatedUsers"
}

output "hosting_url"  { value = "https://${google_firebase_hosting_site.admin.site_id}.web.app" }
output "admin_api_url" { value = google_cloud_run_v2_service.admin_api.uri }
